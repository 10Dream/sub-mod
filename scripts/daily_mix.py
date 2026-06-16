import os
import sys
import time
import base64
import socket
import subprocess
from datetime import datetime, timezone
import geoip2.database

# تنظیم مسیر جاری برای ایمپورت راحت ماژول‌های محلی
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

import clash_converter
import clash_template

def is_file_recent(filepath, days=7) -> bool:
    """سنجش هوشمند اخیر بودن فایل با استفاده از سابقه گیت لاگ."""
    try:
        commit_time_bytes = subprocess.check_output(
            ["git", "log", "-1", "--format=%ct", filepath],
            stderr=subprocess.DEVNULL
        )
        commit_time_str = commit_time_bytes.decode().strip()
        if commit_time_str.isdigit():
            mtime = int(commit_time_str)
            now = int(time.time())
            return (now - mtime) < (days * 24 * 3600)
    except Exception:
        pass
    
    try:
        mtime = os.path.getmtime(filepath)
        now = time.time()
        return (now - mtime) < (days * 24 * 3600)
    except Exception:
        return False

def resolve_ip(server: str):
    """حل آدرس DNS برای استخراج IP و تعیین نسخه IPv4 یا IPv6."""
    if not server or not isinstance(server, str):
        return None, "unknown"
        
    server_clean = server.replace("[", "").replace("]", "").strip()
    
    if ":" in server_clean:
        try:
            socket.inet_pton(socket.AF_INET6, server_clean)
            return server_clean, "ipv6"
        except socket.error:
            pass
            
    try:
        socket.inet_pton(socket.AF_INET, server_clean)
        return server_clean, "ipv4"
    except socket.error:
        pass
        
    try:
        addr_info = socket.getaddrinfo(server_clean, None)
        for family, _, _, _, sockaddr in addr_info:
            ip = sockaddr[0]
            if family == socket.AF_INET:
                return ip, "ipv4"
            elif family == socket.AF_INET6:
                return ip, "ipv6"
    except Exception:
        pass
        
    return None, "unknown"

def encode_to_base64(text: str) -> str:
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def get_country_flag_emoji(cc: str) -> str:
    """تبدیل کد دو حرفی کشور به ایموجی پرچم مربوطه"""
    if not cc or cc == "UNKNOWN":
        return "🏳️"
    cc = cc.upper()
    return "".join(chr(127397 + ord(c)) for c in cc)

# لود کردن دیتابیس بومی کشورها
db_path = os.path.abspath(os.path.join(current_dir, "../utils/Country.mmdb"))
try:
    reader = geoip2.database.Reader(db_path)
    print("[دیتابیس] ژئوای‌پی با موفقیت بارگذاری شد.")
except Exception as e:
    reader = None
    print(f"[هشدار] دیتابیس کشورها در مسیر '{db_path}' لود نشد: {e}")

def get_country_code(ip_address) -> str:
    if not reader or not ip_address:
        return "UNKNOWN"
    try:
        response = reader.country(ip_address)
        return (response.country.iso_code or "UNKNOWN").upper()
    except Exception:
        return "UNKNOWN"

def build_unlimited_clash_config(proxies_list, dest_yaml_path):
    """
    تولید فایل تنظیمات کامل کلش میهومو برای هر اسپلیت با پروکسی‌های نامحدود (بدون سقف) [9].
    نام پروکسی‌ها همراه با اموجی پرچم کشور به اول آن‌ها و اعمال روتین رفع تکراری خواهد بود.
    """
    if not proxies_list:
        return False
        
    processed_proxies = []
    seen_names = {}
    
    # پردازش، افزودن پرچم کشور به ابتدای نام و حل مشکل نام‌های تکراری
    for p in proxies_list:
        p_copy = dict(p)
        
        # استخراج پرچم بر اساس IP سرور
        ip, _ = resolve_ip(p_copy.get("server"))
        cc = get_country_code(ip)
        flag = get_country_flag_emoji(cc)
        
        # چسباندن پرچم به ابتدای نام بومی پروکسی
        orig_name = p_copy.get("name", "Proxy").strip()
        name_with_flag = f"{flag} {orig_name}"
        
        # تضمین یکتا بودن نام پروکسی در این فایل کلش
        if name_with_flag in seen_names:
            seen_names[name_with_flag] += 1
            final_name = f"{name_with_flag}-{seen_names[name_with_flag]}"
        else:
            seen_names[name_with_flag] = 0
            final_name = name_with_flag
            
        p_copy["name"] = final_name
        processed_proxies.append(p_copy)
        
    proxy_names = [p["name"] for p in processed_proxies]
    
    # مونتاژ سند کلش با استفاده از تمپلت ماژولار
    final_dict = {}
    final_dict.update(clash_template.GENERAL_SETTINGS)
    final_dict["dns"] = clash_template.DNS_SETTINGS
    final_dict["sniffer"] = clash_template.SNIFFER_SETTINGS
    final_dict["tun"] = clash_template.TUN_SETTINGS
    final_dict["rule-providers"] = clash_template.RULE_PROVIDERS
    final_dict["proxies"] = processed_proxies
    final_dict["proxy-groups"] = clash_template.get_proxy_groups(proxy_names)
    final_dict["rules"] = clash_template.RULES
    
    final_yaml_content = clash_converter.dump_yaml(final_dict)
    
    os.makedirs(os.path.dirname(dest_yaml_path), exist_ok=True)
    with open(dest_yaml_path, 'w', encoding='utf-8') as f:
        f.write(final_yaml_content)
    return True

def main():
    normal_dir = os.path.abspath(os.path.join(current_dir, "../sub/normal"))
    
    # ایجاد ساختار مسیرهای جدید Split به موازات پروژه‌های ماژولار
    split_normal_dir = os.path.abspath(os.path.join(current_dir, "../sub/split"))
    split_base64_dir = os.path.abspath(os.path.join(current_dir, "../sub/base64/split"))
    split_clash_dir = os.path.abspath(os.path.join(current_dir, "../sub/clash/split"))
    
    countries_normal_dir = os.path.join(split_normal_dir, "countries")
    countries_base64_dir = os.path.join(split_base64_dir, "countries")
    countries_clash_dir = os.path.join(split_clash_dir, "countries")
    
    print("=== شروع فاز تولید میکس، فیلترینگ و تبدیل اسپلیت‌های بدون محدودیت ===")
    
    # ۱. اسکن و جداسازی سورس‌های فعال با قدمت کمتر از ۷ روز
    recent_sources = []
    if os.path.exists(normal_dir):
        for f in os.listdir(normal_dir):
            filepath = os.path.join(normal_dir, f)
            if os.path.isfile(filepath) and not f.startswith('.') and f != "mix.txt" and not f.endswith('.txt'):
                if is_file_recent(filepath, days=7):
                    recent_sources.append(f)
                    
    print(f"تعداد منابع واکشی شده در هفته اخیر: {len(recent_sources)}")
    if not recent_sources:
        print("[پایان] هیچ سورس فعالی یافت نشد.")
        sys.exit(0)
        
    # ۲. دکود، پارس و اعمال دی‌داپلیکیتور سراسری
    unique_proxies_list = []
    seen_fingerprints = set()
    
    for filename in recent_sources:
        filepath = os.path.join(normal_dir, filename)
        with open(filepath, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                split_links = clash_converter.split_concatenated_links(line)
                for single_link in split_links:
                    p = clash_converter.parse_proxy(single_link)
                    if p and clash_converter.validate_proxy(p):
                        fingerprint = clash_converter.get_connection_fingerprint(p)
                        if fingerprint not in seen_fingerprints:
                            seen_fingerprints.add(fingerprint)
                            unique_proxies_list.append({"dict": p, "raw_link": single_link})
                            
    print(f"در مجموع {len(unique_proxies_list)} کانفیگ یکتای فنی آماده تقسیم‌بندی است.")
    
    # ۳. تدارک دسته‌ها
    categories = {
        "grpc": {"links": [], "dicts": []},
        "http": {"links": [], "dicts": []},
        "ws": {"links": [], "dicts": []},
        "tcp": {"links": [], "dicts": []},
        "xhttp": {"links": [], "dicts": []},
        "tls": {"links": [], "dicts": []},
        "reality": {"links": [], "dicts": []},
        "non-tls": {"links": [], "dicts": []},
        "ipv4": {"links": [], "dicts": []},
        "ipv6": {"links": [], "dicts": []}
    }
    countries_data = {}
    
    # ۴. حلقه‌ی دسته‌بندی
    for item in unique_proxies_list:
        p = item["dict"]
        raw = item["raw_link"]
        p_type = p["type"]
        
        # الف. امنیت
        is_tls = p.get("tls", False) or p_type in ["hysteria", "hysteria2", "tuic", "trojan", "anytls", "trusttunnel"]
        is_reality = p.get("reality-opts") is not None
        
        if is_reality:
            categories["reality"]["links"].append(raw)
            categories["reality"]["dicts"].append(p)
            categories["tls"]["links"].append(raw)
            categories["tls"]["dicts"].append(p)
        elif is_tls:
            categories["tls"]["links"].append(raw)
            categories["tls"]["dicts"].append(p)
        else:
            categories["non-tls"]["links"].append(raw)
            categories["non-tls"]["dicts"].append(p)
            
        # ب. ترنسپورت
        net = p.get("network", "tcp").lower()
        if net == "grpc":
            categories["grpc"]["links"].append(raw)
            categories["grpc"]["dicts"].append(p)
        elif net == "ws":
            categories["ws"]["links"].append(raw)
            categories["ws"]["dicts"].append(p)
        elif net == "http":
            categories["http"]["links"].append(raw)
            categories["http"]["dicts"].append(p)
        elif net == "xhttp":
            categories["xhttp"]["links"].append(raw)
            categories["xhttp"]["dicts"].append(p)
        elif net == "tcp" or p_type in ["ss", "ssr", "socks5", "ssh", "snell"]:
            categories["tcp"]["links"].append(raw)
            categories["tcp"]["dicts"].append(p)
            
        # ج. IP و کشور
        ip, ip_ver = resolve_ip(p.get("server"))
        if ip_ver == "ipv4":
            categories["ipv4"]["links"].append(raw)
            categories["ipv4"]["dicts"].append(p)
        elif ip_ver == "ipv6":
            categories["ipv6"]["links"].append(raw)
            categories["ipv6"]["dicts"].append(p)
            
        if ip:
            cc = get_country_code(ip)
            if cc != "UNKNOWN":
                if cc not in countries_data:
                    countries_data[cc] = {"links": [], "dicts": []}
                countries_data[cc]["links"].append(raw)
                countries_data[cc]["dicts"].append(p)
                
    # ۵. تولید فایل‌های اشتراک و تبدیل نامحدود کلش
    # ذخیره و تبدیل دسته‌های عمومی
    os.makedirs(split_normal_dir, exist_ok=True)
    os.makedirs(split_base64_dir, exist_ok=True)
    os.makedirs(split_clash_dir, exist_ok=True)
    
    for cat_name, data in categories.items():
        links = data["links"]
        dicts = data["dicts"]
        if not links:
            continue
        content_str = "\n".join(links)
        
        # ساب متنی معمولی
        with open(os.path.join(split_normal_dir, f"{cat_name}.txt"), 'w', encoding='utf-8') as f:
            f.write(content_str)
        # ساب بیس۶۴
        with open(os.path.join(split_base64_dir, f"{cat_name}.txt"), 'w', encoding='utf-8') as f:
            f.write(encode_to_base64(content_str))
        # کانفیگ نامحدود کلش با پرچم‌های کشورها
        build_unlimited_clash_config(dicts, os.path.join(split_clash_dir, f"{cat_name}.yaml"))
        
    # ذخیره و تبدیل دسته‌های کشوری
    os.makedirs(countries_normal_dir, exist_ok=True)
    os.makedirs(countries_base64_dir, exist_ok=True)
    os.makedirs(countries_clash_dir, exist_ok=True)
    
    for cc, data in countries_data.items():
        links = data["links"]
        dicts = data["dicts"]
        if not links:
            continue
        content_str = "\n".join(links)
        
        # ساب کشوری متنی معمولی
        with open(os.path.join(countries_normal_dir, f"{cc}.txt"), 'w', encoding='utf-8') as f:
            f.write(content_str)
        # ساب کشوری بیس۶۴
        with open(os.path.join(countries_base64_dir, f"{cc}.txt"), 'w', encoding='utf-8') as f:
            f.write(encode_to_base64(content_str))
        # کانفیگ کشوری نامحدود کلش با پرچم‌ها
        build_unlimited_clash_config(dicts, os.path.join(countries_clash_dir, f"{cc}.yaml"))
        
    print("=== فرآیند تجمیع، فیلتر و میکس اسپلیترها با موفقیت به اتمام رسید ===")

if __name__ == "__main__":
    main()
