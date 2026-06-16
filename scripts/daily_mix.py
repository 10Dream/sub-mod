import os
import sys
import time
import base64
import socket
import subprocess
import ipaddress
from datetime import datetime, timezone
import geoip2.database

# تنظیم مسیر جاری برای ایمپورت راحت ماژول‌های محلی
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

import clash_converter
import clash_template

def log_stage(step: int, total: int, message: str):
    """
    نمایش لاگ‌های پیشرفت فوق‌العاده شیک و رنگی به همراه Progress Bar در کنسول گیت‌هاب اکشنز [9].
    """
    percent = int((step / total) * 100)
    bar_length = 20
    filled = int(bar_length * step // total)
    bar = "█" * filled + "░" * (bar_length - filled)
    
    # کدهای رنگی ANSI استاندارد کنسول
    green = "\033[92m"
    cyan = "\033[96m"
    yellow = "\033[93m"
    reset = "\033[0m"
    bold = "\033[1m"
    
    if step == 1:
        print(f"\n{yellow}┌────────────────────────────────────────────────────────┐{reset}")
        print(f"{yellow}│     شروع فرآیند مگا-میکس، فیلترینگ و اسپلیت روزانه    │{reset}")
        print(f"{yellow}└────────────────────────────────────────────────────────┘{reset}\n")
        
    print(f"{green}{bold}[{step}/{total}]{reset} {cyan}{bar}{reset} {bold}{percent}%{reset} | {message}")
    
    if step == total:
        print(f"\n{green}┌────────────────────────────────────────────────────────┐{reset}")
        print(f"{green}│        فرآیند اسپلیت روزانه با موفقیت به پایان رسید!  │{reset}")
        print(f"{green}└────────────────────────────────────────────────────────┘{reset}\n")

# محدوده رنج آی‌پی دیتاسنترها و CDNهای برتر طبق مستندات درخواستی شما
CDN_RANGES = [
    ("Cloudflare", ["1.0.0.0/24","1.1.1.0/24","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","104.16.0.0/13","104.24.0.0/14","108.162.192.0/18","131.0.72.0/22","141.101.64.0/18","162.158.0.0/15","172.64.0.0/13","173.245.48.0/20","188.114.96.0/20","190.93.240.0/20","197.234.240.0/22","198.41.128.0/17"]),
    ("Google Cloud", ["8.8.4.0/24","8.8.8.0/24","64.233.160.0/19","66.102.0.0/20","66.249.64.0/19","74.125.0.0/16","104.132.0.0/14","108.177.0.0/17","142.250.0.0/15","172.217.0.0/16","172.253.0.0/16","173.194.0.0/16","209.85.128.0/17","216.58.192.0/19","216.239.32.0/19", "34.143.0.0/24", "34.160.0.0/24", "34.96.0.0/24", "35.186.0.0/24", "35.201.0.0/24", "34.117.0.0/24"]),
    ("Fastly", ["23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","104.156.80.0/20","146.75.0.0/16","151.101.0.0/16","157.52.64.0/18","167.82.0.0/17","199.27.72.0/21","199.232.0.0/16"]),
    ("Akamai", ["2.16.0.0/13","23.0.0.0/12","23.32.0.0/11","23.64.0.0/14","23.72.0.0/13","23.192.0.0/11","63.0.0.0/8","69.192.0.0/16","72.246.0.0/15","88.221.0.0/16","95.100.0.0/15","104.64.0.0/10","184.24.0.0/13","184.50.0.0/15","184.84.0.0/14", "2.17.0.0/24", "2.18.0.0/24", "2.19.0.0/24", "2.20.0.0/24", "2.21.0.0/24", "2.22.0.0/24", "23.48.0.0/24", "23.58.0.0/24", "23.193.0.0/24", "23.202.0.0/24", "23.43.0.0/24", "104.65.0.0/24", "104.103.0.0/24", "104.112.0.0/24", "184.86.0.0/24", "185.200.232.0/24", "92.16.0.0/24", "92.122.0.0/24"]),
    ("Netlify", ["3.33.128.0/17","13.32.0.0/15","13.35.0.0/16","18.64.0.0/14","44.226.105.0/24","50.7.4.0/24","50.7.85.0/24","50.7.87.0/24","44.235.184.0/24","52.84.0.0/15","35.157.26.0/24","63.176.8.0/24","54.182.0.0/16","99.83.128.0/17","162.159.128.0/20"]),
    ("Vercel", ["64.29.17.0/24","64.29.18.0/24","64.29.19.0/24","66.33.60.0/24","66.33.61.0/24","76.76.21.0/24","76.223.126.0/24"]),
    ("CloudFront", ["52.46.0.0/18","52.84.0.0/15","54.182.0.0/16","99.84.0.0/16","130.176.0.0/17", "13.32.0.0/24", "13.35.0.0/24", "54.230.0.0/24", "143.204.0.0/24", "205.251.192.0/24", "54.239.128.0/24"]),
    ("BunnyCDN", ["89.187.160.0/19","147.75.0.0/16"]),
    ("Gcore", ["92.223.0.0/16","95.85.0.0/16","185.158.0.0/16"]),
    ("ArvanCloud", ["2.144.3.128/28","37.32.16.0/27","37.32.17.0/27","37.32.17.0/27","37.32.18.0/27","37.32.19.0/27","94.101.182.0/27","178.131.120.48/28","185.143.232.0/22","185.215.232.0/22","188.229.116.16/30"]),
    ("DerakCloud", ["5.145.115.0/24","5.145.118.0/23","45.63.43.128/28","45.77.87.48/28","89.222.113.80/28","116.202.90.176/28","159.69.229.224/28","165.232.92.112/28","178.62.222.208/28","185.24.252.192/27","185.24.254.64/27","185.24.255.192/27","185.24.255.224/28","192.168.204.48/28","207.148.25.64/28","2a01:4f8:c0:2da6::/64","2a04:2f00:1:185f::/64","2a04:2f00:2:185f::/64","2a04:2f00:3:185f::/64","2a04:2f00:ff01::/64","2a04:2f00:ff02::/64","2a04:2f00:ff03::/64","2a04:2f00:ff06::/64","2a04:2f00:ff08::/64","2a04:2f00:ff09::/64"]),
    ("IranServer", ["5.182.45.23/32","5.182.45.37/32","45.159.114.11/32","87.98.249.55/32","93.127.182.21/32","93.127.182.24/32","94.143.229.14/32","94.182.97.44/31","94.182.97.46/32","168.119.4.117/32","185.116.162.15/32","185.116.162.19/32"]),
    ("ParsPack", ["2.144.23.191/32","5.135.72.112/28","5.160.143.64/28","31.214.248.208/28","45.32.131.160/28","45.32.154.64/28","45.76.132.16/28","45.77.211.208/28","45.77.211.240/28","45.77.223.80/28","45.139.11.240/28","46.20.41.224/28","64.176.15.176/28","64.176.64.80/28","65.20.72.128/28","65.20.113.240/28","77.237.66.128/28","79.175.148.128/28","84.17.42.224/28","87.236.161.96/28","89.36.162.32/28","89.187.169.48/28","91.228.186.48/28","94.182.153.64/28","95.179.140.112/28","95.179.164.96/28","95.179.220.128/28","95.179.254.176/28","95.211.188.240/28","95.211.219.96/28","95.211.240.112/28","95.211.250.112/28","130.185.74.48/28","130.185.79.128/28","139.84.177.16/28","139.84.236.0/28","144.202.58.96/28","144.202.78.96/28","144.202.114.128/28","155.138.162.96/28","158.51.122.240/28","158.247.223.48/28","167.179.93.112/28","171.22.26.240/28","178.22.120.192/28","185.8.173.0/28","185.8.174.144/28","185.8.175.208/28","185.110.191.240/28","185.204.197.0/28","185.208.175.144/28","194.5.188.32/28","195.88.208.176/28","195.181.174.64/28","195.248.241.160/28","195.248.242.192/28","199.247.3.16/28","207.148.69.96/28","208.85.22.32/28","213.183.48.16/28","216.238.117.0/28","217.197.97.48/28"])
]

PARSED_CDN_RANGES = []
for name, cidrs in CDN_RANGES:
    networks = []
    for cidr in cidrs:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except Exception:
            pass
    PARSED_CDN_RANGES.append((name, networks))

def find_datacenter(ip_str) -> str:
    if not ip_str:
        return "UNKNOWN"
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except Exception:
        return "UNKNOWN"
        
    for name, networks in PARSED_CDN_RANGES:
        for net in networks:
            if ip_obj in net:
                return name
    return "UNKNOWN"

def is_file_recent(filepath, days=7) -> bool:
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
    if not cc or cc == "UNKNOWN":
        return "🏳️"
    cc = cc.upper()
    return "".join(chr(127397 + ord(c)) for c in cc)

# لود کردن دیتابیس بومی کشورها
db_path = os.path.abspath(os.path.join(current_dir, "../utils/Country.mmdb"))
try:
    reader = geoip2.database.Reader(db_path)
except Exception:
    reader = None

def get_country_code(ip_address) -> str:
    if not reader or not ip_address:
        return "UNKNOWN"
    try:
        response = reader.country(ip_address)
        return (response.country.iso_code or "UNKNOWN").upper()
    except Exception:
        return "UNKNOWN"

def build_unlimited_clash_config(proxies_list, dest_yaml_path):
    if not proxies_list:
        return False
        
    processed_proxies = []
    seen_names = {}
    
    for p in proxies_list:
        p_copy = dict(p)
        ip, _ = resolve_ip(p_copy.get("server"))
        cc = get_country_code(ip)
        flag = get_country_flag_emoji(cc)
        
        orig_name = p_copy.get("name", "Proxy").strip()
        name_with_flag = f"{flag} {orig_name}"
        
        if name_with_flag in seen_names:
            seen_names[name_with_flag] += 1
            final_name = f"{name_with_flag}-{seen_names[name_with_flag]}"
        else:
            seen_names[name_with_flag] = 0
            final_name = name_with_flag
            
        p_copy["name"] = final_name
        processed_proxies.append(p_copy)
        
    proxy_names = [p["name"] for p in processed_proxies]
    
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

def map_to_standard_protocol_name(p_type: str) -> str:
    p_type = p_type.lower()
    if p_type in ["hysteria2", "hy2"]:
        return "hy2"
    if p_type in ["wireguard", "wg"]:
        return "wireguard"
    if p_type in ["socks5", "socks"]:
        return "socks5"
    return p_type

def main():
    total_stages = 8
    
    log_stage(1, total_stages, "لود دیتابیس بومی ژئوای‌پی و تخصیص پوشه‌های اسپلیتر...")
    normal_dir = os.path.abspath(os.path.join(current_dir, "../sub/normal"))
    
    split_normal_dir = os.path.abspath(os.path.join(current_dir, "../sub/split"))
    split_base64_dir = os.path.abspath(os.path.join(current_dir, "../sub/base64/split"))
    split_clash_dir = os.path.abspath(os.path.join(current_dir, "../sub/clash/split"))
    
    countries_normal_dir = os.path.join(split_normal_dir, "countries")
    countries_base64_dir = os.path.join(split_base64_dir, "countries")
    countries_clash_dir = os.path.join(split_clash_dir, "countries")
    
    datacenters_normal_dir = os.path.join(split_normal_dir, "datacenters")
    datacenters_base64_dir = os.path.join(split_base64_dir, "datacenters")
    datacenters_clash_dir = os.path.join(split_clash_dir, "datacenters")
    
    protocols_normal_dir = os.path.join(split_normal_dir, "protocols")
    protocols_base64_dir = os.path.join(split_base64_dir, "protocols")
    protocols_clash_dir = os.path.join(split_clash_dir, "protocols")
    
    log_stage(2, total_stages, "اسکن فایل‌های سابسکریپشن معمولی با سن زیر ۷ روز در گیت...")
    recent_sources = []
    if os.path.exists(normal_dir):
        for f in os.listdir(normal_dir):
            filepath = os.path.join(normal_dir, f)
            if os.path.isfile(filepath) and not f.startswith('.') and f != "mix.txt" and not f.endswith('.txt'):
                if is_file_recent(filepath, days=7):
                    recent_sources.append(f)
                    
    if not recent_sources:
        print("[اسکیپ] هیچ منبع فعالی در ۱ هفته گذشته یافت نشد.")
        sys.exit(0)
        
    log_stage(3, total_stages, "پارس، معتبرسازی و فیلترینگ دیتای تکراری با اثر انگشت اتصالی...")
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
                            
    log_stage(4, total_stages, "دسته‌بندی پروکسی‌های یکتا بر اساس امنیت و متدهای ترنسپورت شبکه...")
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
    
    protocols_order = [
        "hy2", "vless", "ss", "vmess", "trojan", "anytls", "ssh", "ssr",
        "snell", "tailscale", "openvpn", "trusttunnel", "masque", "sudoku",
        "wireguard", "tuic", "hysteria", "http"
    ]
    
    protocols_data = {proto: {"links": [], "dicts": []} for proto in protocols_order}
    countries_data = {}
    datacenters_data = {}
    
    # تفکیک عمیق
    for item in unique_proxies_list:
        p = item["dict"]
        raw = item["raw_link"]
        p_type = p["type"]
        
        # ۱. دسته‌بندی پروتکل
        std_proto = map_to_standard_protocol_name(p_type)
        if std_proto in protocols_data:
            protocols_data[std_proto]["links"].append(raw)
            protocols_data[std_proto]["dicts"].append(p)
        
        # ۲. امنیت
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
            
        # ۳. ترنسپورت
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
            
        # ۴. نسخه آی‌پی
        ip, ip_ver = resolve_ip(p.get("server"))
        if ip_ver == "ipv4":
            categories["ipv4"]["links"].append(raw)
            categories["ipv4"]["dicts"].append(p)
        elif ip_ver == "ipv6":
            categories["ipv6"]["links"].append(raw)
            categories["ipv6"]["dicts"].append(p)
            
        if ip:
            # ۵. کشور
            cc = get_country_code(ip)
            if cc != "UNKNOWN":
                if cc not in countries_data:
                    countries_data[cc] = {"links": [], "dicts": []}
                countries_data[cc]["links"].append(raw)
                countries_data[cc]["dicts"].append(p)
                
            # ۶. دیتاسنتر
            dc_name = find_datacenter(ip)
            if dc_name != "UNKNOWN":
                if dc_name not in datacenters_data:
                    datacenters_data[dc_name] = {"links": [], "dicts": []}
                datacenters_data[dc_name]["links"].append(raw)
                datacenters_data[dc_name]["dicts"].append(p)
                
    log_stage(5, total_stages, "تفکیک اختصاصی ۱۸ پروتکل با رعایت کامل اولویت‌ها...")
    log_stage(6, total_stages, "تطبیق رنج‌های آی‌پی و تفکیک بر پایه دیتاسنترها و CDNها...")
    log_stage(7, total_stages, "تطبیق مکانی و تفکیک جغرافیایی بر پایه کشورهای هدف...")
    log_stage(8, total_stages, "رندر و ذخیره همزمان فایل‌های معمولی، کدهای بیس۶۴ و کانفیگ‌های بدون مرز کلش...")
    
    # نوشتن دسته‌های عمومی
    os.makedirs(split_normal_dir, exist_ok=True)
    os.makedirs(split_base64_dir, exist_ok=True)
    os.makedirs(split_clash_dir, exist_ok=True)
    
    for cat_name, data in categories.items():
        links = data["links"]
        dicts = data["dicts"]
        if not links:
            continue
        content_str = "\n".join(links)
        
        with open(os.path.join(split_normal_dir, f"{cat_name}.txt"), 'w', encoding='utf-8') as f:
            f.write(content_str)
        with open(os.path.join(split_base64_dir, f"{cat_name}.txt"), 'w', encoding='utf-8') as f:
            f.write(encode_to_base64(content_str))
        build_unlimited_clash_config(dicts, os.path.join(split_clash_dir, f"{cat_name}.yaml"))
        
    # نوشتن دسته‌های کشوری
    os.makedirs(countries_normal_dir, exist_ok=True)
    os.makedirs(countries_base64_dir, exist_ok=True)
    os.makedirs(countries_clash_dir, exist_ok=True)
    
    for cc, data in countries_data.items():
        links = data["links"]
        dicts = data["dicts"]
        if not links:
            continue
        content_str = "\n".join(links)
        
        with open(os.path.join(countries_normal_dir, f"{cc}.txt"), 'w', encoding='utf-8') as f:
            f.write(content_str)
        with open(os.path.join(countries_base64_dir, f"{cc}.txt"), 'w', encoding='utf-8') as f:
            f.write(encode_to_base64(content_str))
        build_unlimited_clash_config(dicts, os.path.join(countries_clash_dir, f"{cc}.yaml"))
        
    # نوشتن دسته‌های دیتاسنتری
    os.makedirs(datacenters_normal_dir, exist_ok=True)
    os.makedirs(datacenters_base64_dir, exist_ok=True)
    os.makedirs(datacenters_clash_dir, exist_ok=True)
    
    for dc_raw_name, data in datacenters_data.items():
        links = data["links"]
        dicts = data["dicts"]
        if not links:
            continue
        content_str = "\n".join(links)
        
        dc_filename = dc_raw_name.lower().replace(" ", "_")
        
        with open(os.path.join(datacenters_normal_dir, f"{dc_filename}.txt"), 'w', encoding='utf-8') as f:
            f.write(content_str)
        with open(os.path.join(datacenters_base64_dir, f"{dc_filename}.txt"), 'w', encoding='utf-8') as f:
            f.write(encode_to_base64(content_str))
        build_unlimited_clash_config(dicts, os.path.join(datacenters_clash_dir, f"{dc_filename}.yaml"))
        
    # نوشتن دسته‌های پروتکلی
    os.makedirs(protocols_normal_dir, exist_ok=True)
    os.makedirs(protocols_base64_dir, exist_ok=True)
    os.makedirs(protocols_clash_dir, exist_ok=True)
    
    for proto, data in protocols_data.items():
        links = data["links"]
        dicts = data["dicts"]
        if not links:
            continue
        content_str = "\n".join(links)
        
        with open(os.path.join(protocols_normal_dir, f"{proto}.txt"), 'w', encoding='utf-8') as f:
            f.write(content_str)
        with open(os.path.join(protocols_base64_dir, f"{proto}.txt"), 'w', encoding='utf-8') as f:
            f.write(encode_to_base64(content_str))
        build_unlimited_clash_config(dicts, os.path.join(protocols_clash_dir, f"{proto}.yaml"))

if __name__ == "__main__":
    main()
