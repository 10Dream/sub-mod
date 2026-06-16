import os
import re
import subprocess
from datetime import datetime, timezone

def log_stage(step: int, total: int, message: str):
    """
    نمایش لاگ‌های فوق‌العاده زیبا، رنگی و حرفه‌ای به همراه نوار پیشرفت (Progress Bar)
    جهت مانیتورینگ دقیق مراحل در خروجی کنسول گیت‌هاب اکشنز [9].
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
        print(f"{yellow}│       شروع فرآیند بازسازی و رندر مستندات ریدمی       │{reset}")
        print(f"{yellow}└────────────────────────────────────────────────────────┘{reset}\n")
        
    print(f"{green}{bold}[{step}/{total}]{reset} {cyan}{bar}{reset} {bold}{percent}%{reset} | {message}")
    
    if step == total:
        print(f"\n{green}┌────────────────────────────────────────────────────────┐{reset}")
        print(f"{green}│        تمامی جداول رندر شده و فایل نهایی ذخیره شد!      │{reset}")
        print(f"{green}└────────────────────────────────────────────────────────┘{reset}\n")

def get_repo_info():
    """
    استخراج نام نویسنده و مخزن جهت ساخت خودکار لینک‌های دانلود خام مستقیم.
    """
    repo_env = os.environ.get("GITHUB_REPOSITORY")
    if repo_env and "/" in repo_env:
        owner, repo = repo_env.split("/", 1)
        return owner, repo
    
    try:
        git_url = subprocess.check_output(["git", "config", "--get", "remote.origin.url"]).decode().strip()
        match = re.search(r'github\.com[:/]([^/]+)/([^/.]+)(?:\.git)?', git_url)
        if match:
            return match.group(1), match.group(2)
    except Exception:
        pass
        
    return "[USERNAME]", "[REPO]"

def get_file_list(directory):
    """
    واکشی لیست فایل‌های تولید شده در دایرکتوری مشخص‌شده به ترتیب حروف الفبا.
    """
    if not os.path.exists(directory):
        return []
    files = []
    for f in os.listdir(directory):
        if os.path.isfile(os.path.join(directory, f)) and not f.startswith('.'):
            files.append(f)
    return sorted(files)

def get_country_flag_html(cc: str) -> str:
    """
    ساخت هوشمند تگ تصویر SVG پرچم کشورها جهت دور زدن باگ عدم نمایش اموجی‌ها در ویندوز/کروم.
    تصاویر لود شده کاملاً برداری، مدرن و باکیفیت خواهند بود [9].
    """
    if not cc or cc == "UNKNOWN":
        return "🏳️"
    cc_lower = cc.lower()
    return f'<img src="https://raw.githubusercontent.com/lipis/flag-icons/main/flags/4x3/{cc_lower}.svg" width="22" alt="{cc}"/>'

def get_relative_time(filepath):
    """
    محاسبه و تبدیل زمان آخرین تغییر واقعی فایل در تاریخچه گیت (Commit History) به صورت فارسی [2].
    """
    if not os.path.exists(filepath):
        return "نامشخص"
        
    try:
        subprocess.check_call(
            ["git", "diff", "--quiet", "HEAD", "--", filepath],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        has_changed = False
    except subprocess.CalledProcessError:
        has_changed = True
    except Exception:
        has_changed = True

    if has_changed:
        return "همین الان"

    try:
        commit_time_bytes = subprocess.check_output(
            ["git", "log", "-1", "--format=%ct", filepath],
            stderr=subprocess.DEVNULL
        )
        commit_time_str = commit_time_bytes.decode().strip()
        if commit_time_str.isdigit():
            mtime = int(commit_time_str)
        else:
            mtime = os.path.getmtime(filepath)
    except Exception:
        mtime = os.path.getmtime(filepath)
        
    try:
        dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
        now = datetime.now(timezone.utc)
        diff = now - dt
        
        diff_secs = diff.total_seconds()
        if diff_secs < 60:
            return "چند لحظه پیش"
        diff_mins = int(diff_secs / 60)
        if diff_mins < 60:
            return f"{diff_mins} دقیقه پیش"
        diff_hours = int(diff_mins / 60)
        if diff_hours < 24:
            return f"{diff_hours} ساعت پیش"
        diff_days = int(diff_hours / 24)
        return f"{diff_days} روز پیش"
    except Exception:
        return "بروزرسانی شده"

def generate_markdown():
    total_steps = 7
    
    log_stage(1, total_steps, "واکشی اطلاعات و مشخصات متادیتای مخزن گیت‌هاب...")
    owner, repo = get_repo_info()
    base_raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/sub"
    now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    
    log_stage(2, total_steps, "پایش دایرکتوری سورس‌های خام متنی معمولی...")
    normal_files = get_file_list("sub/normal")
    
    log_stage(3, total_steps, "پایش پوشه‌های اسپلیترهای روزانه شبکه و ترنسپورت...")
    split_files = get_file_list("sub/split")
    
    log_stage(4, total_steps, "واکشی پویای لیست ۱۸ پروتکل اسپلیت‌شده روزانه...")
    # ترتیب کاملاً منطبق بر خواسته شما جهت رندر در ریدمی [9]
    protocols_order = [
        "hy2", "vless", "ss", "vmess", "trojan", "anytls", "ssh", "ssr",
        "snell", "tailscale", "openvpn", "trusttunnel", "masque", "sudoku",
        "wireguard", "tuic", "hysteria", "http"
    ]
    
    log_stage(5, total_steps, "واکشی لیست دیتاسنترها و CDNهای تفکیک‌شده روزانه...")
    datacenter_files = get_file_list("sub/split/datacenters")
    
    log_stage(6, total_steps, "ردیابی موقعیت‌های مکانی و کشورهای استخراج‌شده...")
    country_files = get_file_list("sub/split/countries")
    
    log_stage(7, total_steps, "رندر نهایی تمپلت‌ها و بازنویسی جامع فایل README.md مخزن...")
    
    markdown = f"""# ⚡️ سیستم تجمیع هوشمند و خودکار کانفیگ (V2ray & Clash)

یک پروژه کاملاً پویا و ماژولار مبتنی بر گیت‌هاب اکشنز جهت دانلود، پارس، فیلترینگ دیتای تکراری (بر اساس الگوریتم اثر انگشت اتصالی فنی) و جداسازی هوشمند کانفیگ‌های متوالی به‌هم‌چسبیده. 

> 🔄 **بروزرسانی خودکار:** هر ۱ ساعت یک‌بار دیتای تمام منابع واکشی شده و کانفیگ‌های معیوب فیلتر می‌شوند.

---

### 🕒 آخرین زمان اجرای کلی پایپلاین
`{now_utc}`

[![GitHub license](https://img.shields.io/github/license/{owner}/{repo}?style=flat-square)](https://github.com/{owner}/{repo}/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/{owner}/{repo}?style=flat-square)](https://github.com/{owner}/{repo}/stargazers)

---

## 🔗 لینک‌های اشتراک مستقیم یکپارچه (Unified Raw Subscriptions)

*برای استفاده، روی لینک فرمت مورد نظر خود راست‌کلیک کرده و گزینه Copy Link را انتخاب کنید.*

| نام منبع | 📝 اشتراک متنی خام (Normal) | 🔒 رمزگذاری‌شده (Base64) | 🧊 کلش میهومو (Clash YAML) | آخرین بروزرسانی |
| :--- | :---: | :---: | :---: | :---: |
| 🌀 **ترکیب تمام منابع (میکس)** | [📝 دریافت لینک]({base_raw_url}/normal/mix.txt) | [🔒 دریافت لینک]({base_raw_url}/base64/mix.txt) | [🧊 دریافت لینک]({base_raw_url}/clash/mix.yaml) | **{get_relative_time('sub/normal/mix.txt')}** |
"""
    
    # جدول ۱: اضافه کردن تک‌فایل‌ها
    for f in normal_files:
        if f == "mix.txt":
            continue
            
        filepath_normal = f"sub/normal/{f}"
        clash_filename = os.path.splitext(f)[0] + ".yaml"
        
        has_b64 = os.path.exists(f"sub/base64/{f}")
        has_clash = os.path.exists(f"sub/clash/{clash_filename}")
        
        normal_link = f"[📝 دریافت لینک]({base_raw_url}/normal/{f})"
        b64_link = f"[🔒 دریافت لینک]({base_raw_url}/base64/{f})" if has_b64 else "❌ ندارد"
        clash_link = f"[🧊 دریافت لینک]({base_raw_url}/clash/{clash_filename})" if has_clash else "❌ ندارد"
        
        markdown += f"| 📄 **{f}** | {normal_link} | {b64_link} | {clash_link} | {get_relative_time(filepath_normal)} |\n"
        
    markdown += f"""
---

## 🥞 اشتراک‌های تفکیک‌شده بر اساس پروتکل (Daily Protocol Subscriptions)

*میکس روزانه و بدون محدودیت تعداد کانفیگ (Unlimited) پروکسی‌ها به تفکیک ۱۸ پروتکل ارتباطی با رعایت کامل اولویت‌ها [9].*

| پروتکل ارتباطی | 📝 متنی خام (Normal) | 🔒 رمزگذاری‌شده (Base64) | 🧊 کلش میهومو (Clash YAML) | آخرین بروزرسانی |
| :--- | :---: | :---: | :---: | :---: |
"""

    # جدول ۲: اسپلیترهای ۱۸ پروتکل اختصاصی
    for proto in protocols_order:
        f = f"{proto}.txt"
        filepath_proto = f"sub/split/protocols/{f}"
        clash_filename = f"{proto}.yaml"
        
        has_normal = os.path.exists(filepath_proto)
        has_b64 = os.path.exists(f"sub/base64/split/protocols/{f}")
        has_clash = os.path.exists(f"sub/clash/split/protocols/{clash_filename}")
        
        if not has_normal:
            continue
            
        normal_link = f"[📝 دریافت لینک]({base_raw_url}/split/protocols/{f})"
        b64_link = f"[🔒 دریافت لینک]({base_raw_url}/base64/split/protocols/{f})" if has_b64 else "❌ ندارد"
        clash_link = f"[🧊 دریافت لینک]({base_raw_url}/clash/split/protocols/{clash_filename})" if has_clash else "❌ ندارد"
        
        markdown += f"| 🔌 **{proto.upper()}** | {normal_link} | {b64_link} | {clash_link} | {get_relative_time(filepath_proto)} |\n"

    markdown += f"""
---

## ⚙️ اشتراک‌های تفکیک‌شده بر اساس شبکه و ترنسپورت (Daily Network Subscriptions)

*تفکیک بر بستر متدهای انتقال شبکه و ساختارهای رمزگذاری بدون محدودیت تعداد کانفیگ (Unlimited) [9].*

| نوع دسته‌بندی | 📝 متنی خام (Normal) | 🔒 رمزگذاری‌شده (Base64) | 🧊 کلش میهومو (Clash YAML) | آخرین بروزرسانی |
| :--- | :---: | :---: | :---: | :---: |
"""

    # جدول ۳: اسپلیترهای عمومی شبکه
    for f in split_files:
        filepath_split = f"sub/split/{f}"
        clash_filename = os.path.splitext(f)[0] + ".yaml"
        
        has_b64 = os.path.exists(f"sub/base64/split/{f}")
        has_clash = os.path.exists(f"sub/clash/split/{clash_filename}")
        
        normal_link = f"[📝 دریافت لینک]({base_raw_url}/split/{f})"
        b64_link = f"[🔒 دریافت لینک]({base_raw_url}/base64/split/{f})" if has_b64 else "❌ ندارد"
        clash_link = f"[🧊 دریافت لینک]({base_raw_url}/clash/split/{clash_filename})" if has_clash else "❌ ندارد"
        
        markdown += f"| ⚙️ **{os.path.splitext(f)[0].upper()}** | {normal_link} | {b64_link} | {clash_link} | {get_relative_time(filepath_split)} |\n"

    markdown += f"""
---

## 🏢 اشتراک‌های تفکیک‌شده بر اساس دیتاسنتر / CDN (Daily Datacenter Subscriptions)

*میکس روزانه و بدون محدودیت تعداد کانفیگ (Unlimited) پروکسی‌ها بر پایه شناسایی فنی دامنه و رنج IP سرورهای میزبان [9].*

| نام دیتاسنتر / CDN | 📝 متنی خام (Normal) | 🔒 رمزگذاری‌شده (Base64) | 🧊 کلش میهومو (Clash YAML) | آخرین بروزرسانی |
| :--- | :---: | :---: | :---: | :---: |
"""

    # جدول ۴: اسپلیترهای دیتاسنترها
    for f in datacenter_files:
        filepath_dc = f"sub/split/datacenters/{f}"
        raw_name = os.path.splitext(f)[0]
        clash_filename = f"{raw_name}.yaml"
        
        has_b64 = os.path.exists(f"sub/base64/split/datacenters/{f}")
        has_clash = os.path.exists(f"sub/clash/split/datacenters/{clash_filename}")
        
        display_name = raw_name.replace("_", " ").upper()
        
        normal_link = f"[📝 دریافت لینک]({base_raw_url}/split/datacenters/{f})"
        b64_link = f"[🔒 دریافت لینک]({base_raw_url}/base64/split/datacenters/{f})" if has_b64 else "❌ ندارد"
        clash_link = f"[🧊 دریافت لینک]({base_raw_url}/clash/split/datacenters/{clash_filename})" if has_clash else "❌ ندارد"
        
        markdown += f"| 🏢 **{display_name}** | {normal_link} | {b64_link} | {clash_link} | {get_relative_time(filepath_dc)} |\n"

    markdown += f"""
---

## 🗺️ اشتراک‌های تفکیک‌شده بر اساس کشور (Daily Country-Based Subscriptions)

*میکس بومی و بدون محدودیت تعداد کانفیگ (Unlimited) پروکسی‌ها به تفکیک موقعیت جغرافیایی سرورها به همراه پرچم برداری و SVG کشورها [9].*

| کشور هدف | 📝 متنی خام (Normal) | 🔒 رمزگذاری‌شده (Base64) | 🧊 کلش میهومو (Clash YAML) | آخرین بروزرسانی |
| :--- | :---: | :---: | :---: | :---: |
"""

    # جدول ۵: اسپلیترهای کشوری با پرچم‌های SVG
    for f in country_files:
        filepath_country = f"sub/split/countries/{f}"
        cc = os.path.splitext(f)[0].upper()
        clash_filename = f"{cc}.yaml"
        
        has_b64 = os.path.exists(f"sub/base64/split/countries/{f}")
        has_clash = os.path.exists(f"sub/clash/split/countries/{clash_filename}")
        
        flag_img = get_country_flag_html(cc)
        
        normal_link = f"[📝 دریافت لینک]({base_raw_url}/split/countries/{f})"
        b64_link = f"[🔒 دریافت لینک]({base_raw_url}/base64/split/countries/{f})" if has_b64 else "❌ ندارد"
        clash_link = f"[🧊 دریافت لینک]({base_raw_url}/clash/split/countries/{clash_filename})" if has_clash else "❌ ندارد"
        
        markdown += f"| {flag_img} **{cc}** | {normal_link} | {b64_link} | {clash_link} | {get_relative_time(filepath_country)} |\n"

    markdown += """
---

## 📱 کلاینت‌های پیشنهادی و مورد تأیید
شما می‌توانید از برنامه‌های معتبر، بومی و هایپرلینک شده زیر جهت اتصال استفاده کنید:

### 💻 مولتی‌پلتفرم (ویندوز، اندروید، مک، لینوکس)
* **Hiddify:** [دریافت نسخه گیت‌هاب](https://github.com/hiddify/hiddify-app) / [دریافت نسخه اپ‌استور آیفون](https://apps.apple.com/us/app/hiddify-proxy-vpn/id6596777532)
* **Karing:** [دریافت نسخه گیت‌هاب](https://github.com/karingx/karing) / [دریافت نسخه اپ‌استور آیفون](https://apps.apple.com/us/app/karing/id6472431552)
* **FlClash:** [دریافت نسخه گیت‌هاب](https://github.com/chen08209/FlClash)
* **Clash Verge Rev:** [دریافت نسخه گیت‌هاب](https://github.com/clash-verge-rev/clash-verge-rev)
* **Throne:** [دریافت نسخه گیت‌هاب](https://github.com/throneproj/Throne)

### 🍎 مخصوص سیستم‌عامل آیفون (iOS App Store)
* [Clash Mi](https://apps.apple.com/us/app/clash-mi/id6744321968)
* [Clash Lite](https://apps.apple.com/us/app/clash-lite/id6761357475)
* [Nextin](https://apps.apple.com/us/app/nextin/id6754002454)
* [ShadowClash](https://apps.apple.com/us/app/shadowclash/id6760091330)
* [Neko Dash](https://apps.apple.com/us/app/neko-dash/id6758199321)

---

## 🌟 قابلیت‌های متمایز این پروژه
* **تفکیک‌ساز هوشمند متوالی:** پردازش و استخراج خودکار چند کانفیگ متوالی به‌هم‌چسبیده از یک خط منفرد [9].
* **اثر انگشت اتصالی فنی:** حذف هوشمند دیتای کاملاً تکراری فارغ از نام اتصال، بر اساس مشخصه‌های فنی اتصال.
* **پیشگیری از تداخل نام:** تخصیص پسوندهای افزایشی به دیتای هم‌نام جهت جلوگیری از خطای هم‌پوشانی کلش [9].
* **دی‌ان‌اس ضد فیلترینگ و ضد DPI ایران:** اعمال خودکار کانال بکاپ دی‌ان‌اس‌های اجباری با پروتکل TCP به موازات فیلتر مسمومیت‌ها [9].
"""
    
    with open("README.md", "w", encoding="utf-8") as readme_file:
        readme_file.write(markdown)
    
    # اتمام موفق فرآیند رندرسازی ریدمی
    log_stage(7, total_steps, "رندرسازی فایل نهایی ریدمی خاتمه یافت.")

if __name__ == "__main__":
    generate_markdown()
