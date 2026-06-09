import os
import re
import subprocess
from datetime import datetime, timezone

def get_repo_info():
    """
    استخراج نام نویسنده و مخزن جهت ساخت خودکار لینک‌های دانلود خام مستقیم.
    """
    # بررسی متغیرهای محیطی گیت‌هاب اکشنز
    repo_env = os.environ.get("GITHUB_REPOSITORY")
    if repo_env and "/" in repo_env:
        owner, repo = repo_env.split("/", 1)
        return owner, repo
    
    # بکاپ محلی با استفاده از دستور git
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

def get_relative_time(filepath):
    """
    محاسبه و تبدیل زمان آخرین تغییر فایل به صورت مدت زمان سپری شده فارسی (نامحسوس و بهینه).
    """
    if not os.path.exists(filepath):
        return "نامشخص"
    try:
        mtime = os.path.getmtime(filepath)
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
    owner, repo = get_repo_info()
    base_raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/sub"
    
    now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    
    # لیست کردن فایل‌های خروجی موفق در هر پوشه
    normal_files = get_file_list("sub/normal")
    base64_files = get_file_list("sub/base64")
    clash_files = get_file_list("sub/clash")
    
    markdown = f"""# ⚡️ سیستم تجمیع هوشمند و خودکار کانفیگ (V2ray & Clash)

یک پروژه کاملاً پویا و ماژولار مبتنی بر گیت‌هاب اکشنز جهت دانلود، پارس، فیلترینگ دیتای تکراری (بر اساس الگوریتم اثر انگشت اتصالی فنی) و جداسازی هوشمند کانفیگ‌های متوالی به‌هم‌چسبیده. 

> 🔄 **بروزرسانی خودکار:** هر ۳ ساعت یک‌بار دیتای تمام منابع واکشی شده و کانفیگ‌های معیوب فیلتر می‌شوند.

---

### 🕒 آخرین زمان اجرای کلی پایپلاین
`{now_utc}`

[![GitHub license](https://img.shields.io/github/license/{owner}/{repo}?style=flat-square)](https://github.com/{owner}/{repo}/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/{owner}/{repo}?style=flat-square)](https://github.com/{owner}/{repo}/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/{owner}/{repo}?style=flat-square)](https://github.com/{owner}/{repo}/issues)

---

## 🔗 لینک‌های اشتراک مستقیم (Raw Subscriptions)

تمامی لینک‌های زیر به صورت مستقیم (Raw) از سرورهای گیت‌هاب تحویل داده می‌شوند و فاقد کش هستند.

---

### ۱. 📝 کانفیگ‌های متنی خام (Plain-Text Subscriptions)
مناسب برای استفاده در کلاینت‌های اندروید، ویندوز و آیفون.

| نام منبع | آدرس فایل | آخرین بروزرسانی | لینک خام (Raw) |
| :--- | :---: | :---: | :---: |
| **🌀 ترکیب تمام منابع (میکس)** | `mix.txt` | **{get_relative_time('sub/normal/mix.txt')}** | [🔗 دریافت لینک]({base_raw_url}/normal/mix.txt) |
"""
    
    # اضافه کردن تک‌فایل‌های معمولی
    for f in normal_files:
        if f == "mix.txt":
            continue
        filepath = f"sub/normal/{f}"
        markdown += f"| 📄 {f} | `{f}` | {get_relative_time(filepath)} | [🔗 دریافت لینک]({base_raw_url}/normal/{f}) |\n"
        
    markdown += f"""
---

### ۲. 🔒 کانفیگ‌های انکود شده (Base64 Subscriptions)
مناسب برای کلاینت‌های کلاسیک که فقط فرمت Base64 می‌پذیرند.

| نام منبع | آدرس فایل | آخرین بروزرسانی | لینک خام (Raw) |
| :--- | :---: | :---: | :---: |
| **🌀 ترکیب تمام منابع (میکس)** | `mix.txt` | **{get_relative_time('sub/base64/mix.txt')}** | [🔗 دریافت لینک]({base_raw_url}/base64/mix.txt) |
"""
    
    # اضافه کردن تک‌فایل‌های بیس۶۴
    for f in base64_files:
        if f == "mix.txt":
            continue
        filepath = f"sub/base64/{f}"
        markdown += f"| 🔐 {f} | `{f}` | {get_relative_time(filepath)} | [🔗 دریافت لینک]({base_raw_url}/base64/{f}) |\n"

    markdown += f"""
---

### ۳. 🧊 کانفیگ‌های کلش میهومو (Clash/Mihomo YAML Subscriptions)
مخصوص بارگذاری در کلاینت‌های کلش و نرم‌افزارهای سازگار با ساختار قوانین روتینگ هوشمند YAML [9].

| نام منبع | آدرس فایل | آخرین بروزرسانی | لینک خام (Raw) |
| :--- | :---: | :---: | :---: |
| **🌀 ترکیب تمام منابع (میکس)** | `mix.yaml` | **{get_relative_time('sub/clash/mix.yaml')}** | [🔗 دریافت لینک]({base_raw_url}/clash/mix.yaml) |
"""
    
    # اضافه کردن تک‌فایل‌های کلش
    for f in clash_files:
        if f == "mix.yaml":
            continue
        filepath = f"sub/clash/{f}"
        markdown += f"| 🧊 {f} | `{f}` | {get_relative_time(filepath)} | [🔗 دریافت لینک]({base_raw_url}/clash/{f}) |\n"

    markdown += """
---

## 📱 کلاینت‌های پیشنهادی بر اساس سیستم‌عامل
شما می‌توانید از برنامه‌های معتبر و هایپرلینک شده زیر جهت اتصال استفاده کنید:

### 🤖 اندروید (Android)
* [v2rayNG](https://github.com/2dust/v2rayNG) (مناسب برای سابسکریپشن‌های معمولی و Base64)
* [NekoBox for Android](https://github.com/MatsuriDayo/NekoBoxForAndroid) (پشتیبانی عالی از تمام پروتکل‌ها و سابسکریپشن‌های معمولی و Base64)
* [FlClash](https://github.com/chen08209/FlClash) (کلاینت مدرن و پایدار مخصوص سابسکریپشن‌های کلش YAML)
* [Clash Meta for Android](https://github.com/MetaCubeX/ClashMetaForAndroid) (کلاینت رسمی و قدرتمند مخصوص سابسکریپشن‌های کلش YAML)

### 💻 ویندوز (Windows)
* [v2rayN](https://github.com/2dust/v2rayN) (برنامه سبک و پرسرعت برای سابسکریپشن‌های معمولی و Base64)
* [NekoRay](https://github.com/MatsuriDayo/nekoray) (هسته فوق‌العاده قوی برای سابسکریپشن‌های معمولی و Base64)
* [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) (زیباترین و بهترین کلاینت دسکتاپ مخصوص سابسکریپشن‌های کلش YAML)
* [Mihomo Party](https://github.com/mihomo-party-org/mihomo-party) (کلاینت نوین و پایدار مخصوص سابسکریپشن‌های کلش YAML)

### 🍎 آیفون و مک (iOS / macOS)
* [Shadowrocket](https://apps.apple.com/us/app/shadowrocket/id932747118) (بهترین کلاینت غیر رایگان با پشتیبانی ۱۰۰ درصدی از تمامی فرمت‌ها و ساب‌ها)
* [V2Box](https://apps.apple.com/us/app/v2box-v2ray-client/id1639768607) (کلاینت رایگان و باکیفیت برای سابسکریپشن‌های معمولی و Base64)
* [Streisand](https://apps.apple.com/us/app/streisand/id6450534078) (کلاینت پرسرعت و رایگان برای سابسکریپشن‌های معمولی و Base64)
* [FoXray](https://apps.apple.com/us/app/foxray/id6444825379) (کلاینت کاربرپسند برای سابسکریپشن‌های معمولی و Base64)

---

## 🌟 قابلیت‌های متمایز این پروژه
* **تفکیک‌ساز هوشمند متوالی:** پردازش و استخراج خودکار چند کانفیگ متوالی به‌هم‌چسبیده از یک خط منفرد [9].
* **اثر انگشت اتصالی فنی:** حذف هوشمند دیتای کاملاً تکراری فارغ از نام اتصال، بر اساس مشخصه‌های فنی اتصال.
* **پیشگیری از تداخل نام:** تخصیص پسوندهای افزایشی به دیتای هم‌نام جهت جلوگیری از خطای هم‌پوشانی کلش [9].
* **دی‌ان‌اس ضد فیلترینگ و ضد DPI ایران:** اعمال خودکار کانال بکاپ دی‌ان‌اس‌های اجباری با پروتکل TCP به موازات فیلتر مسمومیت‌ها [9].
"""
    
    with open("README.md", "w", encoding="utf-8") as readme_file:
        readme_file.write(markdown)
    
    print("[موفقیت] فایل README.md جدید با موفقیت تولید و بروزرسانی شد.")

if __name__ == "__main__":
    generate_markdown()
