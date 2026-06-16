مسیر و نام فایل: scripts/readme_generator.py

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

def get_country_flag_emoji(cc: str) -> str:
    """تبدیل کد دو حرفی کشور به ایموجی پرچم مربوطه"""
    if not cc or cc == "UNKNOWN":
        return "🏳️"
    cc = cc.upper()
    return "".join(chr(127397 + ord(c)) for c in cc)

def get_relative_time(filepath):
    """
    محاسبه و تبدیل زمان آخرین تغییر واقعی فایل در تاریخچه گیت (Commit History) به صورت فارسی [2].
    این فرآیند تغییرات لایو دیسک رانر را با تاریخچه ثبت شده گیت ترکیب می‌کند تا دقیق‌ترین زمان ثبت شود.
    """
    if not os.path.exists(filepath):
        return "نامشخص"
        
    # ۱. بررسی اینکه آیا فایل در اجرای جاری ویرایش محتوایی شده است یا خیر
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

    # ۲. در غیر این صورت (فایل تغییری نکرده)، زمان آخرین کامیت واقعی فایل واکشی می‌شود [2]
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
    owner, repo = get_repo_info()
    base_raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/sub"
    
    now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    
    # واکشی فایل‌های سورس مرجع معمولی
    normal_files = get_file_list("sub/normal")
    
    # واکشی فایل‌های اسپلیتر عمومی (GRPC, WS, TLS, IPv4, IPv6 و غیره)
    split_files = get_file_list("sub/split")
    
    # واکشی فایل‌های اسپلیتر کشوری
    country_files = get_file_list("sub/split/countries")
    
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
    
    # جدول ۱: اضافه کردن تک‌فایل‌ها به صورت سطر به سطر
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

## 🥞 اشتراک‌های تفکیک‌شده هوشمند (Daily Split Subscriptions)

*این بخش روزی یک‌بار به طور خودکار دیتای منابعِ فعالِ کمتر از ۱ هفته گذشته را ترکیب کرده و به تفکیک ساختارهای فنی و بدون محدودیت تعداد کانفیگ (Unlimited) ارائه می‌دهد [9].*

| نوع دسته‌بندی | 📝 متنی خام (Normal) | 🔒 رمزگذاری‌شده (Base64) | 🧊 کلش میهومو (Clash YAML) | آخرین بروزرسانی |
| :--- | :---: | :---: | :---: | :---: |
"""

    # جدول ۲: اسپلیترهای عمومی
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

## 🗺️ اشتراک‌های تفکیک‌شده بر اساس کشور (Daily Country-Based Subscriptions)

*میکس بومی و بدون محدودیت تعداد کانفیگ (Unlimited) پروکسی‌ها به تفکیک موقعیت جغرافیایی سرورها به همراه اموجی پرچم کشور در کلش [9].*

| کشور هدف | 📝 متنی خام (Normal) | 🔒 رمزگذاری‌شده (Base64) | 🧊 کلش میهومو (Clash YAML) | آخرین بروزرسانی |
| :--- | :---: | :---: | :---: | :---: |
"""

    # جدول ۳: اسپلیترهای کشوری
    for f in country_files:
        filepath_country = f"sub/split/countries/{f}"
        cc = os.path.splitext(f)[0].upper()
        clash_filename = f"{cc}.yaml"
        
        has_b64 = os.path.exists(f"sub/base64/split/countries/{f}")
        has_clash = os.path.exists(f"sub/clash/split/countries/{clash_filename}")
        
        flag = get_country_flag_emoji(cc)
        
        normal_link = f"[📝 دریافت لینک]({base_raw_url}/split/countries/{f})"
        b64_link = f"[🔒 دریافت لینک]({base_raw_url}/base64/split/countries/{f})" if has_b64 else "❌ ندارد"
        clash_link = f"[🧊 دریافت لینک]({base_raw_url}/clash/split/countries/{clash_filename})" if has_clash else "❌ ندارد"
        
        markdown += f"| {flag} **{cc}** | {normal_link} | {b64_link} | {clash_link} | {get_relative_time(filepath_country)} |\n"

    markdown += """
---

## 📱 کلاینت‌های پیشنهادی و مورد تأیید
شما می‌توانید از برنامه‌های معتبر، بومی و هایپرلینک شده زیر جهت اتصال استفاده کنید:

### 💻 مولتی‌پلتفرم (ویندوز، اندروید، مک، لینوکس)
* **Hiddify:** [دریافت نسخه گیت‌هاب](https://github.com/hiddify/hiddify-app) / [دریافت نسخه اپ‌استور آیفون](https://apps.apple.com/us/app/hiddify-proxy-vpn/id6596777532)
* **Karing:** [دریافت نسخه گیت‌هاب](https://github.com/KaringX/karing) / [دریافت نسخه اپ‌استور آیفون](https://apps.apple.com/us/app/karing/id6472431552)
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
    
    print("[موفقیت] فایل README.md جدید با موفقیت تولید و بروزرسانی شد.")

if __name__ == "__main__":
    generate_markdown()

--- گزارش خلاصه تغییرات ---

عملکرد حفظ شده:

  - حفظ الگوی کامل جدول Unified ستونی، کدهای زمانی دقیق مبتنی بر تاریخچه کامیت
    گیت و لینک‌های بومی ۱۲ کلاینت گیت‌هاب و اپ‌استور.

عملکرد اضافه شده:

  - تولید خودکار ۲ جدول جدید اسپلیتر روزانه در README.md:
      - جدول اسپلیترهای عمومی (Daily Split Subscriptions): نمایش سابسکریپشن‌های
        تفکیک‌شده بر اساس پروتکل‌ها و امنیت شبکه به موازات فایل‌های متنی خام،
        کدهای بیس۶۴ و کانفیگ‌های بدون سقف (unlimited) کلشYAML.
      - جدول اسپلیترهای کشوری (Daily Country-Based Subscriptions): لیست‌سازی
        پویای تمام موقعیت‌های مکانی واکشی‌شده در هفته اخیر به همراه اموجی
        پرچم مربوط به آن کشور (نظیر 🇺🇸 یا 🇩🇪) و لینک‌های دانلود مستقیم raw آن
        فایل‌ها.
  - Fail-Safe بودن جداول اسپلیترها: این جداول نیز پیش از قرار دادن دکمه دانلود،
    وجود فیزیکی فایل‌ها را به کمک متد os.path.exists صحت‌سنجی می‌کنند تا مانع
    از بروز خطای لینک شکسته (۴۰۴) در مستندات ریدمی شوند.

پروژه همه‌جانبه، هوشمند و ماژولار شما به تکامل نهایی خود رسید! هر دو اکشن
(بروزرسانی ساعتی و میکس کشوری/پروتکلیِ روزانه بدون سقف) آماده کارکردن با
بالاترین سطح کارایی، بهینگی و زیبایی در گیت‌هاب شما هستند. آماده بررسی‌های
بعدی یا هرگونه دستور دیگر شما هستم._
