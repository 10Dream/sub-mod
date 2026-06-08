import os
import re
from urllib.parse import urlparse

def parse_github_url(url: str):
    """
    بررسی آدرس و تبدیل لینک‌های گیت‌هاب به نسخه خام (Raw) به همراه استخراج اطلاعات نویسنده و مخزن.
    """
    # الگوی لینک معمولی گیت‌هاب دارای بخش blob
    github_blob_pattern = re.compile(
        r'https?://(?:www\.)?github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)'
    )
    match = github_blob_pattern.match(url)
    if match:
        user, repo, branch, path = match.groups()
        # تبدیل مستقیم به آدرس خام بر اساس ساختار درخواستی
        raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/refs/heads/{branch}/{path}"
        filename = path.split('/')[-1]
        return raw_url, user, repo, filename
    
    # الگوی لینک خام گیت‌هاب
    github_raw_pattern = re.compile(
        r'https?://(?:www\.)?raw\.githubusercontent\.com/([^/]+)/([^/]+)/(?:refs/heads/)?([^/]+)/(.+)'
    )
    match_raw = github_raw_pattern.match(url)
    if match_raw:
        user, repo, _, path = match_raw.groups()
        filename = path.split('/')[-1]
        return url, user, repo, filename

    return None

def clean_filename(name: str) -> str:
    """
    پاک‌سازی نام فایل از کاراکترهای نامعتبر در سیستم‌عامل‌ها.
    """
    return re.sub(r'[\\/*?:"<>|]', "_", name)

def get_sources(file_path="sources.txt"):
    """
    خواندن فایل منابع و پارس کردن هر لینک به همراه مشخص کردن نام نهایی فایل خروجی.
    """
    if not os.path.exists(file_path):
        print(f"خطا: فایل منابع در مسیر '{file_path}' یافت نشد.")
        return []
    
    sources = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            # نادیده گرفتن خطوط خالی و کامنت‌ها
            if not line or line.startswith('#'):
                continue
            
            parts = line.split('|', 1)
            url = parts[0].strip()
            custom_name = parts[1].strip() if len(parts) > 1 else None
            
            github_info = parse_github_url(url)
            if github_info:
                raw_url, user, repo, filename = github_info
                url = raw_url
                if not custom_name:
                    # الگوی نام‌گذاری: USER-REPO-FILENAME
                    custom_name = f"{user}-{repo}-{filename}"
            else:
                if not custom_name:
                    # برای لینک‌های غیر گیت‌هاب، نام فایل از آخرین بخش آدرس برداشته می‌شود
                    parsed = urlparse(url)
                    custom_name = os.path.basename(parsed.path)
                    if not custom_name:
                        custom_name = "unknown_source.txt"
            
            # پاک‌سازی و اطمینان از صحت نام فایل خروجی
            custom_name = clean_filename(custom_name)
            
            sources.append({
                'url': url,
                'name': custom_name
            })
            
    return sources

# بخش تست سریع ماژول در صورت اجرای مستقیم
if __name__ == "__main__":
    test_sources = get_sources()
    print("تعداد منابع یافت شده:", len(test_sources))
    for src in test_sources:
        print(f"نام: {src['name']} -> آدرس: {src['url']}")
