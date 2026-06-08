import os
import urllib.request
from urllib.error import URLError, HTTPError
import concurrent.futures

# هدر مرورگر استاندارد جهت دور زدن محدودیت‌های فایروال یا سرورها
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

def download_one(source, normal_dir):
    """
    دانلود یک منبع خاص به صورت امن. اگر فایل دریافتی خالی بود یا خطا داد، فایل قبلی حفظ شده و تغییری ایجاد نمی‌شود.
    """
    url = source['url']
    name = source['name']
    target_path = os.path.join(normal_dir, name)
    
    print(f"شروع دانلود: {name} از آدرس {url}")
    try:
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': USER_AGENT}
        )
        # تخصیص مهلت زمانی (timeout) ۱۰ ثانیه‌ای برای جلوگیری از قفل شدن اکشن
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status != 200:
                print(f"[خطا] کد پاسخ نامعتبر {response.status} برای {name}. عملیات اسکیپ شد.")
                return False
            
            content_bytes = response.read()
            if not content_bytes or len(content_bytes.strip()) == 0:
                print(f"[هشدار] محتوای دریافت شده برای {name} خالی است. عملیات دانلود اسکیپ شد.")
                return False
                
            try:
                content = content_bytes.decode('utf-8', errors='ignore').strip()
            except Exception as dec_err:
                print(f"[خطا] رمزگشایی محتوای {name} ناموفق بود: {dec_err}. اسکیپ شد.")
                return False
                
            if not content:
                print(f"[هشدار] محتوای متنی {name} پس از فیلتر خالی است. اسکیپ شد.")
                return False
            
            # ایجاد دایرکتوری در صورت عدم وجود
            os.makedirs(normal_dir, exist_ok=True)
            
            # ذخیره‌سازی محتوای خام معمولی
            with open(target_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            print(f"[موفقیت] منبع {name} با موفقیت دانلود و بروزرسانی شد.")
            return True
            
    except HTTPError as e:
        print(f"[خطا] خطای پروتکل HTTP ({e.code}) برای منبع {name}: {e.reason}")
    except URLError as e:
        print(f"[خطا] خطای ارتباط شبکه برای منبع {name}: {e.reason}")
    except Exception as e:
        print(f"[خطا] خطای غیرمنتظره در پردازش دانلود منبع {name}: {str(e)}")
    
    return False

def download_all_sources(sources, normal_dir="sub/normal", max_workers=10):
    """
    دانلود همزمان تمام منابع با استفاده از ThreadPoolExecutor جهت رسیدن به حداکثر سرعت و کارایی.
    """
    os.makedirs(normal_dir, exist_ok=True)
    successful_sources = []
    
    if not sources:
        print("هیچ منبعی برای دانلود ارائه نشده است.")
        return successful_sources

    # اجرای همزمان دانلودها به کمک الگوهای بهینه سیستمی بدون بلاک کردن گیت‌هاب اکشن
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_src = {executor.submit(download_one, src, normal_dir): src for src in sources}
        for future in concurrent.futures.as_completed(future_to_src):
            src = future_to_src[future]
            try:
                success = future.result()
                if success:
                    successful_sources.append(src)
            except Exception as exc:
                print(f"[خطا] پردازش فرآیند دانلود منبع {src['name']} متوقف شد: {exc}")
                
    return successful_sources
