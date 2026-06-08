import os
import re
import base64
import urllib.request
from urllib.error import URLError, HTTPError
import concurrent.futures

# هدر مرورگر استاندارد جهت دور زدن محدودیت‌های فایروال یا سرورها
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

def safe_b64decode(s: str) -> str:
    """رمزگشایی ایمن رشته‌های Base64 با تنظیم پدینگ"""
    s = s.strip().replace('-', '+').replace('_', '/')
    padding = len(s) % 4
    if padding:
        s += '=' * (4 - padding)
    try:
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def decode_if_base64(text: str) -> str:
    """
    تشخیص هوشمند و خودکار محتوا. 
    اگر ورودی بیس۶۴ باشد آن را رمزگشایی می‌کند، در غیر این صورت خود متن را بازمی‌گرداند.
    """
    text_clean = text.strip()
    if not text_clean:
        return ""
    
    # اگر متن حاوی کاراکترهای آدرس پروتکل‌ها (://) باشد، از قبل رمزگشایی شده است
    if "://" in text_clean:
        return text_clean
        
    # حذف کاراکترهای متفرقه غیر بیس۶۴ برای تست معتبر بودن
    b64_chars = re.sub(r'[^a-zA-Z0-9+/=_-]', '', text_clean)
    if len(b64_chars) < 10:
        return text_clean
        
    decoded = safe_b64decode(b64_chars)
    # اگر دیکود شد و شامل پروتکل‌ها یا ساختار متنی چندخطی بود، یعنی بیس۶۴ ورودی بوده است
    if decoded and ("://" in decoded or "\n" in decoded or len(decoded) > 10):
        return decoded.strip()
        
    return text_clean

def download_one(source, normal_dir):
    """
    دانلود یک منبع خاص به صورت امن. تشخیص خودکار فرمت متنی/بیس۶۴ و ذخیره متنی خام.
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
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status != 200:
                print(f"[خطا] کد پاسخ نامعتبر {response.status} برای {name}. عملیات اسکیپ شد.")
                return False
            
            content_bytes = response.read()
            if not content_bytes or len(content_bytes.strip()) == 0:
                print(f"[هشدار] محتوای دریافت شده برای {name} خالی است. عملیات دانلود اسکیپ شد.")
                return False
                
            try:
                content_raw = content_bytes.decode('utf-8', errors='ignore').strip()
            except Exception as dec_err:
                print(f"[خطا] رمزگشایی اولیه محتوای {name} ناموفق بود: {dec_err}. اسکیپ شد.")
                return False
                
            # تشخیص هوشمند بیس۶۴ و رمزگشایی خودکار آن به متن خام معمولی
            content = decode_if_base64(content_raw)
                
            if not content:
                print(f"[هشدار] محتوای متنی {name} پس از فیلتر خالی است. اسکیپ شد.")
                return False
            
            # ایجاد دایرکتوری در صورت عدم وجود
            os.makedirs(normal_dir, exist_ok=True)
            
            # ذخیره‌سازی محتوای خام معمولی (همیشه به صورت دکود شده و خوانا)
            with open(target_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            print(f"[موفقیت] منبع {name} با موفقیت دانلود، دکود و بروزرسانی شد.")
            return True
            
    except HTTPError as e:
        print(f"[خطا] خطای پروتکل HTTP ({e.code}) برای منبع {name}: {e.reason}")
    except URLError as e:
        print(f"[خطا] خطای ارتباط شبکه برای منبع {name}: {e.reason}")
    except Exception as e:
        print(f"[خطا] خطای غیرمنتظره در پردازش دانلود منبع {name}: {str(e)}")
    
    return False

def download_all_sources(sources, normal_dir="sub/normal", max_workers=10):
    os.makedirs(normal_dir, exist_ok=True)
    successful_sources = []
    
    if not sources:
        print("هیچ منبعی برای دانلود ارائه نشده است.")
        return successful_sources

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
