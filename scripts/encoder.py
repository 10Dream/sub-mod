import os
import base64

def encode_to_base64_string(text: str) -> str:
    """
    تبدیل یک رشته متنی به فرمت Base64.
    """
    text_bytes = text.encode('utf-8')
    base64_bytes = base64.b64encode(text_bytes)
    return base64_bytes.decode('utf-8')

def generate_base64_files(sources, normal_dir="sub/normal", base64_dir="sub/base64"):
    """
    ایجاد نسخه Base64 برای تک‌تک فایلهای دانلود شده و موفق.
    """
    os.makedirs(base64_dir, exist_ok=True)
    count = 0
    
    for src in sources:
        name = src['name']
        normal_path = os.path.join(normal_dir, name)
        base64_path = os.path.join(base64_dir, name)
        
        if not os.path.exists(normal_path):
            continue
            
        try:
            with open(normal_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                
            if not content:
                continue
                
            b64_content = encode_to_base64_string(content)
            
            with open(base64_path, 'w', encoding='utf-8') as f:
                f.write(b64_content)
                
            count += 1
            print(f"[بیس۶۴] فایل رمزگذاری شده برای {name} ذخیره شد.")
        except Exception as e:
            print(f"[خطا] عدم امکان تولید بیس۶۴ برای {name}: {str(e)}")
            
    print(f"در مجموع {count} فایل به فرمت بیس۶۴ تبدیل شدند.")

def create_mixed_files(sources, normal_dir="sub/normal", base64_dir="sub/base64", mix_filename="mix.txt"):
    """
    ترکیب محتوای تمام منابع دانلود شده موفق در قالب یک فایل میکس نهایی (نسخه معمولی و بیس۶۴).
    """
    mixed_lines = []
    
    for src in sources:
        name = src['name']
        normal_path = os.path.join(normal_dir, name)
        
        if not os.path.exists(normal_path):
            continue
            
        try:
            with open(normal_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line_stripped = line.strip()
                    # نادیده گرفتن خطوط خالی، توضیحات یا هدرهای متفرقه YAML در فایل میکس عمومی
                    if line_stripped and not line_stripped.startswith('#'):
                        mixed_lines.append(line_stripped)
        except Exception as e:
            print(f"[خطا] خطای خواندن فایل {name} برای ساخت نسخه میکس: {str(e)}")
            
    if not mixed_lines:
        print("[هشدار] هیچ محتوایی برای ساخت فایل میکس یافت نشد.")
        return
        
    mixed_content = "\n".join(mixed_lines)
    
    # ۱. ذخیره فایل میکس معمولی در پوشه normal
    os.makedirs(normal_dir, exist_ok=True)
    normal_mix_path = os.path.join(normal_dir, mix_filename)
    try:
        with open(normal_mix_path, 'w', encoding='utf-8') as f:
            f.write(mixed_content)
        print(f"[میکس] فایل ترکیب‌شده معمولی با موفقیت در '{normal_mix_path}' ایجاد شد.")
    except Exception as e:
        print(f"[خطا] ذخیره ناموفق فایل میکس معمولی: {str(e)}")
        
    # ۲. ذخیره فایل میکس بیس۶۴ در پوشه base64
    os.makedirs(base64_dir, exist_ok=True)
    base64_mix_path = os.path.join(base64_dir, mix_filename)
    try:
        b64_mixed_content = encode_to_base64_string(mixed_content)
        with open(base64_mix_path, 'w', encoding='utf-8') as f:
            f.write(b64_mixed_content)
        print(f"[میکس] فایل ترکیب‌شده بیس۶۴ با موفقیت در '{base64_mix_path}' ایجاد شد.")
    except Exception as e:
        print(f"[خطا] ذخیره ناموفق فایل میکس بیس۶۴: {str(e)}")
