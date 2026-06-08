import os
import sys
import argparse

# افزودن مسیر فعلی به sys.path جهت اطمینان از صحت ایمپورت ماژول‌های محلی در گیت‌هاب اکشنز
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

import parser as src_parser
import downloader
import encoder
import clash_converter

def main():
    # تعریف آرگومان‌های ورودی برای کنترل ماژولار بودن عملکردها
    arg_parser = argparse.ArgumentParser(description="Modular Subscription Updater and Process Coordinator")
    arg_parser.add_argument(
        "--mode",
        choices=["all", "download_only", "mix_only", "base64_only"],
        default="all",
        help="حالت اجرای اسکریپت (پیش‌فرض: all)"
    )
    
    args = arg_parser.parse_args()
    mode = args.mode
    
    print(f"=== شروع فرآیند بروزرسانی با حالت اجرا: {mode} ===")
    
    # پوشه‌های هدف ذخیره‌سازی داده‌ها
    normal_dir = os.path.abspath(os.path.join(current_dir, "../sub/normal"))
    base64_dir = os.path.abspath(os.path.join(current_dir, "../sub/base64"))
    sources_file = os.path.abspath(os.path.join(current_dir, "../sources.txt"))
    
    # ۱. استخراج منابع از فایل منابع
    sources = src_parser.get_sources(sources_file)
    print(f"پارس کردن منابع به اتمام رسید. تعداد منبع معتبر: {len(sources)}")
    
    if not sources:
        print("[خطا] هیچ منبع معتبری برای پردازش یافت نشد. عملیات متوقف می‌شود.")
        sys.exit(0)
        
    mix_txt_path = os.path.join(normal_dir, "mix.txt")
        
    # ۲. مدیریت سناریوهای مختلف بر اساس آرگومان mode
    if mode == "all":
        # دانلود منابع فعال و معتبر
        successful_sources = downloader.download_all_sources(sources, normal_dir)
        # تبدیل منابع موفق به بیس۶۴ به صورت انفرادی
        encoder.generate_base64_files(successful_sources, normal_dir, base64_dir)
        # تولید فایل میکس معمولی و بیس۶۴ برای منابع موفق
        encoder.create_mixed_files(successful_sources, normal_dir, base64_dir)
        # اجرای خودکار فاز تبدیل به کلش میهومو (Clash YAML) پس از آماده‌سازی میکس
        clash_converter.run_converter(mix_txt_path, normal_dir)
        
    elif mode == "download_only":
        print("اجرای فاز دانلود منابع...")
        downloader.download_all_sources(sources, normal_dir)
        
    elif mode == "mix_only":
        print("اجرای فاز ادغام و میکس مجدد فایلهای موجود...")
        # در این حالت فقط از فایل‌های محلی دانلودی موجود برای تولید مجدد فایل میکس استفاده می‌شود
        encoder.create_mixed_files(sources, normal_dir, base64_dir)
        # بازسازی مجدد فایل کلش میهومو
        clash_converter.run_converter(mix_txt_path, normal_dir)
        
    elif mode == "base64_only":
        print("اجرای فاز تولید کدهای بیس۶۴ اختصاصی برای فایل‌های موجود...")
        # در این حالت فقط فایل‌های متنی محلی موجود به بیس۶۴ انکود می‌شوند
        encoder.generate_base64_files(sources, normal_dir, base64_dir)

    print("=== فرآیند بروزرسانی با موفقیت خاتمه یافت ===")

if __name__ == "__main__":
    main()
