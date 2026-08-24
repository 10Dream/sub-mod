import os
import sys
import time
import argparse

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# افزودن مسیر فعلی به sys.path جهت اطمینان از صحت ایمپورت ماژول‌های محلی در گیت‌هاب اکشنز
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

import parser as src_parser
import downloader
import encoder
import clash_converter
import daily_mix
import readme_generator
import source_manager

def print_banner(mode: str):
    cyan = "\033[96m"
    yellow = "\033[93m"
    reset = "\033[0m"
    bold = "\033[1m"
    print(f"\n{cyan}╔══════════════════════════════════════════════════════════════════╗{reset}", flush=True)
    print(f"{cyan}║{bold}{yellow}   ⚡ سیستم هوشمند تجمیع، تفکیک و تبدیل کانفیگ سابسکریپشن      {reset}{cyan}║{reset}", flush=True)
    print(f"{cyan}║   حالت اجرا: {bold}{mode.upper()}{reset}{cyan}                                                ║{reset}", flush=True)
    print(f"{cyan}╚══════════════════════════════════════════════════════════════════╝{reset}\n", flush=True)

def print_stage(step: int, total: int, title: str):
    green = "\033[92m"
    yellow = "\033[93m"
    reset = "\033[0m"
    bold = "\033[1m"
    print(f"\n{yellow}▶ {bold}[مرحله {step}/{total}]{reset} {green}{bold}{title}{reset}", flush=True)
    print(f"{yellow}{'─' * 60}{reset}", flush=True)

def main():
    start_time = time.time()
    
    arg_parser = argparse.ArgumentParser(description="Modular Subscription Updater and Process Coordinator")
    arg_parser.add_argument(
        "--mode",
        choices=["all", "download_only", "mix_only", "base64_only", "clash_only", "check_inactive"],
        default="all",
        help="حالت اجرای اسکریپت (پیش‌فرض: all)"
    )
    
    args = arg_parser.parse_args()
    mode = args.mode
    
    print_banner(mode)
    
    # پوشه‌های هدف ذخیره‌سازی داده‌ها
    normal_dir = os.path.abspath(os.path.join(current_dir, "../sub/normal"))
    base64_dir = os.path.abspath(os.path.join(current_dir, "../sub/base64"))
    clash_dir = os.path.abspath(os.path.join(current_dir, "../sub/clash"))
    sources_file = os.path.abspath(os.path.join(current_dir, "../sources.txt"))
    inactive_file = os.path.abspath(os.path.join(current_dir, "../inactive_sources.txt"))
    
    if mode == "all":
        total_stages = 7
        
        # مرحله ۱: پایش سن منابع و انتقال خودکار منابع راکد بالای ۱۵ روز
        print_stage(1, total_stages, "پایش چرخه حیات و آرشیو منابع راکد بالای ۱۵ روز")
        source_manager.archive_stale_sources(sources_file, inactive_file, normal_dir, base64_dir, clash_dir, days=15)
        
        # واکشی مجدد منابع فعال
        sources = src_parser.get_sources(sources_file)
        print(f"📋 تعداد منابع فعال جهت پردازش: {len(sources)} منبع", flush=True)
        if not sources:
            print("[هشدار] هیچ منبع فعالی برای پردازش یافت نشد.", flush=True)
            return
        
        # مرحله ۲: دانلود منابع فعال
        print_stage(2, total_stages, "دانلود هوشمند تمام منابع فعال به صورت موازی")
        successful_sources = downloader.download_all_sources(sources, normal_dir)
        print(f"✅ دانلود موفق: {len(successful_sources)} از {len(sources)} منبع", flush=True)
        
        # مرحله ۳: تولید بیس۶۴ انفرادی
        print_stage(3, total_stages, "رمزگذاری و تولید فایل‌های Base64 اختصاصی هر منبع")
        encoder.generate_base64_files(successful_sources, normal_dir, base64_dir)
        
        # مرحله ۴: تولید فایل خام اولیه میکس
        print_stage(4, total_stages, "تجمیع اولیه خطوط منابع فعال در فایل‌های mix.txt")
        encoder.create_mixed_files(successful_sources, normal_dir, base64_dir)
        
        # مرحله ۵: تبدیل کلش میهومو برای تک‌تک منابع (نسخه ۸۰۰ تایی و نامحدود)
        print_stage(5, total_stages, "تبدیل تمام منابع انفرادی به کانفیگ دوگانه کلش (۸۰۰ تایی + نامحدود)")
        clash_converter.run_converter_for_all(successful_sources, normal_dir, clash_dir)
        
        # مرحله ۶: پردازش مگا-میکس و تفکیک دسته‌بندی‌های ۴ گانه
        print_stage(6, total_stages, "فیلترینگ تکراری، شناسایی کشور/دیتاسنتر و ساخت دسته‌های اسپلیت")
        daily_mix.main()
        
        # مرحله ۷: بروزرسانی مستندات README.md
        print_stage(7, total_stages, "رندرسازی جداول ۶ ستونه و بازتولید فایل README.md مخزن")
        readme_generator.generate_markdown()
        
    elif mode == "check_inactive":
        print_stage(1, 2, "پایش ماهانه و تست احیای منابع راکد در inactive_sources.txt")
        revived_count = source_manager.check_and_revive_inactive(sources_file, inactive_file, normal_dir, base64_dir, clash_dir)
        
        if revived_count > 0:
            print_stage(2, 2, "بازسازی دیتای سابسکریپشن و ریدمی با منابع احیا شده")
            active_sources = src_parser.get_sources(sources_file)
            encoder.generate_base64_files(active_sources, normal_dir, base64_dir)
            encoder.create_mixed_files(active_sources, normal_dir, base64_dir)
            clash_converter.run_converter_for_all(active_sources, normal_dir, clash_dir)
            daily_mix.main()
            readme_generator.generate_markdown()
        else:
            print("[پایش ماهانه] تغییری در لیست منابع رخ نداد.", flush=True)
            
    elif mode == "download_only":
        sources = src_parser.get_sources(sources_file)
        print_stage(1, 1, "دانلود هوشمند منابع")
        downloader.download_all_sources(sources, normal_dir)
        
    elif mode == "mix_only":
        sources = src_parser.get_sources(sources_file)
        total_stages = 4
        print_stage(1, total_stages, "تجمیع خطوط منابع محلی در mix.txt")
        encoder.create_mixed_files(sources, normal_dir, base64_dir)
        
        print_stage(2, total_stages, "تولید کانفیگ دوگانه کلش برای منابع محلی")
        clash_converter.run_converter_for_all(sources, normal_dir, clash_dir)
        
        print_stage(3, total_stages, "اجرای اسپلیت روزانه (پروتکل‌ها، شبکه‌ها، دیتاسنترها و کشورها)")
        daily_mix.main()
        
        print_stage(4, total_stages, "بروزرسانی فایل README.md")
        readme_generator.generate_markdown()
        
    elif mode == "base64_only":
        sources = src_parser.get_sources(sources_file)
        print_stage(1, 1, "تولید کدهای بیس۶۴ برای فایل‌های موجود")
        encoder.generate_base64_files(sources, normal_dir, base64_dir)
        
    elif mode == "clash_only":
        sources = src_parser.get_sources(sources_file)
        total_stages = 2
        print_stage(1, total_stages, "ساخت کانفیگ‌های دوگانه کلش برای تمام منابع")
        clash_converter.run_converter_for_all(sources, normal_dir, clash_dir)
        
        print_stage(2, total_stages, "بروزرسانی مستندات مخزن")
        readme_generator.generate_markdown()

    elapsed = round(time.time() - start_time, 2)
    green = "\033[92m"
    reset = "\033[0m"
    bold = "\033[1m"
    print(f"\n{green}╔══════════════════════════════════════════════════════════════════╗{reset}", flush=True)
    print(f"{green}║{bold}  🎉 کلیه مراحل با موفقیت به پایان رسیدند! ({elapsed} ثانیه)           {reset}{green}║{reset}", flush=True)
    print(f"{green}╚══════════════════════════════════════════════════════════════════╝{reset}\n", flush=True)

if __name__ == "__main__":
    main()

