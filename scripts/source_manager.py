import os
import sys
import time
import subprocess
import parser as src_parser
import downloader
import encoder
import clash_converter

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

def is_file_stale(filepath: str, days: int = 15) -> bool:
    """
    بررسی سن آخرین بروزرسانی فایل بر اساس تاریخچه گیت و سیستم فایل.
    اگر فایل وجود داشته باشد و بیش از days روز پیش تغییر کرده باشد، مقدار True بازمی‌گرداند.
    برای فایل‌های جدید که هنوز دانلود نشده‌اند، False بازمی‌گرداند تا ابتدا دانلود شوند.
    """
    if not os.path.exists(filepath):
        return False
        
    try:
        commit_time_bytes = subprocess.check_output(
            ["git", "log", "-1", "--format=%ct", filepath],
            stderr=subprocess.DEVNULL
        )
        commit_time_str = commit_time_bytes.decode().strip()
        if commit_time_str.isdigit():
            mtime = int(commit_time_str)
            now = int(time.time())
            return (now - mtime) >= (days * 24 * 3600)
    except Exception:
        pass
        
    try:
        mtime = os.path.getmtime(filepath)
        now = time.time()
        return (now - mtime) >= (days * 24 * 3600)
    except Exception:
        return False

def clean_source_files(name: str, normal_dir: str, base64_dir: str, clash_dir: str):
    """
    حذف کامل فایل‌های محلی یک منبع راکد از پوشه‌های ساب، تا در میکس و ریدمی وارد نشود.
    """
    base_name = os.path.splitext(name)[0]
    paths_to_remove = [
        os.path.join(normal_dir, name),
        os.path.join(base64_dir, name),
        os.path.join(clash_dir, f"{base_name}.yaml"),
        os.path.join(clash_dir, f"{base_name}_unlimited.yaml")
    ]
    for p in paths_to_remove:
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass

def read_raw_source_lines(filepath: str) -> list:
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def write_source_lines(filepath: str, lines: list):
    with open(filepath, 'w', encoding='utf-8') as f:
        for line in lines:
            f.write(line + '\n')

def archive_stale_sources(sources_file: str, inactive_file: str, normal_dir: str, base64_dir: str, clash_dir: str, days: int = 15) -> int:
    """
    اسکن تمام منابع فعال در sources.txt و انتقال منابعی که بیش از ۱۵ روز آپدیت نشده‌اند به inactive_sources.txt.
    """
    if not os.path.exists(sources_file):
        return 0
        
    sources = src_parser.get_sources(sources_file)
    if not sources:
        return 0
        
    active_lines = []
    stale_lines = []
    
    existing_inactive = set(read_raw_source_lines(inactive_file))
    archived_count = 0
    
    cyan = "\033[96m"
    yellow = "\033[93m"
    reset = "\033[0m"
    
    print(f"{cyan}[مدیریت منابع]{reset} در حال پایش سن منابع فعال (آستانه راکد بودن: {days} روز)...", flush=True)
    
    for src in sources:
        name = src['name']
        raw_line = src['raw_line']
        normal_path = os.path.join(normal_dir, name)
        
        # اگر فایل وجود ندارد یا بیش از ۱۵ روز است بروز نشده
        if is_file_stale(normal_path, days=days):
            archived_count += 1
            stale_lines.append(raw_line)
            clean_source_files(name, normal_dir, base64_dir, clash_dir)
            print(f"  {yellow}📦 منبع راکد {name} شناسایی و به inactive_sources.txt منتقل شد.{reset}", flush=True)
        else:
            active_lines.append(raw_line)
            
    if archived_count > 0:
        write_source_lines(sources_file, active_lines)
        # ادغام با لیست راکد موجود بدون تکرار
        all_inactive = list(existing_inactive.union(set(stale_lines)))
        all_inactive.sort()
        write_source_lines(inactive_file, all_inactive)
        print(f"{cyan}[مدیریت منابع]{reset} در مجموع {archived_count} منبع راکد از لیست اصلی خارج و پاک‌سازی شدند.", flush=True)
    else:
        print(f"{cyan}[مدیریت منابع]{reset} تمامی منابع فعال دارای سن زیر {days} روز هستند. نیازی به آرشیو نیست.", flush=True)
        
    return archived_count

def check_and_revive_inactive(sources_file: str, inactive_file: str, normal_dir: str, base64_dir: str, clash_dir: str) -> int:
    """
    پایش ماهانه منابع راکد در inactive_sources.txt؛ تست دانلود و احیای مجدد سورس‌های فعال شده به sources.txt.
    """
    if not os.path.exists(inactive_file):
        print("[پایش ماهانه] فایل inactive_sources.txt یافت نشد.", flush=True)
        return 0
        
    inactive_sources = src_parser.get_sources(inactive_file)
    if not inactive_sources:
        print("[پایش ماهانه] هیچ منبع راکدی برای پایش وجود ندارد.", flush=True)
        return 0
        
    cyan = "\033[96m"
    green = "\033[92m"
    reset = "\033[0m"
    
    print(f"{cyan}[پایش ماهانه]{reset} در حال تست و اعتبارسنجی {len(inactive_sources)} منبع راکد جهت احیای احتمالی...", flush=True)
    
    # دانلود تستی منابع راکد
    successful = downloader.download_all_sources(inactive_sources, normal_dir)
    
    revived_names = set()
    for src in successful:
        name = src['name']
        normal_path = os.path.join(normal_dir, name)
        if os.path.exists(normal_path):
            with open(normal_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
            proxies = clash_converter.parse_subscription_text(content)
            # اگر کانفیگ‌های معتبری استخراج شد، این منبع زنده است و باید احیا شود
            if len(proxies) > 0:
                revived_names.add(name)
                print(f"  {green}✨ منبع {name} فعال و دارای {len(proxies)} کانفیگ شناسایی شد! در حال احیا به لیست اصلی...{reset}", flush=True)
            else:
                clean_source_files(name, normal_dir, base64_dir, clash_dir)
                
    if not revived_names:
        print(f"{cyan}[پایش ماهانه]{reset} هیچ‌کدام از منابع راکد فعال نشده بودند و در لیست راکد باقی ماندند.", flush=True)
        return 0
        
    # انتقال منابع احیا شده از inactive به sources.txt
    current_active_lines = read_raw_source_lines(sources_file)
    current_inactive_lines = read_raw_source_lines(inactive_file)
    
    new_active = list(current_active_lines)
    new_inactive = []
    
    for line in current_inactive_lines:
        line_name = line.split('|')[0].strip() if '|' in line else line.strip()
        if line_name in revived_names:
            if line not in new_active:
                new_active.append(line)
        else:
            new_inactive.append(line)
            
    write_source_lines(sources_file, new_active)
    write_source_lines(inactive_file, new_inactive)
    
    print(f"{green}[احیای موفق]{reset} تعداد {len(revived_names)} منبع با موفقیت به چرخه سابسکریپشن اصلی بازگشتند.", flush=True)
    return len(revived_names)
