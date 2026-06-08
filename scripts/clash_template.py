# =====================================================================
# ماژول تمپلت و پیکربندی‌های بومی کلش میهومو (Modular Clash/Mihomo Template)
# شما می‌توانید هر بخش از این تنظیمات را به دلخواه خود ویرایش و شخصی‌سازی کنید.
# =====================================================================

# ۱. تنظیمات عمومی و سیستمی
GENERAL_SETTINGS = {
    "global-client-fingerprint": "chrome",
    "port": 7890,
    "socks-port": 7891,
    "redir-port": 7892,
    "mixed-port": 7893,
    "tproxy-port": 7894,
    "allow-lan": True,
    "tcp-concurrent": True,
    "enable-process": True,
    "find-process-mode": "always",
    "ipv6": True,
    "log-level": "info",
    "geo-auto-update": True,
    "geo-update-interval": 168,
    "secret": "",
    "bind-address": "*",
    "unified-delay": False,
    "disable-keep-alive": False,
    "keep-alive-idle": 30,
    "keep-alive-interval": 30,
}

# ۲. تنظیمات DNS پیشرفته میهومو
DNS_SETTINGS = {
    "enable": True,
    "ipv6": True,
    "respect-rules": False,
    "prefer-h3": True,
    "cache-algorithm": "arc",
    "use-system-hosts": True,
    "use-host": True,
    "listen": "0.0.0.0:53",
    "enhanced-mode": "fake-ip",
    "fake-ip-filter-mode": "blacklist",
    "fake-ip-range": "198.18.0.1/16",
    "fake-ip-filter": [
        "*.lan",
        "*.localdomain",
        "*.invalid",
        "*.localhost",
        "*.test",
        "*.local",
        "*.home.arpa",
        "time.*.com",
        "ntp.*.com",
        "*.ir",
    ],
    "default-nameserver": [
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "9.9.9.9",
    ],
    "nameserver": [
        "https://dns.google/dns-query",
        "https://cloudflare-dns.com/dns-query",
    ],
    "direct-nameserver": [
        "78.157.42.100",
        "78.157.42.101",
    ],
    "proxy-server-nameserver": [
        "1.1.1.1",
        "8.8.8.8",
    ]
}

# ۳. تنظیمات اسنیفر (شنود ترافیک برای تشخیص صحیح پروتکل‌ها)
SNIFFER_SETTINGS = {
    "enable": True,
    "force-dns-mapping": True,
    "parse-pure-ip": True,
    "override-destination": False,
    "sniff": {
        "HTTP": {"ports": [80, 8080, 8880, 2052, 2082, 2086, 2095]},
        "TLS": {"ports": [443, 8443, 2053, 2083, 2087, 2096]}
    }
}

# ۴. تنظیمات کارت شبکه مجازی TUN
TUN_SETTINGS = {
    "enable": True,
    "stack": "mixed",
    "auto-route": True,
    "auto-detect-interface": True,
    "auto-redir": True,
    "dns-hijack": [
        "any:53",
        "tcp://any:53"
    ]
}

# ۵. مخازن قوانین (Rule Providers)
RULE_PROVIDERS = {
    "local_ips": {
        "type": "http",
        "behavior": "ipcidr",
        "url": "https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/generated/local-ips.yaml",
        "interval": 86400,
        "path": "./ruleset/local_ips.yaml"
    },
    "category_ir": {
        "type": "http",
        "behavior": "domain",
        "url": "https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/generated/category-ir.yaml",
        "interval": 86400,
        "path": "./ruleset/category_ir.yaml"
    },
    "iran": {
        "type": "http",
        "behavior": "classical",
        "url": "https://raw.githubusercontent.com/10ium/clash_rules/main/iran.yaml",
        "interval": 86400,
        "path": "./ruleset/iran.yaml"
    }
}

# ۶. قوانین روتینگ و هدایت ترافیک (Routing Rules)
RULES = [
    "RULE-SET,local_ips,بدون فیلترشکن 🛡️",
    "PROCESS-NAME,Telegram.exe,تلگرام 💬",
    "PROCESS-NAME,org.telegram.messenger,تلگرام 💬",
    "RULE-SET,iran,سایتای ایرانی 🇮🇷",
    "RULE-SET,category_ir,سایتای ایرانی 🇮🇷",
    "GEOIP,ir,سایتای ایرانی 🇮🇷",
    "MATCH,نوع انتخاب پروکسی 🔀"
]

# ۷. گروه پروکسی‌ها (Proxy Groups)
def get_proxy_groups(proxy_names_list):
    """
    تولید لیست گروه‌های پروکسی به صورت پویا با استفاده از نام پروکسی‌های استخراج شده
    """
    return [
        {
            "name": "نوع انتخاب پروکسی 🔀",
            "type": "select",
            "proxies": [
                "خودکار (بهترین پینگ) 🤖",
                "دستی 🤏🏻",
                "بدون فیلترشکن 🛡️",
                "قطع اینترنت ⛔"
            ]
        },
        {
            "name": "دستی 🤏🏻",
            "type": "select",
            "proxies": proxy_names_list
        },
        {
            "name": "خودکار (بهترین پینگ) 🤖",
            "type": "url-test",
            "url": "https://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50,
            "lazy": True,
            "proxies": proxy_names_list
        },
        {
            "name": "سایتای ایرانی 🇮🇷",
            "type": "select",
            "proxies": [
                "بدون فیلترشکن 🛡️",
                "نوع انتخاب پروکسی 🔀",
                "خودکار (بهترین پینگ) 🤖",
                "دستی 🤏🏻",
                "اجازه ندادن 🚫"
            ]
        },
        {
            "name": "تلگرام 💬",
            "type": "select",
            "proxies": [
                "نوع انتخاب پروکسی 🔀",
                "بدون فیلترشکن 🛡️",
                "خودکار (بهترین پینگ) 🤖",
                "دستی 🤏🏻",
                "اجازه ندادن 🚫"
            ]
        },
        {
            "name": "بدون فیلترشکن 🛡️",
            "type": "select",
            "proxies": ["DIRECT"],
            "hidden": True
        },
        {
            "name": "قطع اینترنت ⛔",
            "type": "select",
            "proxies": ["REJECT"],
            "hidden": True
        },
        {
            "name": "اجازه ندادن 🚫",
            "type": "select",
            "proxies": ["REJECT"],
            "hidden": True
        }
    ]
