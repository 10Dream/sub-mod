import os
import re
import json
import base64
from urllib.parse import urlparse, parse_qs, unquote
import clash_template

# تنظیمات پیش‌فرض تبدیل به کلش میهومو با اعمال فیلتر و اولویت‌ها طبق کانفیگ سفارشی جدید شما
CLASH_CONFIG = {
    "limit_total": 800,             # حداکثر تعداد کل کانفیگ‌های خروجی
    "priorities": [                 # اولویت‌بندی از بالا به پایین به همراه محدودیت برای هر پروتکل
        {"type": "sudoku", "limit": 300},
        {"type": "masque", "limit": 300},
        {"type": "trusttunnel", "limit": 300},
        {"type": "openvpn", "limit": 300},
        {"type": "tailscale", "limit": 300},
        {"type": "snell", "limit": 300},
        {"type": "ssh", "limit": 300},
        {"type": "socks5", "limit": 300},
        {"type": "ssr", "limit": 300},
        {"type": "anytls", "limit": 300},
        {"type": "hy2", "limit": 300},
        {"type": "vless", "limit": 300},
        {"type": "ss", "limit": 300},
        {"type": "vmess", "limit": 300},
        {"type": "trojan", "limit": 300},
        {"type": "wireguard", "limit": 300},
        {"type": "tuic", "limit": 300},
        {"type": "hysteria", "limit": 300},
        {"type": "http", "limit": 300},
    ],
    "default_limit_for_others": 0  # محدودیت پیش‌فرض برای پروتکل‌هایی که در لیست بالا نیستند (0 یعنی حذف)
}

# الگوی ریجکس برای شناسایی کاراکترهای کنترل اسکی و کاراکترهای نامرئی مخدوش یونیکد [14]
CONTROL_CHARS_RE = re.compile(r'[\x00-\x1F\x7F-\x9F\u200B-\u200D\uFEFF\uFFFD]')

def remove_control_chars(s: str) -> str:
    """تصفیه و حذف کامل کاراکترهای نامعتبر کنترل و غیرقابل چاپ از رشته‌ها [14]"""
    if not isinstance(s, str):
        return s
    return CONTROL_CHARS_RE.sub('', s)

# الگوی شناسایی پروتکل‌ها جهت تفکیک خطوط به هم چسبیده
PROTOCOL_PATTERN = re.compile(
    r'(vless://|vmess://|trojan://|ss://|ssr://|hy2://|hysteria2://|hysteria://|wg://|wireguard://|tuic://|snell://|socks5://|socks://|http://|https://|ssh://|sudoku://|tailscale://|masque://|trusttunnel://|openvpn://)',
    re.IGNORECASE
)

# لیست سایفرهای معتبر و استاندارد Shadowsocks مورد تایید میهومو [11]
VALID_SS_CIPHERS = [
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "aes-128-ccm", "aes-192-ccm", "aes-256-ccm",
    "aes-128-gcm-siv", "aes-256-gcm-siv",
    "chacha20-ietf", "chacha20", "xchacha20",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "chacha8-ietf-poly1305", "xchacha8-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
    "lea-128-gcm", "lea-192-gcm", "lea-256-gcm",
    "rabbit128-poly1305", "aegis-128l", "aegis-256", "aez-384",
    "deoxys-ii-256-128", "rc4-md5", "none"
]

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

def is_valid_curve25519_key(s: str) -> bool:
    """
    اعتبارسنجی ریاضیاتی کلیدهای وایرگارد و فیلتر شکن های هم خانواده [12].
    کلیدها باید با موفقیت دکود بیس۶۴ شده و طول بایتی آن‌ها دقیقاً ۳۲ بایت باشد [12].
    """
    if not s or not isinstance(s, str):
        return False
    s_clean = s.strip().replace('-', '+').replace('_', '/')
    padding = len(s_clean) % 4
    if padding:
        s_clean += '=' * (4 - padding)
    try:
        decoded = base64.b64decode(s_clean)
        return len(decoded) == 32
    except Exception:
        return False

def is_valid_b64(s: str) -> bool:
    if not s or not isinstance(s, str):
        return False
    s_clean = s.strip().replace('-', '+').replace('_', '/')
    padding = len(s_clean) % 4
    if padding:
        s_clean += '=' * (4 - padding)
    try:
        base64.b64decode(s_clean)
        return True
    except Exception:
        return False

def safe_decode(s: str) -> str:
    try:
        return unquote(s)
    except Exception:
        return s

def get_display_type(t: str) -> str:
    t = t.lower()
    if t in ["hysteria2", "hy2"]: return "hy2"
    if t in ["hysteria", "hy"]: return "hy"
    if t in ["wireguard", "wg"]: return "wg"
    if t in ["socks5", "socks"]: return "socks"
    return t

def split_concatenated_links(line: str) -> list:
    """
    سیستم تفکیک فوق هوشمند لینک‌های متوالی و به‌هم‌چسبیده [9].
    هرگاه در حین خواندن رشته به الگوی یکی از پروتکل‌های اشتراک برسد،
    درک می‌کند کانفیگ قبلی خاتمه یافته و اتصال جدید آغاز شده است.
    """
    matches = list(PROTOCOL_PATTERN.finditer(line))
    if not matches:
        return [line]
        
    links = []
    for i in range(len(matches)):
        start = matches[i].start()
        end = matches[i+1].start() if i + 1 < len(matches) else len(line)
        link = line[start:end].strip()
        if link:
            links.append(link)
    return links

def get_connection_fingerprint(p: dict) -> str:
    """
    سیستم تولید اثر انگشت اتصالی فوق هوشمند (Smart Connection Fingerprint).
    این سیستم فیلدهای ظاهری نظیر 'name' یا 'icon' را به طور کامل نادیده می‌گیرد و
    پروکسی‌ها را بر اساس متغیرهای فنی و حیاتی متصل‌کننده (نظیر آی‌پی، پورت، کلیدها، مسیرها و الگوریتم‌ها)
    یکتا می‌سازد تا از تکرار کانفیگ‌های مشابه با نام‌های متفاوت پیشگیری کند.
    """
    exclude_keys = {"name", "icon"}
    core_properties = {k: v for k, v in p.items() if k not in exclude_keys}
    try:
        return json.dumps(core_properties, sort_keys=True)
    except Exception:
        return f"{p.get('type')}|{p.get('server')}|{p.get('port')}"

# --- بخش پارسرهای پروتکل‌های کلاسیک و نوین کلش میهومو ---

def parse_vless(link: str):
    try:
        url = urlparse(link.replace("vless://", "http://", 1))
        qs = parse_qs(url.query)
        security = qs.get("security", [""])[0]
        proxy = {
            "name": safe_decode(url.fragment or url.hostname),
            "type": "vless",
            "server": url.hostname,
            "port": int(url.port or 443),
            "uuid": url.username or "",
            "udp": True,
            "tls": security in ["tls", "reality"],
            "network": qs.get("type", ["tcp"])[0]
        }
        sni = qs.get("sni", [""])[0]
        if sni: proxy["servername"] = sni
        fp = qs.get("fp", [""])[0]
        if fp: proxy["client-fingerprint"] = fp
        alpn = qs.get("alpn", [""])[0]
        if alpn: proxy["alpn"] = alpn.split(",")
        
        # در ویلس میهومو فقط جریان xtls-rprx-vision استاندارد است
        flow = qs.get("flow", [""])[0]
        if flow == "xtls-rprx-vision":
            proxy["flow"] = flow

        if security == "reality":
            proxy["reality-opts"] = {"public-key": qs.get("pbk", [""])[0]}
            sid = qs.get("sid", [""])[0]
            if sid: proxy["reality-opts"]["short-id"] = sid

        if proxy["network"] == "ws":
            path = qs.get("path", [""])[0]
            host = qs.get("host", [""])[0]
            if path or host:
                proxy["ws-opts"] = {}
                if path: proxy["ws-opts"]["path"] = path
                if host: proxy["ws-opts"]["headers"] = {"Host": host}
        elif proxy["network"] == "grpc":
            service_name = qs.get("serviceName", [""])[0]
            if service_name:
                proxy["grpc-opts"] = {"grpc-service-name": service_name}
        return proxy
    except Exception:
        return None

def parse_vmess(link: str):
    try:
        decoded = safe_b64decode(link.replace("vmess://", "", 1))
        if not decoded: return None
        j = json.loads(decoded)
        
        # تضمین وجود سایفر خودکار و پورت معتبر برای جلوگیری از ارور unset fields: cipher در کلش
        return {
            "name": j.get("ps", j.get("add")),
            "type": "vmess",
            "server": j.get("add"),
            "port": int(j.get("port", 443)),
            "uuid": j.get("id", ""),
            "alterId": int(j.get("aid", 0)),
            "cipher": j.get("scy", "auto"),
            "udp": True
        }
    except Exception:
        return None

def parse_trojan(link: str):
    try:
        url = urlparse(link.replace("trojan://", "http://", 1))
        qs = parse_qs(url.query)
        proxy = {
            "name": safe_decode(url.fragment or url.hostname),
            "type": "trojan",
            "server": url.hostname,
            "port": int(url.port or 443),
            "password": safe_decode(url.username or ""),
            "udp": True,
            "tls": True,
            "network": qs.get("type", ["tcp"])[0]
        }
        sni = qs.get("sni", [""])[0]
        if sni: proxy["servername"] = sni
        if proxy["network"] == "ws":
            path = qs.get("path", [""])[0]
            host = qs.get("host", [""])[0]
            if path or host:
                proxy["ws-opts"] = {}
                if path: proxy["ws-opts"]["path"] = path
                if host: proxy["ws-opts"]["headers"] = {"Host": host}
        elif proxy["network"] == "grpc":
            service_name = qs.get("serviceName", [""])[0]
            if service_name:
                proxy["grpc-opts"] = {"grpc-service-name": service_name}
        return proxy
    except Exception:
        return None

def parse_anytls(link: str):
    try:
        url = urlparse(link.replace("anytls://", "http://", 1))
        qs = parse_qs(url.query)
        proxy = {
            "name": safe_decode(url.fragment or url.hostname),
            "type": "anytls",
            "server": url.hostname,
            "port": int(url.port or 443)
        }
        password = safe_decode(url.username or url.password or "")
        if password: proxy["password"] = password
        sni = qs.get("sni", [""])[0]
        if sni: proxy["servername"] = sni
        alpn = qs.get("alpn", [""])[0]
        if alpn: proxy["alpn"] = alpn.split(",")
        fp = qs.get("fp", qs.get("fingerprint", [""]))[0]
        if fp: proxy["client-fingerprint"] = fp
        return proxy
    except Exception:
        return None

def parse_ss(link: str):
    """پارس بومی پروتکل Shadowsocks به همراه تفکیک بهینه پلاگین‌ها طبق الگوی مستندات [8]"""
    try:
        raw = link.replace("ss://", "", 1)
        tag = ""
        if "#" in raw:
            raw, tag = raw.split("#", 1)
            
        query_str = ""
        if "?" in raw:
            raw, query_str = raw.split("?", 1)
            
        qs = parse_qs(query_str)
        
        server, port, method, password = "", 0, "", ""
        if "@" in raw:
            auth_part, server_part = raw.split("@", 1)
            decoded_auth = safe_b64decode(auth_part) or auth_part
            if ":" in decoded_auth:
                method, password = decoded_auth.split(":", 1)
            if ":" in server_part:
                server, port_str = server_part.split(":", 1)
                port = int(port_str)
        else:
            decoded_full = safe_b64decode(raw)
            if decoded_full and "@" in decoded_full:
                auth_part, server_part = decoded_full.split("@", 1)
                method, password = auth_part.split(":", 1)
                server, port_str = server_part.split(":", 1)
                port = int(port_str)
                
        if not server or not port: 
            return None
            
        proxy = {
            "name": safe_decode(tag or server),
            "type": "ss",
            "server": server,
            "port": port,
            "cipher": method,
            "password": password,
            "udp": True
        }
        
        # پارس پلاگین‌های شادوساکس در صورت وجود
        plugin_val = qs.get("plugin", [""])[0]
        if plugin_val:
            parts = plugin_val.split(";")
            plugin_name = parts[0].strip()
            proxy["plugin"] = plugin_name
            plugin_opts = {}
            for part in parts[1:]:
                if "=" in part:
                    pk, pv = part.split("=", 1)
                    plugin_opts[pk.strip()] = pv.strip()
            if plugin_opts:
                # حل باگ تبدیل نوع داده‌ی mux در v2ray-plugin به مقدار بولی معتبر [8]
                if "mux" in plugin_opts:
                    mux_v = str(plugin_opts["mux"]).lower().strip()
                    if mux_v in ["0", "false", "off"]:
                        plugin_opts["mux"] = False
                    else:
                        plugin_opts["mux"] = True
                proxy["plugin-opts"] = plugin_opts
                
        return proxy
    except Exception:
        return None

def parse_ssr(link: str):
    try:
        decoded = safe_b64decode(link.replace("ssr://", "", 1))
        if not decoded: return None
        parts = decoded.split("/")
        server, port, protocol, method, obfs, b64pass = parts[0].split(":")
        proxy = {
            "name": "SSR",
            "type": "ssr",
            "server": server,
            "port": int(port),
            "cipher": method,
            "password": safe_b64decode(b64pass) or b64pass,
            "protocol": protocol,
            "obfs": obfs
        }
        if len(parts) > 1:
            qs = parse_qs(parts[1].replace("?", "", 1))
            remarks = qs.get("remarks", [""])[0]
            if remarks: proxy["name"] = safe_decode(safe_b64decode(remarks) or remarks)
            obfsparam = qs.get("obfsparam", [""])[0]
            if obfsparam: proxy["obfs-param"] = safe_decode(safe_b64decode(obfsparam) or obfsparam)
            protoparam = qs.get("protoparam", [""])[0]
            if protoparam: proxy["protocol-param"] = safe_decode(safe_b64decode(protoparam) or protoparam)
        return proxy
    except Exception:
        return None

def parse_hysteria2(link: str):
    try:
        url = urlparse(link.replace("hysteria2://", "http://", 1).replace("hy2://", "http://", 1))
        qs = parse_qs(url.query)
        proxy = {
            "name": safe_decode(url.fragment or url.hostname),
            "type": "hysteria2",
            "server": url.hostname,
            "port": int(url.port or 443),
            "password": safe_decode(url.username or "")
        }
        sni = qs.get("sni", qs.get("peer", [""]))[0]
        if sni: proxy["sni"] = sni
        insecure = qs.get("insecure", [""])[0]
        if insecure in ["1", "true"]: proxy["skip-cert-verify"] = True
        obfs = qs.get("obfs", [""])[0]
        if obfs and obfs != "none":
            proxy["obfs"] = obfs
            obfs_pass = qs.get("obfs-password", [""])[0]
            if obfs_pass: proxy["obfs-password"] = obfs_pass
        return proxy
    except Exception:
        return None

def parse_hysteria(link: str):
    try:
        url = urlparse(link.replace("hysteria://", "http://", 1))
        qs = parse_qs(url.query)
        proxy = {
            "name": safe_decode(url.fragment or url.hostname),
            "type": "hysteria",
            "server": url.hostname,
            "port": int(url.port or 443),
            "protocol": qs.get("protocol", ["udp"])[0],
            "up": qs.get("up", ["50 Mbps"])[0],
            "down": qs.get("down", ["100 Mbps"])[0]
        }
        auth = qs.get("auth", qs.get("obfsParam", [""]))[0]
        if auth: proxy["auth_str"] = auth
        sni = qs.get("peer", qs.get("sni", [""]))[0]
        if sni: proxy["sni"] = sni
        insecure = qs.get("insecure", [""])[0]
        if insecure in ["1", "true"]: proxy["skip-cert-verify"] = True
        alpn = qs.get("alpn", [""])[0]
        if alpn: proxy["alpn"] = alpn.split(",")
        return proxy
    except Exception:
        return None

def parse_wireguard(link: str):
    """
    پارس فوق هوشمند پروتکل Wireguard بدون اتکا به urlparse بومی [9].
    این فرآیند از اختلال و خطای ناشی از وجود کاراکتر اسلش (/) در کلیدهای بیس۶۴ جلوگیری می‌کند.
    """
    try:
        raw = link.replace("wireguard://", "", 1).replace("wg://", "", 1)
        
        fragment = ""
        if "#" in raw:
            raw, fragment = raw.split("#", 1)
            fragment = safe_decode(fragment)
            
        query_str = ""
        if "?" in raw:
            raw, query_str = raw.split("?", 1)
            
        qs = parse_qs(query_str)
        
        # استخراج کلید خصوصی از بخش اصلی آدرس با ردیابی آخرین کاراکتر @
        if "@" in raw:
            userinfo, server_port = raw.rsplit("@", 1)
        else:
            userinfo = ""
            server_port = raw
            
        if ":" in server_port:
            server, port_str = server_port.rsplit(":", 1)
            port = int(port_str) if port_str.isdigit() else 51820
        else:
            server = server_port
            port = 51820
            
        priv_key = safe_decode(userinfo)
        pub_key = qs.get("public-key", qs.get("peer_publickey", qs.get("publicKey", qs.get("publickey", [""]))))[0]
        
        if not priv_key:
            priv_key = qs.get("privateKey", qs.get("private-key", qs.get("privatekey", [""])))[0]
            
        # حل کردن کامل باگ عدم تحویل کلیدهای عمومی و فیلدهای دیگر به علت فرآیند فشرده و ارکستراسیون URL-Decode
        pub_key = safe_decode(pub_key)
        priv_key = safe_decode(priv_key)
                    
        if not pub_key:
            pub_key = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="  # کلید فرضی پیش‌فرض وارپ
            
        raw_ip = qs.get("ip", qs.get("address", ["10.0.0.1"]))[0]
        # هماهنگ‌سازی IP کلاینت و حذف آدرس CIDR (پاک‌سازی اسلش ۳۲ یا ۱۲۸)
        clean_ip = safe_decode(raw_ip).split("/")[0].strip()
        
        proxy = {
            "name": safe_decode(fragment or server),
            "type": "wireguard",
            "server": server,
            "port": port,
            "ip": clean_ip,
            "private-key": priv_key,
            "public-key": pub_key,
            "allowed-ips": ["0.0.0.0/0"],
            "udp": True
        }
        
        # پارس کردن و پشتیبانی از آرایه اعداد Reserved
        reserved_val = safe_decode(qs.get("reserved", [""])[0])
        if reserved_val:
            if "," in reserved_val:
                proxy["reserved"] = [int(x) for x in reserved_val.split(",") if x.strip().isdigit()]
            elif is_valid_b64(reserved_val) and len(reserved_val) == 4:
                try:
                    proxy["reserved"] = list(base64.b64decode(reserved_val))
                except Exception:
                    pass
                    
        mtu = qs.get("mtu", [""])[0]
        if mtu and mtu.isdigit():
            proxy["mtu"] = int(mtu)
            
        return proxy
    except Exception:
        return None

def parse_tuic(link: str):
    try:
        url = urlparse(link.replace("tuic://", "http://", 1))
        qs = parse_qs(url.query)
        proxy = {
            "name": safe_decode(url.fragment or url.hostname),
            "type": "tuic",
            "server": url.hostname,
            "port": int(url.port or 443),
            "uuid": safe_decode(url.username or ""),
            "password": safe_decode(url.password or ""),
            "disable-sni": True,
            "reduce-rtt": True,
            "udp-relay-mode": "native"
        }
        sni = qs.get("sni", [""])[0]
        if sni: proxy["sni"] = sni
        alpn = qs.get("alpn", [""])[0]
        if alpn: proxy["alpn"] = alpn.split(",")
        congestion = qs.get("congestion_control", [""])[0]
        if congestion: proxy["congestion-controller"] = congestion
        udp_relay = qs.get("udp_relay_mode", [""])[0]
        if udp_relay: proxy["udp-relay-mode"] = udp_relay
        return proxy
    except Exception:
        return None

def parse_snell(link: str):
    try:
        url = urlparse(link.replace("snell://", "http://", 1))
        qs = parse_qs(url.query)
        proxy = {
            "name": safe_decode(url.fragment or url.hostname),
            "type": "snell",
            "server": url.hostname,
            "port": int(url.port or 443),
            "psk": safe_decode(url.username or qs.get("psk", [""])[0]),
            "version": qs.get("version", ["2"])[0]
        }
        obfs = qs.get("obfs", [""])[0]
        if obfs and obfs != "none":
            proxy["obfs-opts"] = {"mode": obfs}
            host = qs.get("obfs-host", [""])[0]
            if host: proxy["obfs-opts"]["host"] = host
        return proxy
    except Exception:
        return None

def parse_socks(link: str):
    try:
        url = urlparse(link.replace("socks5://", "http://", 1).replace("socks://", "http://", 1))
        return {
            "name": safe_decode(url.fragment or url.hostname),
            "type": "socks5",
            "server": url.hostname,
            "port": int(url.port or 1080),
            "username": safe_decode(url.username or ""),
            "password": safe_decode(url.password or "")
        }
    except Exception:
        return None

def parse_http(link: str):
    try:
        is_https = link.lower().startswith("https://")
        url = urlparse(link if is_https else link.replace("http://", "https://", 1))
        return {
            "name": safe_decode(url.fragment or url.hostname),
            "type": "http",
            "server": url.hostname,
            "port": int(url.port or (443 if is_https else 80)),
            "tls": is_https,
            "username": safe_decode(url.username or ""),
            "password": safe_decode(url.password or "")
        }
    except Exception:
        return None

def parse_ssh(link: str):
    try:
        url = urlparse(link.replace("ssh://", "http://", 1))
        return {
            "name": safe_decode(url.fragment or url.hostname),
            "type": "ssh",
            "server": url.hostname,
            "port": int(url.port or 22),
            "user": safe_decode(url.username or ""),
            "password": safe_decode(url.password or "")
        }
    except Exception:
        return None

# --- پارسرهای پروتکل‌های تازه اضافه شده ---

def parse_sudoku(link: str):
    try:
        url = urlparse(link.replace("sudoku://", "http://", 1))
        qs = parse_qs(url.query)
        disable_hm = qs.get("httpmask-disable", ["false"])[0].lower() in ["1", "true"]
        mode_hm = qs.get("httpmask-mode", ["legacy"])[0]
        tls_hm = qs.get("httpmask-tls", ["true"])[0].lower() in ["1", "true"]
        host_hm = qs.get("httpmask-host", qs.get("httpmask-mask-host", [""]))[0]
        path_hm = qs.get("httpmask-path-root", [""])[0]
        multiplex_hm = qs.get("httpmask-multiplex", ["off"])[0]
        
        proxy = {
            "name": safe_decode(url.fragment or url.hostname),
            "type": "sudoku",
            "server": url.hostname,
            "port": int(url.port or 443),
            "key": safe_decode(url.username or qs.get("key", [""])[0]),
            "aead-method": qs.get("aead-method", ["chacha20-poly1305"])[0],
            "padding-min": int(qs.get("padding-min", ["2"])[0]),
            "padding-max": int(qs.get("padding-max", ["7"])[0]),
            "table-type": qs.get("table-type", ["prefer_ascii"])[0],
            "enable-pure-downlink": qs.get("enable-pure-downlink", ["false"])[0].lower() in ["1", "true"],
            "httpmask": {
                "disable": disable_hm,
                "mode": mode_hm,
                "tls": tls_hm,
                "mask-host": host_hm,
                "path-root": path_hm,
                "multiplex": multiplex_hm
            }
        }
        custom_table = qs.get("custom-table", [""])[0]
        if custom_table: proxy["custom-table"] = custom_table
        custom_tables = qs.get("custom-tables", [])
        if custom_tables:
            proxy["custom-tables"] = custom_tables[0].split(",") if "," in custom_tables[0] else custom_tables
        return proxy
    except Exception:
        return None

def parse_tailscale(link: str):
    try:
        url = urlparse(link.replace("tailscale://", "http://", 1))
        qs = parse_qs(url.query)
        proxy = {
            "name": safe_decode(url.fragment or url.hostname),
            "type": "tailscale",
            "hostname": url.hostname or "mihomo",
            "auth-key": qs.get("auth-key", [""])[0],
            "control-url": qs.get("control-url", ["https://controlplane.tailscale.com"])[0],
            "state-dir": qs.get("state-dir", ["./tailscale"])[0],
            "ephemeral": qs.get("ephemeral", ["false"])[0].lower() in ["1", "true"],
            "udp": qs.get("udp", ["true"])[0].lower() in ["1", "true"],
            "accept-routes": qs.get("accept-routes", ["true"])[0].lower() in ["1", "true"],
            "exit-node-allow-lan-access": qs.get("exit-node-allow-lan-access", ["true"])[0].lower() in ["1", "true"]
        }
        exit_node = qs.get("exit-node", [""])[0]
        if exit_node: proxy["exit-node"] = exit_node
        dialer = qs.get("dialer-proxy", [""])[0]
        if dialer: proxy["dialer-proxy"] = dialer
        ifname = qs.get("interface-name", [""])[0]
        if ifname: proxy["interface-name"] = ifname
        mark = qs.get("routing-mark", [""])[0]
        if mark.isdigit(): proxy["routing-mark"] = int(mark)
        ipver = qs.get("ip-version", ["ipv4-prefer"])[0]
        if ipver: proxy["ip-version"] = ipver
        return proxy
    except Exception:
        return None

def parse_masque(link: str):
    try:
        url = urlparse(link.replace("masque://", "http://", 1))
        qs = parse_qs(url.query)
        proxy = {
            "name": safe_decode(url.fragment or url.hostname),
            "type": "masque",
            "server": url.hostname,
            "port": int(url.port or 443),
            "private-key": qs.get("private-key", [""])[0],
            "public-key": qs.get("public-key", [""])[0],
            "ip": qs.get("ip", ["172.16.0.2/32"])[0],
            "ipv6": qs.get("ipv6", ["fd00::2/128"])[0],
            "mtu": int(qs.get("mtu", ["1280"])[0]),
            "udp": qs.get("udp", ["true"])[0].lower() in ["1", "true"]
        }
        net = qs.get("network", ["quic"])[0]
        if net: proxy["network"] = net
        dialer = qs.get("dialer-proxy", [""])[0]
        if dialer: proxy["dialer-proxy"] = dialer
        dns_res = qs.get("remote-dns-resolve", ["false"])[0].lower() in ["1", "true"]
        if dns_res: proxy["remote-dns-resolve"] = dns_res
        dns_servs = qs.get("dns", [])
        if dns_servs:
            proxy["dns"] = dns_servs[0].split(",") if "," in dns_servs[0] else dns_servs
        cc = qs.get("congestion-controller", [""])[0]
        if cc: proxy["congestion-controller"] = cc
        bbr = qs.get("bbr-profile", [""])[0]
        if bbr: proxy["bbr-profile"] = bbr
        return proxy
    except Exception:
        return None

def parse_trusttunnel(link: str):
    try:
        url = urlparse(link.replace("trusttunnel://", "http://", 1))
        qs = parse_qs(url.query)
        proxy = {
            "name": safe_decode(url.fragment or url.hostname),
            "type": "trusttunnel",
            "server": url.hostname,
            "port": int(url.port or 443),
            "username": safe_decode(url.username or ""),
            "password": safe_decode(url.password or ""),
            "health-check": qs.get("health-check", ["true"])[0].lower() in ["1", "true"],
            "udp": qs.get("udp", ["true"])[0].lower() in ["1", "true"]
        }
        fp = qs.get("client-fingerprint", [""])[0]
        if fp: proxy["client-fingerprint"] = fp
        sni = qs.get("sni", [""])[0]
        if sni: proxy["sni"] = sni
        alpn = qs.get("alpn", [])
        if alpn:
            proxy["alpn"] = alpn[0].split(",") if "," in alpn[0] else alpn
        skip_cert = qs.get("skip-cert-verify", ["false"])[0].lower() in ["1", "true"]
        if skip_cert: proxy["skip-cert-verify"] = True
        quic_mode = qs.get("quic", ["false"])[0].lower() in ["1", "true"]
        if quic_mode: proxy["quic"] = True
        cc = qs.get("congestion-controller", [""])[0]
        if cc: proxy["congestion-controller"] = cc
        bbr = qs.get("bbr-profile", [""])[0]
        if bbr: proxy["bbr-profile"] = bbr
        max_conn = qs.get("max-connections", [""])[0]
        if max_conn.isdigit(): proxy["max-connections"] = int(max_conn)
        min_str = qs.get("min-streams", [""])[0]
        if min_str.isdigit(): proxy["min-streams"] = int(min_str)
        max_str = qs.get("max-streams", [""])[0]
        if max_str.isdigit(): proxy["max-streams"] = int(max_str)
        return proxy
    except Exception:
        return None

def parse_openvpn(link: str):
    try:
        url = urlparse(link.replace("openvpn://", "http://", 1))
        qs = parse_qs(url.query)
        proxy = {
            "name": safe_decode(url.fragment or url.hostname),
            "type": "openvpn",
            "server": url.hostname,
            "port": int(url.port or 1194),
            "proto": qs.get("proto", ["udp"])[0],
            "ca": safe_decode(qs.get("ca", [""])[0]),
            "udp": qs.get("udp", ["true"])[0].lower() in ["1", "true"]
        }
        user = safe_decode(url.username or qs.get("username", [""])[0])
        password = safe_decode(url.password or qs.get("password", [""])[0])
        if user: proxy["username"] = user
        if password: proxy["password"] = password
        cert = safe_decode(qs.get("cert", [""])[0])
        if cert: proxy["cert"] = cert
        key = safe_decode(qs.get("key", [""])[0])
        if key: proxy["key"] = key
        tc = safe_decode(qs.get("tls-crypt", [""])[0])
        if tc: proxy["tls-crypt"] = tc
        ping = qs.get("ping", [""])[0]
        if ping.isdigit(): proxy["ping"] = int(ping)
        ping_res = qs.get("ping-restart", [""])[0]
        if ping_res.isdigit(): proxy["ping-restart"] = int(ping_res)
        dev = qs.get("dev", [""])[0]
        if dev: proxy["dev"] = dev
        cipher = qs.get("cipher", [""])[0]
        if cipher: proxy["cipher"] = cipher
        auth = qs.get("auth", [""])[0]
        if auth: proxy["auth"] = auth
        comp = qs.get("comp-lzo", [""])[0]
        if comp: proxy["comp-lzo"] = comp
        mtu = qs.get("mtu", [""])[0]
        if mtu.isdigit(): proxy["mtu"] = int(mtu)
        dialer = qs.get("dialer-proxy", [""])[0]
        if dialer: proxy["dialer-proxy"] = dialer
        dns_res = qs.get("remote-dns-resolve", ["false"])[0].lower() in ["1", "true"]
        if dns_res: proxy["remote-dns-resolve"] = dns_res
        dns_servs = qs.get("dns", [])
        if dns_servs:
            proxy["dns"] = dns_servs[0].split(",") if "," in dns_servs[0] else dns_servs
        return proxy
    except Exception:
        return None

def parse_proxy(line: str):
    prefix = line[:15].lower()
    if prefix.startswith("vless://"): return parse_vless(line)
    if prefix.startswith("vmess://"): return parse_vmess(line)
    if prefix.startswith("trojan://"): return parse_trojan(line)
    if prefix.startswith("anytls://"): return parse_anytls(line)
    if prefix.startswith("ss://"): return parse_ss(line)
    if prefix.startswith("ssr://"): return parse_ssr(line)
    if prefix.startswith("hy2://") or prefix.startswith("hysteria2://"): return parse_hysteria2(line)
    if prefix.startswith("hysteria://"): return parse_hysteria(line)
    if prefix.startswith("wg://") or prefix.startswith("wireguard://"): return parse_wireguard(line)
    if prefix.startswith("tuic://"): return parse_tuic(line)
    if prefix.startswith("snell://"): return parse_snell(line)
    if prefix.startswith("socks://") or prefix.startswith("socks5://"): return parse_socks(line)
    if prefix.startswith("http://") or prefix.startswith("https://"): return parse_http(line)
    if prefix.startswith("ssh://"): return parse_ssh(line)
    if prefix.startswith("sudoku://"): return parse_sudoku(line)
    if prefix.startswith("tailscale://"): return parse_tailscale(line)
    if prefix.startswith("masque://"): return parse_masque(line)
    if prefix.startswith("trusttunnel://"): return parse_trusttunnel(line)
    if prefix.startswith("openvpn://"): return parse_openvpn(line)
    return None

# --- اعتبارسنجی اختصاصی کلیدهای شادوساکس ۲۰۲۲ ---

def validate_ss_2022_key(cipher: str, key_b64: str) -> bool:
    cipher = cipher.lower()
    parts = key_b64.split(":")
    for part in parts:
        part_clean = part.strip().replace('-', '+').replace('_', '/')
        padding = len(part_clean) % 4
        if padding:
            part_clean += '=' * (4 - padding)
        try:
            base64.b64decode(part_clean)
        except Exception:
            return False
            
    main_key = parts[0].strip().replace('-', '+').replace('_', '/')
    padding = len(main_key) % 4
    if padding:
        main_key += '=' * (4 - padding)
        
    try:
        decoded_bytes = base64.b64decode(main_key)
        decoded_len = len(decoded_bytes)
    except Exception:
        return False
        
    if "128" in cipher:
        expected_len = 16
    elif "256" in cipher or "chacha" in cipher:
        expected_len = 32
    else:
        expected_len = 32
        
    return decoded_len == expected_len

def validate_proxy(p) -> bool:
    """اعتبارسنجی انطباق پروکسی با استانداردهای میهومو به همراه بررسی نوع و ساختار متغیرها"""
    if not p or not isinstance(p, dict) or not p.get("type"):
        return False
    p_type = p["type"]
    if not p.get("name") or not isinstance(p["name"], str):
        return False
    if p_type == "tailscale":
        return bool(p.get("auth-key") or p.get("hostname"))
    server = p.get("server")
    if not server or not isinstance(server, str):
        return False
    port = p.get("port")
    try:
        port_num = int(port)
        if port_num < 1 or port_num > 65535:
            return False
        p["port"] = port_num
    except (ValueError, TypeError):
        return False
    server_lower = server.lower()
    blocked = ["127.0.0.1", "0.0.0.0", "localhost", "t.me", "github.com", "raw.githubusercontent.com", "google.com"]
    if any(b in server_lower for b in blocked):
        return False
        
    # تطبیق سخت‌گیرانه پارامترهای فنی هر پروتکل طبق الگوهای رسمی
    if p_type in ["vless", "vmess"]:
        if not p.get("uuid") or not isinstance(p["uuid"], str): return False
        if p_type == "vmess":
            # تضمین پر شدن فیلدهای اجباری vmess جهت پیشگیری از خطای unset fields: cipher در کلش
            if "cipher" not in p or not p["cipher"] or str(p["cipher"]).strip() == "":
                p["cipher"] = "auto"
            if "alterId" not in p:
                p["alterId"] = 0
    elif p_type in ["trojan", "hysteria2"]:
        if not p.get("password") or not isinstance(p["password"], str): return False
    elif p_type == "wireguard":
        if not p.get("private-key") or not isinstance(p["private-key"], str) or \
           not p.get("public-key") or not isinstance(p["public-key"], str) or \
           not p.get("ip") or not isinstance(p["ip"], str):
            return False
        # بررسی صحت فرمت بیس۶۴ کلیدها جهت تضمین سلامت وایرگارد
        if not is_valid_curve25519_key(p["private-key"]) or not is_valid_curve25519_key(p["public-key"]):
            return False
    elif p_type == "hysteria":
        if not p.get("auth_str") or not isinstance(p["auth_str"], str): return False
    elif p_type == "tuic":
        if not p.get("uuid") or not isinstance(p["uuid"], str) or not p.get("password") or not isinstance(p["password"], str): return False
    elif p_type == "ss":
        cipher = p.get("cipher")
        password = p.get("password")
        if not cipher or not isinstance(cipher, str) or not password or not isinstance(password, str):
            return False
        if cipher.lower() not in VALID_SS_CIPHERS:
            return False
        if cipher.lower().startswith("2022-"):
            if not validate_ss_2022_key(cipher, password):
                return False
    elif p_type == "ssr":
        if not p.get("cipher") or not isinstance(p["cipher"], str) or \
           not p.get("password") or not isinstance(p["password"], str) or \
           not p.get("protocol") or not isinstance(p["protocol"], str) or \
           not p.get("obfs") or not isinstance(p["obfs"], str):
            return False
        if p["cipher"].lower() not in VALID_SS_CIPHERS:
            return False
    elif p_type == "sudoku":
        if not p.get("key") or not isinstance(p["key"], str): return False
    elif p_type == "masque":
        if not p.get("private-key") or not isinstance(p["private-key"], str) or not p.get("public-key") or not isinstance(p["public-key"], str): return False
    elif p_type == "trusttunnel":
        if not p.get("username") or not isinstance(p["username"], str) or not p.get("password") or not isinstance(p["password"], str): return False
    elif p_type == "openvpn":
        if not p.get("ca") or not isinstance(p["ca"], str): return False
        
    # اعتبارسنجی بسیار سخت‌گیرانه کلید عمومی و شناسه کوتاه در پروتکل REALITY [12]
    if p.get("reality-opts"):
        pbk = p["reality-opts"].get("public-key")
        if not pbk or not isinstance(pbk, str):
            return False
            
        pbk_clean = pbk.strip().replace('-', '+').replace('_', '/')
        padding = len(pbk_clean) % 4
        if padding:
            pbk_clean += '=' * (4 - padding)
            
        try:
            # کلید عمومی Curve25519 حتماً باید دقیقاً ۳۲ بایت دکود شود [12]
            decoded_pbk = base64.b64decode(pbk_clean)
            if len(decoded_pbk) != 32:
                return False
        except Exception:
            return False
            
        sid = p["reality-opts"].get("short-id")
        if sid:
            # شناسه کوتاه حتماً باید یک رشته هگزادسیمال زوج و حداکثر ۱۶ کاراکتر باشد
            if not isinstance(sid, str) or not re.match(r'^[0-9a-fA-F]+$', sid) or len(sid) % 2 != 0 or len(sid) > 16:
                return False
                
    return True

# --- بخش فیلتر، مرتب‌سازی و حفظ نام اصلی به همراه رفع تکراری‌ها بر اساس اثر انگشت فنی ---

def process_and_filter_proxies(proxies_list):
    valid_proxies = []
    unique_keys = set()
    
    for p in proxies_list:
        if not validate_proxy(p):
            continue
        ukey = get_connection_fingerprint(p)
        if ukey in unique_keys:
            continue
        unique_keys.add(ukey)
        valid_proxies.append(p)
        
    grouped_proxies = {}
    for p in valid_proxies:
        dtype = get_display_type(p["type"])
        if dtype not in grouped_proxies:
            grouped_proxies[dtype] = []
        grouped_proxies[dtype].append(p)
        
    final_proxies = []
    for prio in CLASH_CONFIG["priorities"]:
        ptype = prio["type"]
        plimit = prio.get("limit")
        
        if ptype in grouped_proxies:
            if plimit is None or plimit == -1 or plimit in ["unlimited", "∞"]:
                selected = grouped_proxies[ptype]
            else:
                selected = grouped_proxies[ptype][:int(plimit)]
            final_proxies.extend(selected)
            del grouped_proxies[ptype]
            
    default_limit = CLASH_CONFIG.get("default_limit_for_others", 0)
    if default_limit is None or default_limit == -1 or default_limit in ["unlimited", "∞"]:
        for ptype, items in grouped_proxies.items():
            final_proxies.extend(items)
    elif default_limit > 0:
        for ptype, items in grouped_proxies.items():
            selected = items[:int(default_limit)]
            final_proxies.extend(selected)
            
    final_proxies = final_proxies[:CLASH_CONFIG["limit_total"]]
    
    # تصحیح نام‌گذاری پروکسی‌ها: حفظ نام اصلی + شمارنده افزایشی
    seen_names = {}
    for p in final_proxies:
        original_name = p.get("name", "").strip()
        if not original_name:
            original_name = get_display_type(p["type"]).upper()
            
        name = original_name
        if name in seen_names:
            seen_names[original_name] += 1
            name = f"{original_name}-{seen_names[original_name]}"
        else:
            seen_names[name] = 0
            
        p["name"] = name
        
    return final_proxies

# --- مبدل پایتونی بومی برای ساختن YAML (با امنیت کوتیشن‌گذاری ۱۰۰ درصدی) ---

def dump_yaml(data, indent=0) -> str:
    lines = []
    spacing = " " * indent
    if isinstance(data, dict):
        for k, v in data.items():
            if v is None:
                continue
            if isinstance(v, (dict, list)):
                lines.append(f"{spacing}{k}:")
                lines.append(dump_yaml(v, indent + 2))
            else:
                if isinstance(v, bool):
                    val_str = "true" if v else "false"
                elif isinstance(v, (int, float)):
                    val_str = str(v)
                elif isinstance(v, str):
                    # پاک‌سازی کامل مقادیر رشته‌ای از کاراکترهای کنترل در زمان تولید خروجی YAML [14]
                    v_clean = remove_control_chars(v)
                    if "\n" in v_clean:
                        val_str = "|\n" + "\n".join(" " * (indent + 2) + line for line in v_clean.splitlines())
                    else:
                        escaped_v = v_clean.replace('\\', '\\\\').replace('"', '\\"')
                        val_str = f'"{escaped_v}"'
                else:
                    val_str = f'"{str(v)}"'
                lines.append(f"{spacing}{k}: {val_str}")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                sub_yaml = dump_yaml(item, indent + 2).lstrip()
                lines.append(f"{spacing}- {sub_yaml}")
            else:
                if isinstance(item, bool):
                    val_str = "true" if item else "false"
                elif isinstance(item, (int, float)):
                    val_str = str(item)
                elif isinstance(item, str):
                    # تصفیه مقادیر لیست‌ها از کاراکترهای مخفی و غیرقابل چاپ [14]
                    item_clean = remove_control_chars(item)
                    escaped_item = item_clean.replace('\\', '\\\\').replace('"', '\\"')
                    val_str = f'"{escaped_item}"'
                else:
                    val_str = f'"{str(item)}"'
                lines.append(f"{spacing}- {val_str}")
    return "\n".join(lines)

def convert_single_file(src_txt_path, dest_yaml_path):
    if not os.path.exists(src_txt_path):
        return False
        
    raw_proxies = []
    with open(src_txt_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
                
            # تصفیه کامل هر خط دیتای خام ورودی از وجود کاراکترهای مخدوش و کنترلی مخفی [14]
            line_sanitized = remove_control_chars(line)
            
            split_links = split_concatenated_links(line_sanitized)
            for single_link in split_links:
                p = parse_proxy(single_link)
                if p:
                    raw_proxies.append(p)
                
    if not raw_proxies:
        return False
        
    processed = process_and_filter_proxies(raw_proxies)
    if not processed:
        return False
        
    proxy_names = [p["name"] for p in processed]
    
    final_dict = {}
    final_dict.update(clash_template.GENERAL_SETTINGS)
    final_dict["dns"] = clash_template.DNS_SETTINGS
    final_dict["sniffer"] = clash_template.SNIFFER_SETTINGS
    final_dict["tun"] = clash_template.TUN_SETTINGS
    final_dict["rule-providers"] = clash_template.RULE_PROVIDERS
    final_dict["proxies"] = processed
    final_dict["proxy-groups"] = clash_template.get_proxy_groups(proxy_names)
    final_dict["rules"] = clash_template.RULES
    
    final_yaml_content = dump_yaml(final_dict)
    
    os.makedirs(os.path.dirname(dest_yaml_path), exist_ok=True)
    with open(dest_yaml_path, 'w', encoding='utf-8') as f:
        f.write(final_yaml_content)
    return True

def run_converter_for_all(sources, normal_dir, clash_dir):
    os.makedirs(clash_dir, exist_ok=True)
    print(f"[تبدیل کلش] شروع تبدیل چندگانه منابع در مسیر: {clash_dir}")
    
    for src in sources:
        name = src['name']
        src_path = os.path.join(normal_dir, name)
        base_name = os.path.splitext(name)[0]
        dest_path = os.path.join(clash_dir, f"{base_name}.yaml")
        
        if os.path.exists(src_path):
            success = convert_single_file(src_path, dest_path)
            if success:
                print(f"[موفقیت] کانفیگ کلش اختصاصی منبع {name} در مسیر '{dest_path}' ایجاد شد.")
            else:
                print(f"[اسکیپ] تبدیل منبع {name} به دلیل عدم وجود کانفیگ‌های معتبر اسکیپ شد.")
                
    mix_txt_path = os.path.join(normal_dir, "mix.txt")
    mix_yaml_path = os.path.join(clash_dir, "mix.yaml")
    if os.path.exists(mix_txt_path):
        success = convert_single_file(mix_txt_path, mix_yaml_path)
        if success:
            print(f"[موفقیت] کانفیگ کلش میکس نهایی (mix.yaml) با موفقیت تولید شد.")
