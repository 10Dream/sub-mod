import os
import re
import json
import base64
from urllib.parse import urlparse, parse_qs, unquote
import clash_template

# تنظیمات پیش‌فرض تبدیل به کلش میهومو با اعمال فیلتر و اولویت‌ها
CLASH_CONFIG = {
    "limit_total": 600,             # حداکثر تعداد کل کانفیگ‌های خروجی
    "priorities": [                 # اولویت‌بندی از بالا به پایین به همراه محدودیت برای هر پروتکل
        {"type": "anytls", "limit": 200},
        {"type": "hy2", "limit": 200},      # hysteria2 به اختصار hy2
        {"type": "vless", "limit": 200},
        {"type": "ss", "limit": 100},       # shadowsocks
        {"type": "sudoku", "limit": 100},   # پروتکل سودوکو جدید
        {"type": "masque", "limit": 50},    # پروتکل مسک جدید
        {"type": "trusttunnel", "limit": 50},# پروتکل تراست تانل جدید
        {"type": "openvpn", "limit": 30},   # پروتکل اوپن وی پی ان جدید
        {"type": "tailscale", "limit": 20}, # پروتکل تیل اسکیل جدید
        {"type": "vmess", "limit": 50},
        {"type": "trojan", "limit": 50},
        {"type": "wireguard", "limit": 50},
        {"type": "tuic", "limit": 50},
        {"type": "hysteria", "limit": 50},
        {"type": "socks5", "limit": 20},
        {"type": "http", "limit": 20},
        {"type": "snell", "limit": 20},
        {"type": "ssh", "limit": 10},
    ],
    "default_limit_for_others": 0
}

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
        flow = qs.get("flow", [""])[0]
        if flow: proxy["flow"] = flow

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
    try:
        raw = link.replace("ss://", "", 1)
        tag = ""
        if "#" in raw:
            raw, tag = raw.split("#", 1)
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
        if not server or not port: return None
        return {
            "name": safe_decode(tag or server),
            "type": "ss",
            "server": server,
            "port": port,
            "cipher": method,
            "password": password,
            "udp": True
        }
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
    try:
        url = urlparse(link.replace("wireguard://", "http://", 1).replace("wg://", "http://", 1))
        qs = parse_qs(url.query)
        raw_ip = qs.get("ip", qs.get("address", ["10.0.0.1"]))[0]
        pub_key = qs.get("public-key", qs.get("peer_public_key", qs.get("publicKey", qs.get("publickey", [""]))))[0]
        priv_key = url.username or qs.get("privateKey", qs.get("private-key", qs.get("privatekey", [""])))[0]
        if not pub_key:
            pub_key = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
        proxy = {
            "name": safe_decode(url.fragment or url.hostname),
            "type": "wireguard",
            "server": url.hostname,
            "port": int(url.port or 51820),
            "ip": raw_ip.split(",")[0].strip(),
            "private-key": safe_decode(priv_key),
            "public-key": safe_decode(pub_key),
            "allowed-ips": ["0.0.0.0/0"],
            "udp": True
        }
        reserved = qs.get("reserved", [""])[0]
        if reserved: proxy["reserved"] = [int(x) for x in reserved.split(",") if x.strip().isdigit()]
        mtu = qs.get("mtu", [""])[0]
        if mtu and mtu.isdigit(): proxy["mtu"] = int(mtu)
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
    """پارس پروتکل جدید Sudoku"""
    try:
        url = urlparse(link.replace("sudoku://", "http://", 1))
        qs = parse_qs(url.query)
        
        # استخراج داده‌های فرعی httpmask
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
    """پارس پروتکل Tailscale"""
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
    """پارس پروتکل MASQUE"""
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
    """پارس پروتکل TrustTunnel"""
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
        
        # مقادیر بهینه‌سازی جریان
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
    """پارس پروتکل OpenVPN"""
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
    """شناسایی پروتکل و ارجاع به پارسر مناسب"""
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

def validate_proxy(p) -> bool:
    """اعتبارسنجی انطباق پروکسی با استانداردهای میهومو (Mihomo)"""
    if not p or not p.get("type"):
        return False
        
    p_type = p["type"]
    
    # برای Tailscale نیازی به فیلدهای پورت شبکه یا سرور عمومی استاندارد نیست
    if p_type == "tailscale":
        return bool(p.get("auth-key") or p.get("hostname"))
        
    if not p.get("server") or not p.get("port"):
        return False
    
    server = p["server"].lower()
    blocked = ["127.0.0.1", "0.0.0.0", "localhost", "t.me", "github.com", "raw.githubusercontent.com", "google.com"]
    if any(b in server for b in blocked):
        return False
        
    if p_type in ["vless", "vmess"] and not p.get("uuid"): return False
    if p_type in ["trojan", "hysteria2"] and not p.get("password"): return False
    if p_type == "wireguard" and not p.get("private-key"): return False
    if p_type == "hysteria" and not p.get("auth_str"): return False
    if p_type == "tuic" and (not p.get("uuid") or not p.get("password")): return False
    if p_type == "ss" and (not p.get("cipher") or not p.get("password")): return False
    if p_type == "sudoku" and not p.get("key"): return False
    if p_type == "masque" and (not p.get("private-key") or not p.get("public-key")): return False
    if p_type == "trusttunnel" and (not p.get("username") or not p.get("password")): return False
    if p_type == "openvpn" and not p.get("ca"): return False
    return True

# --- بخش فیلتر، مرتب‌سازی و اولویت‌بندی ---

def process_and_filter_proxies(proxies_list):
    valid_proxies = []
    unique_keys = set()
    
    for p in proxies_list:
        if not validate_proxy(p):
            continue
            
        # تولید کلید یکتا برای حذف تکراری‌ها
        ukey = f"{p['type']}|{p['server']}|{p.get('port', 0)}"
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
    
    # مرتب‌سازی طبق ترتیب اولویت‌ها
    for prio in CLASH_CONFIG["priorities"]:
        ptype = prio["type"]
        plimit = prio["limit"]
        
        if ptype in grouped_proxies:
            selected = grouped_proxies[ptype][:plimit]
            final_proxies.extend(selected)
            del grouped_proxies[ptype]
            
    if CLASH_CONFIG["default_limit_for_others"] > 0:
        for ptype, items in grouped_proxies.items():
            selected = items[:CLASH_CONFIG["default_limit_for_others"]]
            final_proxies.extend(selected)
            
    final_proxies = final_proxies[:CLASH_CONFIG["limit_total"]]
    
    # نام‌گذاری ترتیبی
    type_counters = {}
    for p in final_proxies:
        dtype = get_display_type(p["type"])
        type_counters[dtype] = type_counters.get(dtype, 0) + 1
        p["name"] = f"{dtype.upper()} {type_counters[dtype]}"
        
    return final_proxies

# --- مبدل پایتونی بومی برای ساختن YAML بدون وابستگی PyYAML ---

def dump_yaml(data, indent=0) -> str:
    """تولید خروجی استاندارد YAML از داده‌های دیکشنری پایتون به صورت بومی و بدون وابستگی خارجی"""
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
                elif isinstance(v, str):
                    if "\n" in v:
                        # برای رشته‌های چند خطی مثل گواهینامه‌های اوپن‌وی‌پی‌ان
                        val_str = "|\n" + "\n".join(" " * (indent + 2) + line for line in v.splitlines())
                    elif any(char in v for char in [":", "{", "}", "[", "]", ",", "*", "&", "?", "|", "-", "<", ">", "=", "!"]):
                        val_str = f'"{v}"'
                    else:
                        val_str = v
                else:
                    val_str = str(v)
                lines.append(f"{spacing}{k}: {val_str}")
                
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                sub_yaml = dump_yaml(item, indent + 2).lstrip()
                lines.append(f"{spacing}- {sub_yaml}")
            else:
                if isinstance(item, bool):
                    val_str = "true" if item else "false"
                elif isinstance(item, str):
                    if any(char in item for char in [":", "{", "}", "[", "]", ",", "*", "&", "?", "|", "-", "<", ">", "=", "!"]):
                        val_str = f'"{item}"'
                    else:
                        val_str = item
                else:
                    val_str = str(item)
                lines.append(f"{spacing}- {val_str}")
                
    return "\n".join(lines)

def run_converter(mix_txt_path, normal_dir):
    """تابع هماهنگ‌کننده تبدیل پروکسی به میهومو"""
    if not os.path.exists(mix_txt_path):
        print(f"[تبدیل کلش] فایل منبع تجمیعی در مسیر '{mix_txt_path}' یافت نشد.")
        return
        
    print("[تبدیل کلش] شروع واکشی و تبدیل پروکسی‌ها...")
    
    raw_proxies = []
    with open(mix_txt_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            p = parse_proxy(line)
            if p:
                raw_proxies.append(p)
                
    print(f"[تبدیل کلش] تعداد پروکسی‌های خام پارس شده: {len(raw_proxies)}")
    
    processed = process_and_filter_proxies(raw_proxies)
    print(f"[تبدیل کلش] {len(processed)} پروکسی طبق اولویت‌ها فیلتر و آماده شدند.")
    
    if not processed:
        print("[تبدیل کلش] پروکسی معتبری پیدا نشد. ذخیره فایل اسکیپ شد.")
        return
        
    # واکشی اسامی پروکسی‌ها جهت اختصاص به گروه‌ها
    proxy_names = [p["name"] for p in processed]
    
    # مونتاژ نهایی سند پیکربندی کلش به صورت ماژولار با ایمپورت تنظیمات از تمپلت
    final_dict = {}
    final_dict.update(clash_template.GENERAL_SETTINGS)
    final_dict["dns"] = clash_template.DNS_SETTINGS
    final_dict["sniffer"] = clash_template.SNIFFER_SETTINGS
    final_dict["tun"] = clash_template.TUN_SETTINGS
    final_dict["rule-providers"] = clash_template.RULE_PROVIDERS
    final_dict["proxies"] = processed
    final_dict["proxy-groups"] = clash_template.get_proxy_groups(proxy_names)
    final_dict["rules"] = clash_template.RULES
    
    # خروجی گرفتن به صورت بومی با سرعت بالا
    final_yaml_content = dump_yaml(final_dict)
    
    # ذخیره‌سازی فایل در پوشه معمولی (بیس۶۴ به درخواست کاربر حذف شد)
    os.makedirs(normal_dir, exist_ok=True)
    clash_normal_path = os.path.join(normal_dir, "clash.yaml")
    with open(clash_normal_path, 'w', encoding='utf-8') as f:
        f.write(final_yaml_content)
        
    print(f"[تبدیل کلش] فایل خروجی کلش میهومو با موفقیت در '{clash_normal_path}' ذخیره شد.")
