#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pyright: reportMissingImports=false, reportMissingModuleSource=false
"""CubScanner Free v12.0 — Static Logo, Smart Scroll, Improved UI."""

import sys
MIN_PY = (3, 8)
if sys.version_info < MIN_PY:
    print(f"CubScanner Free needs Python {MIN_PY[0]}.{MIN_PY[1]}+.")
    try:
        import webbrowser
        webbrowser.open("https://www.python.org/downloads/")
    except Exception: pass
    sys.exit(1)

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading, socket, os, time, json, re, struct, hashlib, subprocess
import webbrowser, csv as _csv
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from scapy.all import (ARP, Ether, srp, sniff, IP, TCP, UDP, ICMP,
                            DNS, DNSQR, DHCP, BOOTP, Raw)
    SCAPY_OK = True
except ImportError:
    try:
        print("Installing scapy...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy"])
        from scapy.all import (ARP, Ether, srp, sniff, IP, TCP, UDP, ICMP,
                                DNS, DNSQR, DHCP, BOOTP, Raw)
        SCAPY_OK = True
    except Exception as e:
        print(f"scapy install failed: {e}")
        SCAPY_OK = False

try:
    from npcap_setup import is_npcap_installed, run_npcap_setup_if_needed
except ImportError:
    def is_npcap_installed(): return True
    def run_npcap_setup_if_needed(parent): return True

# ==================== CONSTANTS ====================
KOFI_URL = "https://ko-fi.com/pietro67"
APP_VERSION = "12.0"
ONLINE_THRESHOLD = 90
ROW_HEIGHT = 26
UNKNOWN_AFTER = 300
PING_WORKERS = 100
PORT_WORKERS = 20
PING_TIMEOUT = 0.7
BOOT_MAX_SECONDS = 60
BOOT_SKIP_AFTER = 12
NET_CHECK_INTERVAL = 10

APP_DIR = os.path.join(os.path.expanduser("~"), ".cubscanner")
os.makedirs(APP_DIR, exist_ok=True)

# ==================== THEME (Improved) ====================
BG, BG2, BG3 = "#121214", "#18181b", "#27272a"
BORDER, FG, FG_MUT = "#3f3f46", "#e4e4e7", "#a1a1aa"
ACCENT = "#3b82f6"
DANGER = "#ef4444"
WARN = "#f59e0b"
YEL = "#eab308"
OK = "#22c55e"
LINK = "#60a5fa"
PORT_LINK = "#a855f7"
LOCAL_COLOR = "#3b82f6"
OFFLINE_COLOR = "#71717a"
BANNER_BG = "#1e293b"
BANNER_FG = "#93c5fd"
CLOCK_COLOR = "#60a5fa"
TITLE_BG = "#121214"
HOUSE_CHAR = "⌂"

def now_hms():
    return datetime.now().strftime("%H:%M:%S")

# ==================== FORMATTING ====================
def fmt_duration(seconds):
    seconds = max(0, int(seconds))
    d, r = divmod(seconds, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    parts = []
    if d: parts.append(f"{d}d")
    if h or d: parts.append(f"{h}h")
    if m or h or d: parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)

def fmt_ago(seconds):
    if seconds < 60: return f"{int(seconds)}s ago"
    if seconds < 3600: return f"{int(seconds/60)}m ago"
    if seconds < 86400: return f"{int(seconds/3600)}h ago"
    return f"{int(seconds/86400)}d ago"

def fmt_bytes(b):
    b = float(b)
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024: return f"{b:.0f} {u}"
        b /= 1024
    return f"{b:.1f} PB"

def text_is_at_bottom(widget):
    try: return widget.yview()[1] >= 0.995
    except Exception: return True

def text_scroll_to_bottom(widget):
    try: widget.see("end")
    except Exception: pass

# ==================== OUI ====================
OUI_DB = {
    "00:50:56": "VMware", "00:0C:29": "VMware", "08:00:27": "VirtualBox",
    "AC:DE:48": "Apple", "F0:18:98": "Apple", "00:1B:63": "Apple",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "3C:5A:B4": "Google", "F4:F5:D8": "Google",
    "FC:A1:83": "Amazon", "44:65:0D": "Amazon",
    "00:17:88": "Philips Hue", "24:DA:9B": "Samsung", "8C:77:12": "Samsung",
    "B0:BE:76": "TP-Link", "A4:2B:B0": "TP-Link", "98:DA:C4": "TP-Link",
    "00:1D:7E": "Cisco", "C0:56:27": "Belkin", "00:11:32": "Synology",
    "DC:0B:34": "Xiaomi", "EC:FA:BC": "Espressif", "24:0A:C4": "Espressif",
}

def vendor_from_mac(mac):
    if not mac: return "Unknown"
    return OUI_DB.get(mac.upper().replace("-", ":")[:8], "Unknown")

def dhcp_options_to_os(options):
    if not options: return None
    opts = set(options)
    if {44, 46, 47}.issubset(opts): return "Windows"
    if 121 in opts and 95 in opts: return "macOS"
    if 252 in opts and 95 in opts and 121 not in opts: return "iOS"
    if {26, 28}.issubset(opts): return "Android"
    if {1, 3, 6, 15, 119, 252}.issubset(opts) and len(opts) <= 12: return "Linux"
    if len(opts) <= 4: return "Embedded"
    return None

# ==================== PARSERS ====================
def extract_mdns_info(pkt):
    info = {"hostnames": set(), "services": set()}
    try:
        if DNS not in pkt: return info
        if pkt[DNS].qr != 1: return info
        raw = bytes(pkt[DNS])
        for token in re.findall(rb"[a-zA-Z0-9_\-\.]{4,}", raw):
            s = token.decode("ascii", errors="ignore").rstrip(".")
            if not s or "." not in s: continue
            if "_tcp.local" in s or "_udp.local" in s:
                info["services"].add(s)
            elif s.endswith(".local") and not s.startswith("_"):
                info["hostnames"].add(s[:-6])
    except Exception: pass
    return info

def extract_ssdp_info(pkt):
    info = {"server": None, "device_type": None, "location": None, "usn": None}
    try:
        if UDP not in pkt or Raw not in pkt: return info
        if pkt[UDP].sport != 1900 and pkt[UDP].dport != 1900: return info
        payload = bytes(pkt[Raw].load).decode("utf-8", errors="ignore")
        for line in payload.split("\r\n"):
            if ":" not in line: continue
            k, _, v = line.partition(":")
            k = k.strip().lower(); v = v.strip()
            if k == "server": info["server"] = v[:120]
            elif k == "st": info["device_type"] = v[:120]
            elif k == "location": info["location"] = v[:200]
            elif k == "usn": info["usn"] = v[:120]
    except Exception: pass
    return info

# ==================== JA3 ====================
def parse_tls_ja3(data):
    try:
        if len(data) < 6 or data[0] != 0x16 or data[5] != 0x01: return None
        pos = 5
        if data[pos] != 1: return None
        pos += 4
        ver = struct.unpack(">H", data[pos:pos + 2])[0]; pos += 2
        pos += 32
        sid_len = data[pos]; pos += 1 + sid_len
        cs_len = struct.unpack(">H", data[pos:pos + 2])[0]; pos += 2
        cs_end = pos + cs_len
        ciphers = []
        while pos + 2 <= cs_end:
            ciphers.append(struct.unpack(">H", data[pos:pos + 2])[0]); pos += 2
        cm_len = data[pos]; pos += 1 + cm_len
        exts, curves, ecpf, sni = [], [], [], None
        if pos + 2 <= len(data):
            el = struct.unpack(">H", data[pos:pos + 2])[0]; pos += 2
            end = min(pos + el, len(data))
            while pos + 4 <= end:
                et = struct.unpack(">H", data[pos:pos + 2])[0]
                elen = struct.unpack(">H", data[pos + 2:pos + 4])[0]; pos += 4
                exts.append(et)
                if et == 0x0000 and pos + 5 <= len(data):
                    try:
                        nl = struct.unpack(">H", data[pos + 3:pos + 5])[0]
                        sni = data[pos + 5:pos + 5 + nl].decode("ascii", errors="ignore")
                    except Exception: pass
                elif et == 0x000a and pos + 2 <= len(data):
                    try:
                        gl = struct.unpack(">H", data[pos:pos + 2])[0]; gp = pos + 2
                        while gp + 2 <= pos + 2 + gl:
                            curves.append(struct.unpack(">H", data[gp:gp + 2])[0]); gp += 2
                    except Exception: pass
                elif et == 0x000b and pos < len(data):
                    try:
                        fl = data[pos]; ecpf = list(data[pos + 1:pos + 1 + fl])
                    except Exception: pass
                pos += elen
        s = (f"{ver}," + "-".join(map(str, ciphers)) + "," +
             "-".join(map(str, exts)) + "," + "-".join(map(str, curves)) +
             "," + "-".join(map(str, ecpf)))
        return s, hashlib.md5(s.encode()).hexdigest(), sni
    except Exception: return None

JA3_DB = {
    "cd08e31494f9531f560d64c695473da9": "Chrome",
    "579ccef312d18482fc42e2b822ca2430": "Firefox",
    "e7d705a3286e19ea42f587b344ee6865": "Tor Browser",
    "3b5074b1b5d032e5620f69f9f700ff0e": "Python requests",
    "51c64c77e60f3980eea90869b68c58a8": "curl",
}
SUSPICIOUS_JA3 = ("Cobalt", "Metasploit", "Empire", "Sliver", "Tor")

# ==================== WIKI ====================
WIKI_BASE = "https://en.wikipedia.org/wiki/"
WIKI_LINKS = {
    "FTP": "File_Transfer_Protocol", "SSH": "Secure_Shell", "Telnet": "Telnet",
    "SMTP": "Simple_Mail_Transfer_Protocol", "DNS": "Domain_Name_System",
    "HTTP": "Hypertext_Transfer_Protocol", "HTTPS": "HTTPS",
    "RPC": "Remote_procedure_call", "NetBIOS": "NetBIOS", "SMB": "Server_Message_Block",
    "MSSQL": "Microsoft_SQL_Server", "MySQL": "MySQL", "RDP": "Remote_Desktop_Protocol",
    "PostgreSQL": "PostgreSQL", "VNC": "VNC", "Redis": "Redis",
    "JA3": "JA3_fingerprint", "SNI": "Server_Name_Indication",
    "TLS": "Transport_Layer_Security", "ARP": "Address_Resolution_Protocol",
}

def wiki_url(term):
    s = WIKI_LINKS.get(term)
    return WIKI_BASE + s if s else None

# ==================== PORTS ====================
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9200: "Elasticsearch", 27017: "MongoDB", 62078: "iPhone Sync",
    9100: "Print", 631: "IPP", 515: "LPD", 554: "RTSP",
    8008: "Chromecast", 8009: "Chromecast", 5000: "Synology", 5001: "Synology-HTTPS",
    1900: "SSDP", 5353: "mDNS", 3074: "Xbox Live", 8554: "RTSP-alt", 1935: "RTMP",
}
RISKY_PORTS = {23: 15, 445: 15, 3389: 15, 21: 8, 3306: 8, 5432: 8, 5900: 8}

def scan_port(ip, port, timeout=0.6):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, port)) != 0: return None
        banner = ""
        s.settimeout(2.0)
        try:
            if port in (80, 8080, 8000, 8888):
                s.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port in (443, 8443, 22, 21, 25, 110, 143, 3306):
                pass
            else:
                s.send(b"\r\n")
            data = b""
            for _ in range(3):
                try:
                    c = s.recv(512)
                    if not c: break
                    data += c
                    if len(data) > 2048: break
                except socket.timeout: break
            banner = re.sub(r"\s+", " ", data.decode(errors="ignore").strip())[:400]
        except Exception: pass
        finally:
            try: s.close()
            except Exception: pass
        return (port, banner)
    except Exception: return None

def scan_ports(ip, workers=30):
    found = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(scan_port, ip, p): p for p in COMMON_PORTS}
        for f in as_completed(futs):
            r = f.result()
            if r: found.append(r)
    return sorted(found)

def ping_one(ip, timeout=1):
    try:
        if sys.platform == "win32":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
            r = subprocess.run(cmd, capture_output=True, timeout=timeout + 1.5,
                               creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]
            r = subprocess.run(cmd, capture_output=True, timeout=timeout + 1.5)
        return r.returncode == 0
    except Exception: return False

def extract_service_info(port, banner):
    info = {"port": port, "service": COMMON_PORTS.get(port, "?"),
            "product": None, "version": None, "raw": banner[:200] if banner else ""}
    if not banner: return info
    for pat, prod in [
        (r"OpenSSH[_/\s]([\d.p]+)", "OpenSSH"), (r"Apache/([\d.]+)", "Apache"),
        (r"nginx/([\d.]+)", "nginx"), (r"Microsoft-IIS/([\d.]+)", "IIS"),
        (r"vsFTPd ([\d.]+)", "vsFTPd"), (r"ProFTPD ([\d.]+)", "ProFTPD"),
        (r"MySQL[^\d]*([\d.]+)", "MySQL"), (r"MariaDB", "MariaDB"),
        (r"PostgreSQL", "PostgreSQL"), (r"Redis", "Redis"),
        (r"MongoDB", "MongoDB"), (r"OpenSSL/([\d.a-z]+)", "OpenSSL"),
        (r"Samba ([\d.]+)", "Samba"),
    ]:
        m = re.search(pat, banner, re.IGNORECASE)
        if m:
            info["product"] = prod
            if m.groups(): info["version"] = m.group(1)
            break
    if port == 445 and not info["product"]: info["product"] = "SMB"
    if port == 53 and not info["product"]: info["product"] = "DNS"
    return info

# ==================== DEVICE ====================
class Device:
    def __init__(self, ip, mac=""):
        self.ip = ip; self.mac = mac
        self.vendor = vendor_from_mac(mac) if mac else "Unknown"
        self.hostname = ""
        self.ports = []; self.service_info = []
        self.domains = set(); self.ja3s = set()
        self.flows = defaultdict(lambda: {"out": 0, "in": 0, "pkts": 0, "last": 0})
        self.first_seen = time.time(); self.last_seen = time.time()
        self.last_reconnect = time.time()
        self.discovery_method = "arp"
        self.is_online = True
        self.session_start = time.time()
        self.sessions = []
        self.dhcp_os_guess = None
        self.port_traffic = defaultdict(lambda: {"pkts": 0, "bytes": 0, "samples": []})
        self.device_traffic = {"pkts": 0, "bytes": 0, "samples": []}
        self.mdns_services = set()
        self.ssdp_server = None
        self.ssdp_types = set()
        self._cached_type = None
        self._cached_type_key = None

    def touch(self):
        now = time.time()
        gap = now - self.last_seen
        was_offline = (not self.is_online) or (gap > ONLINE_THRESHOLD)
        if gap > ONLINE_THRESHOLD:
            if self.session_start is not None:
                self.sessions.append({"start": self.session_start, "end": self.last_seen})
            self.session_start = now
        if was_offline: self.last_reconnect = now
        self.last_seen = now
        self.is_online = True

    def current_status(self):
        if self.is_online and (time.time() - self.last_seen) < ONLINE_THRESHOLD:
            return ("Online", OK)
        return (fmt_ago(time.time() - self.last_seen), OFFLINE_COLOR)

    def get_type(self):
        key = (tuple(sorted(p for p, _ in self.ports)),
               tuple(sorted(self.domains))[:20],
               self.mac, self.hostname,
               self.dhcp_os_guess,
               tuple(sorted(self.mdns_services)),
               tuple(sorted(self.ssdp_types)))
        if self._cached_type_key == key and self._cached_type:
            return self._cached_type
        result = infer_device_type(self)
        self._cached_type = result; self._cached_type_key = key
        return result

    def risk_score(self):
        s = 0
        for d in self.domains:
            if re.search(r"\.(tk|ml|ga|cf|gq)$", d): s += 15
        for h in self.ja3s:
            t = JA3_DB.get(h, "")
            if any(x in t for x in SUSPICIOUS_JA3): s += 30
        for p, _ in self.ports: s += RISKY_PORTS.get(p, 0)
        return min(s, 100)

    def risk_label(self):
        s = self.risk_score()
        if s >= 60: return ("CRITICAL", DANGER)
        if s >= 30: return ("HIGH", WARN)
        if s >= 10: return ("MEDIUM", YEL)
        return ("OK", OK)

    def total_time_online(self):
        total = 0
        for s in self.sessions: total += s["end"] - s["start"]
        if self.is_online: total += time.time() - self.session_start
        return total

# ==================== TYPE INFERENCE ====================
DEVICE_TYPES = ["Computer", "Phone", "Tablet", "Camera", "TV",
                "Router", "Printer", "IoT", "Speaker", "Console", "NAS"]

def infer_device_type(d):
    scores = {t: 0.0 for t in DEVICE_TYPES}
    evidence = []
    def bump(add, reason):
        for t, w in add.items():
            if t in scores: scores[t] += w
        if reason: evidence.append(reason)

    if getattr(d, "ssdp_types", None):
        for t in d.ssdp_types:
            tl = t.lower()
            if "mediarenderer" in tl or "mediaserver" in tl: bump({"TV": 5, "Speaker": 3}, f"UPnP")
            if "printer" in tl: bump({"Printer": 8}, f"UPnP")
            if "internetgateway" in tl: bump({"Router": 8}, f"UPnP")
            if "camera" in tl: bump({"Camera": 8}, f"UPnP")
    if getattr(d, "mdns_services", None):
        s = " ".join(d.mdns_services).lower()
        if "_airplay" in s or "_raop" in s: bump({"Speaker": 4, "TV": 3}, "mDNS")
        if "_googlecast" in s: bump({"TV": 4, "Speaker": 3}, "mDNS")
        if "_ipp" in s or "_printer" in s: bump({"Printer": 8}, "mDNS")

    v = d.vendor or ""
    if v == "Apple": bump({"Phone": 3, "Tablet": 3, "Computer": 2, "TV": 1}, "Apple OUI")
    elif v == "Espressif": bump({"IoT": 5, "Camera": 3, "Speaker": 2}, "Espressif")
    elif v == "Raspberry Pi": bump({"Computer": 3, "IoT": 2, "Camera": 1}, "Raspberry Pi")
    elif v in ("TP-Link", "Cisco", "Belkin"): bump({"Router": 4, "Computer": 1}, f"{v} OUI")
    elif v == "Synology": bump({"NAS": 10}, "Synology")
    elif v == "Samsung": bump({"Phone": 2, "Tablet": 2, "TV": 2}, "Samsung")
    elif v == "Xiaomi": bump({"Phone": 3, "Tablet": 2, "Camera": 2, "IoT": 2}, "Xiaomi")
    elif v == "Google": bump({"Phone": 2, "Tablet": 2, "TV": 2, "Speaker": 2}, "Google")
    elif v == "Philips Hue": bump({"IoT": 10}, "Philips Hue")
    elif v == "Amazon": bump({"Speaker": 3, "Tablet": 2, "TV": 1}, "Amazon")

    if d.dhcp_os_guess:
        evidence.append(f"DHCP: {d.dhcp_os_guess}")
        if d.dhcp_os_guess == "Windows": bump({"Computer": 6}, None)
        elif d.dhcp_os_guess == "macOS": bump({"Computer": 6}, None)
        elif d.dhcp_os_guess == "iOS": bump({"Phone": 4, "Tablet": 4, "TV": 1}, None)
        elif d.dhcp_os_guess == "Android": bump({"Phone": 3, "Tablet": 3, "TV": 2, "IoT": 1}, None)
        elif d.dhcp_os_guess == "Linux": bump({"Computer": 2, "IoT": 2, "Camera": 2, "Router": 2, "NAS": 2}, None)

    h = (d.hostname or "").lower()
    if h:
        for kws, types in [
            (["iphone", "galaxy", "pixel", "redmi", "oneplus", "-phone"], {"Phone": 8}),
            (["ipad", "tablet", "tab-"], {"Tablet": 8}),
            (["laptop", "desktop", "macbook", "thinkpad", "imac", "workstation"], {"Computer": 8}),
            (["ipcam", "hikvision", "dahua", "reolink", "camera"], {"Camera": 8}),
            (["bravia", "webos", "roku", "chromecast", "firetv", "appletv", "smarttv"], {"TV": 8}),
            (["router", "gateway", "archer", "fritz", "openwrt"], {"Router": 8}),
            (["printer", "epson", "canon", "brother"], {"Printer": 8}),
            (["echo", "alexa", "homepod", "speaker", "sonos"], {"Speaker": 8}),
            (["ps4", "ps5", "xbox", "nintendo"], {"Console": 8}),
            (["nas", "synology", "qnap", "diskstation"], {"NAS": 8}),
        ]:
            if any(k in h for k in kws):
                bump(types, f"Hostname"); break

    ports = {p for p, _ in d.ports}
    if 62078 in ports: bump({"Phone": 7, "Tablet": 6}, "Port 62078")
    if 9100 in ports or 631 in ports or 515 in ports: bump({"Printer": 8}, "Printing")
    if 554 in ports: bump({"Camera": 6, "TV": 2}, "Port 554")
    if 3389 in ports: bump({"Computer": 5}, "RDP")
    if 5000 in ports and 5001 in ports: bump({"NAS": 7}, "Synology")
    if 8008 in ports or 8009 in ports: bump({"TV": 4, "Speaker": 2}, "Chromecast")
    if 445 in ports and 139 in ports: bump({"Computer": 3, "NAS": 3}, "SMB")

    total_pos = sum(max(0, s) for s in scores.values())
    age = time.time() - d.first_seen
    if total_pos == 0:
        return ("Unknown", 0.0, evidence) if age > UNKNOWN_AFTER else ("Detecting...", 0.0, evidence)
    best = max(scores, key=scores.get)
    best_score = scores[best]
    ss = sorted(scores.values(), reverse=True)
    second = ss[1] if len(ss) > 1 else 0
    dominance = (best_score - second) / best_score if best_score > 0 else 0
    if best_score >= 8 and dominance >= 0.4: conf = 0.9
    elif best_score >= 5 and dominance >= 0.2: conf = 0.75
    elif best_score >= 3: conf = 0.5
    elif best_score >= 2: conf = 0.3
    else:
        return ("Unknown", 0.0, evidence) if age > UNKNOWN_AFTER else ("Detecting...", 0.0, evidence)
    return (best, conf, evidence)

# ==================== SNIFFER ====================
class Sniffer(threading.Thread):
    def __init__(self, app):
        super().__init__(daemon=True)
        self.app = app; self.stop_flag = False
    def run(self):
        if not SCAPY_OK: return
        try:
            sniff(prn=self.handle, store=False, stop_filter=lambda p: self.stop_flag)
        except Exception as e:
            self.app.set_status(f"Sniffer: {e}")
    def _record_device_traffic(self, dev, direction, src, dst, size, payload):
        try:
            dt = dev.device_traffic
            dt["pkts"] += 1; dt["bytes"] += size
            if payload and len(dt["samples"]) < 250:
                dt["samples"].append({
                    "ts": time.time(), "dir": direction,
                    "from": src, "to": dst, "len": len(payload),
                    "preview": payload.decode(errors="replace")[:200]})
        except Exception: pass
    def handle(self, pkt):
        try:
            if IP not in pkt: return
            src, dst = pkt[IP].src, pkt[IP].dst
            size = len(pkt)
            if (src not in self.app.devices
                    and not src.startswith("224.")
                    and not src.startswith("239.")
                    and src != "0.0.0.0"):
                mac = ""
                try:
                    if pkt.haslayer("Ether"): mac = pkt["Ether"].src
                except Exception: pass
                d = Device(src, mac); d.discovery_method = "passive"
                self.app.devices[src] = d

            dev = self.app.devices.get(src)
            payload = None
            try:
                if Raw in pkt:
                    raw = bytes(pkt[Raw].load)
                    if raw: payload = raw[:200]
            except Exception: pass

            if dev:
                dev.touch()
                dev.flows[dst]["out"] += size
                dev.flows[dst]["pkts"] += 1
                dev.flows[dst]["last"] = time.time()
                self._record_device_traffic(dev, "out", src, dst, size, payload)

            dst_dev = self.app.devices.get(dst)
            if dst_dev and dst_dev is not dev:
                self._record_device_traffic(dst_dev, "in", src, dst, size, payload)

            if DNS in pkt and pkt[DNS].qr == 0:
                try:
                    q = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                    if dev: dev.domains.add(q)
                except Exception: pass

            if TCP in pkt and pkt[TCP].dport == 443 and Raw in pkt:
                parsed = parse_tls_ja3(bytes(pkt[Raw].load))
                if parsed and dev:
                    _, h, sni = parsed
                    if sni: dev.domains.add(sni)
                    dev.ja3s.add(h)

            if TCP in pkt:
                try:
                    sport, dport = pkt[TCP].sport, pkt[TCP].dport
                    if dev:
                        st = dev.port_traffic[sport]
                        st["pkts"] += 1; st["bytes"] += size
                        if payload and len(st["samples"]) < 120:
                            st["samples"].append({
                                "ts": time.time(), "dir": "out",
                                "from": f"{src}:{sport}", "to": f"{dst}:{dport}",
                                "len": len(payload),
                                "preview": payload.decode(errors="replace")[:200]})
                    if dst_dev and dst_dev is not dev:
                        st = dst_dev.port_traffic[dport]
                        st["pkts"] += 1; st["bytes"] += size
                        if payload and len(st["samples"]) < 120:
                            st["samples"].append({
                                "ts": time.time(), "dir": "in",
                                "from": f"{src}:{sport}", "to": f"{dst}:{dport}",
                                "len": len(payload),
                                "preview": payload.decode(errors="replace")[:200]})
                except Exception: pass

            self.app.pkt_count += 1
        except Exception: pass

# ==================== FRAMED WINDOW ====================
class FramedWindow(tk.Toplevel):
    def __init__(self, master, title="", width=880, height=700, resizable=True):
        super().__init__(master)
        self.title(title); self.geometry(f"{width}x{height}")
        self.configure(bg=BG)
        try: self.resizable(resizable, resizable)
        except Exception: pass
    def _on_close(self):
        try: self._alive = False
        except Exception: pass
        try: self.destroy()
        except Exception: pass

# ==================== PORT INSPECTOR ====================
class PortInspector(FramedWindow):
    def __init__(self, master, app, ip, port):
        super().__init__(master, title=f"Traffic · {ip}:{port}", width=880, height=700)
        self.app = app; self.ip = ip; self.port = port
        self._alive = True
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        header = tk.Frame(self, bg=BG2, height=44)
        header.pack(fill="x"); header.pack_propagate(False)
        tk.Label(header, text=f"📡  {COMMON_PORTS.get(port, '?')}", bg=BG2, fg=FG,
                 font=("Segoe UI", 11, "bold")).pack(side="left", padx=14)
        self.header_clock = tk.Label(header, text="● LIVE  " + now_hms(),
                                       bg=BG2, fg=OK, font=("Consolas", 9, "bold"))
        self.header_clock.pack(side="right", padx=14)
        body = tk.Frame(self, bg=BG); body.pack(fill="both", expand=True, padx=12, pady=10)
        self.text = tk.Text(body, bg=BG2, fg=FG, relief="flat",
                    font=("Consolas", 10), wrap="word", padx=14, pady=12,
                    borderwidth=0, highlightthickness=0)
        sb = tk.Scrollbar(body, command=self.text.yview, bg=BG2, troughcolor=BG2,
                          relief="flat", borderwidth=0)
        self.text.configure(yscrollcommand=sb.set); sb.pack(side="right", fill="y")
        self.text.pack(fill="both", expand=True)
        self.text.tag_configure("h", foreground=ACCENT, font=("Segoe UI", 12, "bold"),
                                spacing1=8, spacing3=6)
        self.text.tag_configure("muted", foreground=FG_MUT)
        bar = tk.Frame(self, bg=BG2, height=34)
        bar.pack(fill="x", side="bottom"); bar.pack_propagate(False)
        self.status_lbl = tk.Label(bar, text="Starting...", bg=BG2, fg=FG_MUT,
                                    font=("Segoe UI", 8))
        self.status_lbl.pack(side="left", padx=14)
        self.status_clock = tk.Label(bar, text=now_hms(), bg=BG2, fg=CLOCK_COLOR,
                                       font=("Consolas", 9, "bold"))
        self.status_clock.pack(side="right", padx=14)
        self.after(1000, self._tick)
    def _tick(self):
        if not self._alive: return
        try:
            self.header_clock.config(text="● LIVE  " + now_hms())
            self.status_clock.config(text=now_hms())
            self._refresh()
        except Exception as e: print("inspector:", e)
        if self._alive:
            try: self.after(1000, self._tick)
            except Exception: pass
    def _refresh(self):
        try:
            if not self.winfo_exists(): return
        except Exception: return
        d = self.app.devices.get(self.ip)
        was_bottom = text_is_at_bottom(self.text)
        prev = None
        if not was_bottom:
            try: prev = self.text.yview()
            except: pass
        self.text.configure(state="normal"); self.text.delete("1.0", "end")
        self.text.insert("end", f"Port {self.port}\n", "h")
        if not d:
            self.text.insert("end", "Device no longer tracked.\n")
            self.text.configure(state="disabled")
            if was_bottom: text_scroll_to_bottom(self.text)
            return
        stats = d.port_traffic.get(self.port)
        if not stats or stats["pkts"] == 0:
            self.text.insert("end", "\nNo traffic on this port yet.\n", "muted")
        else:
            self.text.insert("end", f"Packets: {stats['pkts']}   Bytes: {fmt_bytes(stats['bytes'])}\n\n")
            for s in stats["samples"][-100:]:
                ts = datetime.fromtimestamp(s["ts"]).strftime("%H:%M:%S")
                arrow = "←" if s["dir"] == "in" else "→"
                self.text.insert("end",
                    f"[{ts}] {arrow}  {s['from']}  →  {s['to']}  ({s['len']}B)\n", "muted")
        self.text.configure(state="disabled")
        if was_bottom: text_scroll_to_bottom(self.text)
        elif prev:
            try: self.text.yview_moveto(prev[0])
            except: pass

# ==================== DEVICE TRAFFIC ====================
class DeviceTrafficWindow(FramedWindow):
    def __init__(self, master, app, ip):
        super().__init__(master, title=f"Device traffic · {ip}", width=900, height=720)
        self.app = app; self.ip = ip
        self._alive = True
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        header = tk.Frame(self, bg=BG2, height=44)
        header.pack(fill="x"); header.pack_propagate(False)
        self.hdr_lbl = tk.Label(header, text=f"📊  {ip}", bg=BG2, fg=FG,
                                  font=("Segoe UI", 11, "bold"))
        self.hdr_lbl.pack(side="left", padx=14)
        self.header_clock = tk.Label(header, text="● LIVE  " + now_hms(),
                                       bg=BG2, fg=OK, font=("Consolas", 9, "bold"))
        self.header_clock.pack(side="right", padx=14)
        body = tk.Frame(self, bg=BG); body.pack(fill="both", expand=True, padx=12, pady=10)
        self.text = tk.Text(body, bg=BG2, fg=FG, relief="flat",
                    font=("Consolas", 10), wrap="word", padx=14, pady=12,
                    borderwidth=0, highlightthickness=0)
        sb = tk.Scrollbar(body, command=self.text.yview, bg=BG2, troughcolor=BG2,
                          relief="flat", borderwidth=0)
        self.text.configure(yscrollcommand=sb.set); sb.pack(side="right", fill="y")
        self.text.pack(fill="both", expand=True)
        self.text.tag_configure("h", foreground=ACCENT, font=("Segoe UI", 12, "bold"),
                                spacing1=8, spacing3=6)
        self.text.tag_configure("muted", foreground=FG_MUT)
        bar = tk.Frame(self, bg=BG2, height=34)
        bar.pack(fill="x", side="bottom"); bar.pack_propagate(False)
        self.status_lbl = tk.Label(bar, text="Starting...", bg=BG2, fg=FG_MUT,
                                    font=("Segoe UI", 8))
        self.status_lbl.pack(side="left", padx=14)
        self.status_clock = tk.Label(bar, text=now_hms(), bg=BG2, fg=CLOCK_COLOR,
                                       font=("Consolas", 9, "bold"))
        self.status_clock.pack(side="right", padx=14)
        self.after(1000, self._tick)
    def _tick(self):
        if not self._alive: return
        try:
            self.header_clock.config(text="● LIVE  " + now_hms())
            self.status_clock.config(text=now_hms())
            self._refresh()
        except Exception as e: print("device traffic:", e)
        if self._alive:
            try: self.after(1000, self._tick)
            except: pass
    def _refresh(self):
        try:
            if not self.winfo_exists(): return
        except: return
        d = self.app.devices.get(self.ip)
        was_bottom = text_is_at_bottom(self.text)
        prev = None
        if not was_bottom:
            try: prev = self.text.yview()
            except: pass
        self.text.configure(state="normal"); self.text.delete("1.0", "end")
        if not d:
            self.text.insert("end", "Device no longer tracked.\n")
            self.text.configure(state="disabled")
            if was_bottom: text_scroll_to_bottom(self.text)
            return
        dt = d.device_traffic
        self.text.insert("end", f"Device: {self.ip}\n", "h")
        self.text.insert("end", f"Type: {d.get_type()[0]}   Status: {d.current_status()[0]}\n")
        self.text.insert("end", "─" * 70 + "\n\n", "muted")
        self.text.insert("end", f"Total: {dt['pkts']} pkts / {fmt_bytes(dt['bytes'])}\n\n")
        samples = list(dt["samples"])
        if not samples:
            self.text.insert("end", "No packets captured yet.\n", "muted")
        else:
            for s in samples[-120:]:
                ts = datetime.fromtimestamp(s["ts"]).strftime("%H:%M:%S")
                arrow = "←" if s["dir"] == "in" else "→"
                self.text.insert("end",
                    f"[{ts}] {arrow}  {s['from']}  →  {s['to']}  ({s['len']}B)\n", "muted")
        self.text.configure(state="disabled")
        if was_bottom: text_scroll_to_bottom(self.text)
        elif prev:
            try: self.text.yview_moveto(prev[0])
            except: pass

# ==================== HELP ====================
def show_help(parent, title, text):
    win = FramedWindow(parent, title=title, width=620, height=460)
    win.transient(parent)
    t = tk.Text(win, bg=BG2, fg=FG, relief="flat", font=("Segoe UI", 10),
                wrap="word", padx=18, pady=16, borderwidth=0, highlightthickness=0)
    t.pack(fill="both", expand=True, padx=10, pady=10)
    t.tag_configure("h", foreground=ACCENT, font=("Segoe UI", 12, "bold"))
    t.insert("end", title + "\n\n", "h"); t.insert("end", text)
    t.configure(state="disabled")

# ==================== MAIN APP ====================
class CubScanner(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CubScanner Free")
        self.geometry("1360x880"); self.configure(bg=BG)
        
        # Set taskbar icon (Windows)
        if sys.platform == "win32" and os.path.exists("icon.ico"):
            try: self.iconbitmap("icon.ico")
            except: pass

        self.devices = {}
        self.selected_ip = None
        self.sniffer = None
        self.pkt_count = 0
        self.local_ip = None
        self.current_network = None
        self.current_gateway_mac = None
        self._port_windows = {}
        self._last_order = []
        self._boot_done = False
        self._boot_cancel = None
        self._boot_start = 0
        
        self._setup_style()
        self._build_ui()
        
        self.after(50, self._apply_fullscreen)
        self.after(150, self._boot_sequence)

    # ---------- WINDOW CONTROLS ----------
    def _apply_fullscreen(self):
        try: self.attributes("-fullscreen", True)
        except: pass
        self.lift(); self.focus_force()
        self.after(100, self._update_window_controls)

    def _update_window_controls(self):
        try: is_fs = bool(self.attributes("-fullscreen"))
        except: is_fs = False
        try:
            if is_fs: self.win_ctrl_frame.pack(side="left", padx=(10, 0))
            else: self.win_ctrl_frame.pack_forget()
        except: pass

    def _win_minimize(self):
        try:
            self.attributes("-fullscreen", False)
            self.after(100, self._update_window_controls)
            self.iconify()
        except: pass

    def _win_maximize(self):
        try:
            self.attributes("-fullscreen", not bool(self.attributes("-fullscreen")))
            self.after(100, self._update_window_controls)
        except: pass

    def _win_close(self):
        try:
            if self.sniffer and not self.sniffer.stop_flag: self.sniffer.stop_flag = True
        except: pass
        try: self.destroy()
        except: pass

    # ---------- BOOT ----------
    def _boot_sequence(self):
        self._boot_cancel = threading.Event()
        self._boot_start = time.time()
        self._boot_done = False

        def force():
            if self._boot_done: return
            self._boot_cancel.set()
            self._boot_status("Boot timeout — entering", 100, "")
            time.sleep(0.5)
            self.after(0, self._reveal_main)

        def watchdog():
            start = time.time()
            while not self._boot_done and not self._boot_cancel.is_set():
                if time.time() - start > BOOT_MAX_SECONDS: force(); return
                time.sleep(0.5)

        def ticker():
            while not self._boot_done and not self._boot_cancel.is_set():
                try:
                    e = time.time() - self._boot_start
                    self.after(0, lambda v=e: self.boot_elapsed.config(text=f"{v:.0f}s"))
                except: pass
                time.sleep(1)

        def run():
            try:
                self._boot_status("Checking Npcap...", 10, "")
                time.sleep(0.15)
                if sys.platform == "win32" and not is_npcap_installed():
                    self._boot_status("Npcap missing", 15, "")
                    done = threading.Event(); result = {"ok": False}
                    def ask():
                        try: result["ok"] = run_npcap_setup_if_needed(self)
                        except: pass
                        done.set()
                    self.after(0, ask); done.wait(timeout=600)
                    if not result["ok"]:
                        time.sleep(1)
                if self._boot_cancel.is_set(): return
                
                self._boot_status("Checking deps...", 20, "")
                time.sleep(0.1)
                if not SCAPY_OK:
                    self._boot_status("Scapy missing", 100, "")
                    time.sleep(1)
                    self.after(0, lambda: (messagebox.showerror("CubScanner", "Scapy required."), self.destroy()))
                    return
                
                self._boot_status("Detecting network...", 40, "")
                net = self._guess_network()
                self.local_ip = self._guess_local_ip()
                self.current_network = net
                time.sleep(0.1)
                self.after(0, lambda n=net: self.net_lbl.config(text=n))
                if self._boot_cancel.is_set(): return
                
                self._boot_status("Reading gateway...", 50, "")
                self.current_gateway_mac = self._get_gateway_mac()
                if self._boot_cancel.is_set(): return
                
                self._boot_status("ARP discovery...", 60, "")
                self._do_arp_scan_sync()
                n = len(self.devices)
                self._boot_status(f"Found {n}", 70, "")
                if self._boot_cancel.is_set(): return
                
                if n > 0:
                    self._boot_status("Port scan...", 75, "")
                    with ThreadPoolExecutor(max_workers=PORT_WORKERS) as ex:
                        futs = {ex.submit(self._scan_device_sync, ip): ip for ip in list(self.devices.keys())}
                        done = 0
                        for f in as_completed(futs):
                            if self._boot_cancel.is_set(): return
                            done += 1
                            pct = 75 + int((done / n) * 20)
                            op = sum(len(d.ports) for d in self.devices.values())
                            self._boot_status(f"Ports {done}/{n}...", pct, f"{op} open")
                if self._boot_cancel.is_set(): return
                
                self._boot_status("Ready", 100, "")
                time.sleep(0.3)
                if not self._boot_cancel.is_set():
                    self.after(0, self._reveal_main)
            except Exception as e:
                print("boot:", e)
                self._boot_status(f"Error: {e}", 100, "")
                time.sleep(1)
                self.after(0, self._reveal_main)

        threading.Thread(target=watchdog, daemon=True).start()
        threading.Thread(target=ticker, daemon=True).start()
        threading.Thread(target=run, daemon=True).start()

    def _boot_status(self, text, pct, detail=""):
        def do():
            try:
                self.boot_status.config(text=text); self.boot_detail.config(text=detail)
                self.boot_pb.config(value=pct)
            except: pass
        try: self.after(0, do)
        except: pass

    def _show_skip_button(self):
        try:
            if self._boot_done: return
            self.boot_skip.pack(pady=(16, 0))
        except: pass

    def _skip_boot(self):
        try: self._boot_cancel.set()
        except: pass
        try: self._boot_status("Skipping...", 100, "")
        except: pass
        self.after(200, self._reveal_main)

    def _reveal_main(self):
        if self._boot_done: return
        self._boot_done = True
        try: self._boot_cancel.set()
        except: pass
        try:
            self.boot_overlay.pack_forget(); self.boot_overlay.destroy()
        except: pass
        self.set_status("Ready")
        self.after(100, self.toggle_sniff)
        self.after(400, self._refresh_loop)
        self.after(1000, self._tick_clock)
        self.after(500, self._background_ping_sweep)
        threading.Thread(target=self._network_watch_loop, daemon=True).start()
        threading.Thread(target=self._session_watch_loop, daemon=True).start()

    def _tick_clock(self):
        try: self.clock_lbl.config(text=now_hms())
        except: pass
        self.after(1000, self._tick_clock)

    def _background_ping_sweep(self):
        def worker():
            try:
                if not SCAPY_OK: return
                net = self.current_network
                if not net: return
                prefix = ".".join(net.split(".")[:3])
                self.set_status("Background ping sweep...")
                with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
                    futs = {ex.submit(ping_one, f"{prefix}.{i}", PING_TIMEOUT): i
                            for i in range(1, 255)}
                    for f in as_completed(futs):
                        try: f.result()
                        except: pass
                self._do_arp_scan_sync()
                self.set_status(f"Ready — {len(self.devices)}")
            except: pass
        threading.Thread(target=worker, daemon=True).start()

    def _do_arp_scan_sync(self):
        net = self.current_network
        if not net: return
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=net)
            ans, _ = srp(pkt, timeout=3, verbose=0)
            for _, recv in ans:
                ip, mac = recv.psrc, recv.hwsrc
                if ip not in self.devices:
                    d = Device(ip, mac); d.discovery_method = "arp"
                    self.devices[ip] = d
                else:
                    if not self.devices[ip].mac:
                        self.devices[ip].mac = mac
                        self.devices[ip].vendor = vendor_from_mac(mac)
                    self.devices[ip].touch()
        except Exception as e: self.set_status(f"ARP: {e}")

    def _scan_device_sync(self, ip):
        ports = scan_ports(ip)
        services = [extract_service_info(p, b) for p, b in ports]
        d = self.devices.get(ip)
        if not d: return
        d.ports = ports; d.service_info = services
        try: d.hostname = socket.gethostbyaddr(ip)[0]
        except: pass

    def _guess_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
            return ip
        except: return None

    def _guess_network(self):
        ip = self._guess_local_ip()
        if ip: return ".".join(ip.split(".")[:3]) + ".0/24"
        return "192.168.1.0/24"

    def _guess_gateway_ip(self):
        ip = self._guess_local_ip()
        if ip: return ".".join(ip.split(".")[:3]) + ".1"
        return None

    def _get_gateway_mac(self):
        try:
            gw = self._guess_gateway_ip()
            if not gw: return None
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gw)
            ans, _ = srp(pkt, timeout=1, verbose=0)
            if ans: return ans[0][1].hwsrc
        except: pass
        return None

    # ---------- UI ----------
    def _setup_style(self):
        st = ttk.Style(self); st.theme_use("clam")
        st.configure(".", background=BG, foreground=FG,
                     fieldbackground=BG2, bordercolor=BORDER)
        st.configure("Treeview", background=BG2, foreground=FG,
                     fieldbackground=BG2, borderwidth=0, rowheight=ROW_HEIGHT)
        st.configure("Treeview.Heading", background=BG3, foreground=FG_MUT,
                     borderwidth=0, relief="flat", font=("Segoe UI", 9, "bold"))
        st.map("Treeview", background=[("selected", ACCENT)],
               foreground=[("selected", "white")])
        st.configure("TNotebook", background=BG, borderwidth=0)
        st.configure("TNotebook.Tab", background=BG2, foreground=FG_MUT,
                     padding=[12, 7], borderwidth=0, font=("Segoe UI", 9))
        st.map("TNotebook.Tab", background=[("selected", BG3)],
               foreground=[("selected", FG)])
        st.configure("Horizontal.TProgressbar", background=ACCENT,
                     troughcolor=BG3, borderwidth=0)

    def _build_ui(self):
        self._build_main_ui()
        self._rebuild_boot_overlay()

    def _load_logo(self, size):
        if os.path.exists("logo.png"):
            try:
                img = tk.PhotoImage(file="logo.png")
                w, h = img.width(), img.height()
                if w > size or h > size:
                    factor = max(1, max(w // size, h // size))
                    img = img.subsample(factor, factor)
                return img
            except: pass
        return None

    def _rebuild_boot_overlay(self):
        self.boot_overlay = tk.Frame(self, bg=BG)
        self.boot_overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.boot_overlay.lift()
        self.boot_overlay.bind("<Button-1>", lambda e: "break")
        
        logo_img = self._load_logo(200)
        if logo_img:
            lbl = tk.Label(self.boot_overlay, image=logo_img, bg=BG)
            lbl.image = logo_img
            lbl.pack(pady=(120, 20))
        else:
            tk.Label(self.boot_overlay, text="▣", bg=BG, fg=ACCENT,
                     font=("Segoe UI", 60, "bold")).pack(pady=(120, 20))

        tk.Label(self.boot_overlay, text="CubScanner", bg=BG, fg=FG,
                 font=("Segoe UI", 28, "bold")).pack()
        tk.Label(self.boot_overlay, text="FREE EDITION", bg=BG, fg=FG_MUT,
                 font=("Segoe UI", 10, "bold")).pack(pady=(0, 30))
                 
        self.boot_status = tk.Label(self.boot_overlay, text="Starting...",
                                      bg=BG, fg=FG, font=("Segoe UI", 12))
        self.boot_status.pack(pady=(10, 4))
        self.boot_detail = tk.Label(self.boot_overlay, text="", bg=BG, fg=FG_MUT,
                                     font=("Consolas", 9))
        self.boot_detail.pack(pady=(0, 12))
        self.boot_pb = ttk.Progressbar(self.boot_overlay, length=400, mode="determinate")
        self.boot_pb.pack(pady=6)
        self.boot_elapsed = tk.Label(self.boot_overlay, text="0s", bg=BG, fg=FG_MUT,
                                       font=("Consolas", 9))
        self.boot_elapsed.pack(pady=(10, 0))
        self.boot_skip = tk.Button(
            self.boot_overlay, text="Skip loading →", command=self._skip_boot,
            bg=BG3, fg=FG_MUT, activebackground=ACCENT, activeforeground="white",
            relief="flat", borderwidth=0, padx=16, pady=6,
            font=("Segoe UI", 9), cursor="hand2")
        self.after(BOOT_SKIP_AFTER * 1000, self._show_skip_button)

    def _build_main_ui(self):
        # Banner
        banner = tk.Frame(self, bg=BANNER_BG, height=44)
        banner.pack(side="bottom", fill="x"); banner.pack_propagate(False)
        tk.Label(banner, text="⚡  Upgrade to PRO for AI vulnerability scans, history & alerts",
                 bg=BANNER_BG, fg=BANNER_FG, font=("Segoe UI", 9)).pack(side="left", padx=16)
        tk.Button(banner, text="Get PRO →", command=lambda: webbrowser.open(KOFI_URL),
                  bg=ACCENT, fg="white", relief="flat", borderwidth=0,
                  padx=16, pady=6, font=("Segoe UI", 9, "bold"),
                  cursor="hand2").pack(side="right", padx=12, pady=6)

        # Custom Title Bar
        tbar = tk.Frame(self, bg=TITLE_BG, height=36)
        tbar.pack(fill="x", side="top"); tbar.pack_propagate(False)
        
        left_row = tk.Frame(tbar, bg=TITLE_BG); left_row.pack(side="left", padx=10)
        logo_img = self._load_logo(22)
        if logo_img:
            lbl = tk.Label(left_row, image=logo_img, bg=TITLE_BG)
            lbl.image = logo_img
            lbl.pack(side="left", padx=(0, 6))
        else:
            tk.Label(left_row, text="▣", bg=TITLE_BG, fg=ACCENT,
                     font=("Segoe UI", 11, "bold")).pack(side="left", padx=(0, 6))
                     
        tk.Label(left_row, text="CubScanner", bg=TITLE_BG, fg=FG,
                 font=("Segoe UI", 10, "bold")).pack(side="left")

        right_row = tk.Frame(tbar, bg=TITLE_BG); right_row.pack(side="right", padx=10)
        self.clock_lbl = tk.Label(right_row, text=now_hms(), bg=TITLE_BG,
                                    fg=CLOCK_COLOR, font=("Consolas", 11, "bold"))
        self.clock_lbl.pack(side="left", padx=(0, 10))
        
        self.win_ctrl_frame = tk.Frame(right_row, bg=TITLE_BG)
        def _wbtn(parent, text, cmd, hfg=FG, hbg=BG3):
            return tk.Button(parent, text=text, command=cmd, bg=TITLE_BG, fg=FG_MUT,
                             activebackground=hbg, activeforeground=hfg,
                             relief="flat", borderwidth=0, padx=12, pady=4,
                             font=("Segoe UI", 10), cursor="hand2")
        _wbtn(self.win_ctrl_frame, "—", self._win_minimize).pack(side="left")
        _wbtn(self.win_ctrl_frame, "☐", self._win_maximize).pack(side="left")
        _wbtn(self.win_ctrl_frame, "✕", self._win_close,
              hfg="white", hbg="#e81123").pack(side="left")
        self._update_window_controls()

        # Toolbar
        top = tk.Frame(self, bg=BG2, height=46)
        top.pack(fill="x"); top.pack_propagate(False)
        self.net_lbl = tk.Label(top, text="Detecting...", bg=BG2, fg=FG_MUT,
                                 font=("Consolas", 9))
        self.net_lbl.pack(side="left", padx=(14, 2))
        tk.Button(top, text="?", command=self._help_network,
                  bg=BG3, fg=ACCENT, relief="flat", borderwidth=0,
                  padx=6, pady=1, font=("Segoe UI", 8, "bold"),
                  cursor="hand2").pack(side="left", padx=(0, 4))

        self.deep_btn = self._btn(top, "🔍 Deep Scan", self.deep_scan, BG3)
        self.deep_btn.pack(side="left", padx=6)
        self.sniff_btn = self._btn(top, "▶ Capture", self.toggle_sniff, BG3)
        self.sniff_btn.pack(side="left", padx=6)
        self._btn(top, "Export", self.export_menu, BG3).pack(side="left", padx=6)

        self.status_lbl = tk.Label(top, text="Starting up...", bg=BG2, fg=FG_MUT,
                                   font=("Segoe UI", 9))
        self.status_lbl.pack(side="right", padx=14)

        # Main content
        main = tk.PanedWindow(self, orient="horizontal", bg=BORDER, sashwidth=2, bd=0)
        main.pack(fill="both", expand=True)
        
        left = tk.Frame(main, bg=BG); main.add(left, width=560, minsize=400)
        hdr = tk.Frame(left, bg=BG2, height=30)
        hdr.pack(fill="x"); hdr.pack_propagate(False)
        tk.Label(hdr, text=" DEVICES", bg=BG2, fg=FG_MUT,
                 font=("Segoe UI", 8, "bold")).pack(side="left", padx=10)
        self.count_lbl = tk.Label(hdr, text="0", bg=BG2, fg=ACCENT,
                                  font=("Segoe UI", 8, "bold"))
        self.count_lbl.pack(side="right", padx=10)
        
        cols = ("ip", "mac", "type", "status", "risk")
        self.tree = ttk.Treeview(left, columns=cols, show="headings")
        for c, t, w, a in [("ip", "IP", 120, "w"), ("mac", "MAC", 135, "w"),
                            ("type", "Type", 130, "w"),
                            ("status", "Status", 90, "center"),
                            ("risk", "Risk", 70, "center")]:
            self.tree.heading(c, text=t); self.tree.column(c, width=w, anchor=a)
        self.tree.pack(fill="both", expand=True, padx=6, pady=6)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.tag_configure("critical", foreground=DANGER)
        self.tree.tag_configure("high", foreground=WARN)
        self.tree.tag_configure("medium", foreground=YEL)
        self.tree.tag_configure("ok", foreground=OK)
        self.tree.tag_configure("offline", foreground=OFFLINE_COLOR)
        self.tree.tag_configure("local", foreground=LOCAL_COLOR,
                                font=("Segoe UI", 9, "bold"))

        right = tk.Frame(main, bg=BG); main.add(right)
        self.detail_header = tk.Frame(right, bg=BG2, height=62)
        self.detail_header.pack(fill="x"); self.detail_header.pack_propagate(False)
        self.detail_title = tk.Label(self.detail_header, text="Select a device",
                                     bg=BG2, fg=FG, font=("Segoe UI", 12, "bold"))
        self.detail_title.pack(anchor="w", padx=14, pady=(10, 0))
        self.detail_sub = tk.Label(self.detail_header, text="", bg=BG2, fg=FG_MUT,
                                    font=("Segoe UI", 9))
        self.detail_sub.pack(anchor="w", padx=14)
        
        self.nb = ttk.Notebook(right); self.nb.pack(fill="both", expand=True, padx=6, pady=6)
        self.txt = {}
        for key, label in [("overview", "Overview"), ("traffic", "Traffic"),
                            ("timeline", "Timeline"),
                            ("ports", "Ports"), ("domains", "Domains"),
                            ("flows", "Flows"), ("ja3", "JA3 / TLS")]:
            frame, text = self._make_text_tab(self.nb)
            self.nb.add(frame, text=label)
            self.txt[key] = text

    def _btn(self, parent, text, cmd, bg):
        return tk.Button(parent, text=text, command=cmd, bg=bg, fg=FG,
                         activebackground=ACCENT, activeforeground="white",
                         relief="flat", borderwidth=0, padx=14, pady=6,
                         font=("Segoe UI", 9), cursor="hand2")

    def _make_text_tab(self, parent):
        f = tk.Frame(parent, bg=BG)
        t = tk.Text(f, bg=BG2, fg=FG, insertbackground=FG, relief="flat",
                    font=("Consolas", 10), wrap="word", padx=14, pady=12,
                    borderwidth=0, highlightthickness=0)
        sb = tk.Scrollbar(f, command=t.yview, bg=BG2, troughcolor=BG2,
                          relief="flat", borderwidth=0)
        t.configure(yscrollcommand=sb.set); sb.pack(side="right", fill="y")
        t.pack(fill="both", expand=True, padx=6, pady=6)
        t.tag_configure("h", foreground=ACCENT, font=("Segoe UI", 11, "bold"))
        t.tag_configure("muted", foreground=FG_MUT)
        t.tag_configure("danger", foreground=DANGER, font=("Consolas", 10, "bold"))
        t.tag_configure("warn", foreground=WARN, font=("Consolas", 10, "bold"))
        t.tag_configure("yell", foreground=YEL)
        t.tag_configure("ok", foreground=OK)
        t.tag_configure("local", foreground=LOCAL_COLOR, font=("Consolas", 10, "bold"))
        t.tag_configure("clock", foreground=CLOCK_COLOR, font=("Consolas", 10, "bold"))
        t.tag_configure("wiki", foreground=LINK, underline=True)
        t.tag_configure("port_link", foreground=PORT_LINK, underline=True)
        t.tag_bind("wiki", "<Button-1>", self._on_wiki_click)
        t.tag_bind("port_link", "<Button-1>", self._on_port_link_click)
        return f, t

    def _insert_with_links(self, widget, text, base_tag=None):
        if not text: return
        terms = sorted(WIKI_LINKS.keys(), key=len, reverse=True)
        pattern = re.compile(r"\b(" + "|".join(re.escape(t) for t in terms) + r")\b")
        pos = 0
        for m in pattern.finditer(text):
            if m.start() > pos:
                widget.insert("end", text[pos:m.start()], base_tag or ())
            widget.insert("end", m.group(1), ("wiki", f"wiki:{m.group(1)}"))
            pos = m.end()
        if pos < len(text):
            widget.insert("end", text[pos:], base_tag or ())

    def _on_wiki_click(self, event):
        w = event.widget; idx = w.index(f"@{event.x},{event.y}")
        for tag in w.tag_names(idx):
            if tag.startswith("wiki:"):
                url = wiki_url(tag.split(":", 1)[1])
                if url: webbrowser.open(url); return

    def _on_port_link_click(self, event):
        w = event.widget; idx = w.index(f"@{event.x},{event.y}")
        for tag in w.tag_names(idx):
            if tag.startswith("port:"):
                try:
                    port = int(tag.split(":", 1)[1])
                    if self.selected_ip: self._open_port_window(self.selected_ip, port)
                except: pass
                return
            if tag.startswith("device:"):
                ip = tag.split(":", 1)[1]; self._open_device_window(ip); return

    def _open_port_window(self, ip, port):
        key = (ip, port)
        win = self._port_windows.get(key)
        if win is not None:
            try:
                if win.winfo_exists(): win.lift(); win.focus_force(); return
            except: pass
        try:
            win = PortInspector(self, self, ip, port)
            self._port_windows[key] = win
        except Exception as e: messagebox.showerror("CubScanner", str(e))

    def _open_device_window(self, ip):
        key = f"device:{ip}"
        win = self._port_windows.get(key)
        if win is not None:
            try:
                if win.winfo_exists(): win.lift(); win.focus_force(); return
            except: pass
        try:
            win = DeviceTrafficWindow(self, self, ip)
            self._port_windows[key] = win
        except Exception as e: messagebox.showerror("CubScanner", str(e))

    def _set_text(self, key, parts):
        w = self.txt.get(key)
        if w is None: return
        was_bottom = text_is_at_bottom(w)
        prev = None
        if not was_bottom:
            try: prev = w.yview()
            except: pass
        w.configure(state="normal"); w.delete("1.0", "end")
        for text, tag in parts:
            if tag == "wiki": self._insert_with_links(w, text)
            elif isinstance(tag, tuple): w.insert("end", text, tag)
            else: w.insert("end", text, tag or ())
        w.configure(state="disabled")
        if was_bottom: text_scroll_to_bottom(w)
        elif prev:
            try: w.yview_moveto(prev[0])
            except: pass

    def _help_network(self):
        show_help(self, "Network address",
            "Example: 192.168.1.0/24\n\n"
            "• /24 = 254 hosts\n• /16 = 65534 hosts")

    def set_status(self, msg):
        try: self.after(0, lambda m=msg: self.status_lbl.config(text=m))
        except: pass

    # ---------- LOOPS ----------
    def _network_watch_loop(self):
        while True:
            time.sleep(NET_CHECK_INTERVAL)
            try:
                new_ip = self._guess_local_ip()
                new_net = self._guess_network()
                if self.current_network and new_net != self.current_network:
                    self.after(0, self._handle_network_change, new_net, new_ip)
                self.local_ip = new_ip
            except: pass

    def _handle_network_change(self, new_net, new_ip):
        self.current_network = new_net
        self.net_lbl.config(text=new_net)
        self.set_status(f"Network changed — re-discovering on {new_net}")
        self._stop_sniffer()
        self.devices = {}; self.selected_ip = None; self._last_order = []
        for key, win in list(self._port_windows.items()):
            try: win._on_close()
            except: pass
        self._port_windows.clear()
        try:
            for iid in self.tree.get_children(): self.tree.delete(iid)
            self.detail_title.config(text="Select a device")
            self.detail_sub.config(text="")
            for k in self.txt:
                w = self.txt[k]
                if w:
                    w.configure(state="normal"); w.delete("1.0", "end")
                    w.configure(state="disabled")
        except: pass
        self.local_ip = new_ip
        threading.Thread(target=self._do_deep_scan, daemon=True).start()
        self.after(500, self.toggle_sniff)

    def _session_watch_loop(self):
        while True:
            time.sleep(30)
            try:
                now = time.time()
                for d in list(self.devices.values()):
                    if d.is_online and (now - d.last_seen) > ONLINE_THRESHOLD:
                        d.is_online = False
                        if d.session_start is not None:
                            d.sessions.append({"start": d.session_start, "end": d.last_seen})
            except: pass

    def _sort_key(self, item):
        ip, d = item
        is_local = (ip == self.local_ip)
        is_online = d.is_online and (time.time() - d.last_seen) < ONLINE_THRESHOLD
        if is_local: return (0, 0, ip)
        if is_online: return (1, -d.last_reconnect, ip)
        return (2, -d.last_seen, ip)

    def _refresh_loop(self):
        try:
            self._refresh_tree()
            if self.selected_ip: self._render_detail()
            online = sum(1 for d in self.devices.values() if d.is_online)
            total = len(self.devices)
            if self.sniffer and not self.sniffer.stop_flag:
                self.count_lbl.config(text=f"{online}/{total} · {self.pkt_count} · {now_hms()}")
            else:
                self.count_lbl.config(text=f"{online}/{total} · {now_hms()}")
        except: pass
        self.after(1500, self._refresh_loop)

    def _row_data(self, d):
        label, _ = d.risk_label()
        status, _ = d.current_status()
        dtype, _, _ = d.get_type()
        values = (d.ip, d.mac or "—", dtype, status, label)
        tag_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "OK": "ok"}
        base = tag_map.get(label, "ok")
        is_local = (d.ip == self.local_ip)
        is_online = d.is_online and (time.time() - d.last_seen) < ONLINE_THRESHOLD
        if is_local: tags = ("local",)
        elif not is_online: tags = (base, "offline")
        else: tags = (base,)
        return values, tags

    def _refresh_tree(self):
        ordered = sorted(self.devices.items(), key=self._sort_key)
        new_order = [ip for ip, _ in ordered]
        if new_order == self._last_order:
            for ip, d in ordered:
                if self.tree.exists(ip):
                    v, t = self._row_data(d); self.tree.item(ip, values=v, tags=t)
            return
        prev = None
        try: prev = self.tree.yview()
        except: pass
        for iid in list(self.tree.get_children()):
            if iid not in new_order: self.tree.delete(iid)
        for idx, (ip, d) in enumerate(ordered):
            v, t = self._row_data(d)
            if self.tree.exists(ip):
                self.tree.item(ip, values=v, tags=t)
                if self.tree.index(ip) != idx: self.tree.move(ip, "", idx)
            else: self.tree.insert("", idx, iid=ip, values=v, tags=t)
        if self.selected_ip and self.tree.exists(self.selected_ip):
            try: self.tree.selection_set(self.selected_ip)
            except: pass
        if prev:
            try: self.tree.yview_moveto(prev[0])
            except: pass
        self._last_order = new_order

    def on_select(self, _):
        sel = self.tree.selection()
        if not sel: return
        self.selected_ip = sel[0]
        self._render_detail()

    def deep_scan(self):
        if not SCAPY_OK: return
        if not messagebox.askyesno("Deep Scan", "Wake sleeping devices?\n\nContinue?"): return
        threading.Thread(target=self._do_deep_scan, daemon=True).start()

    def _do_deep_scan(self):
        net = self.current_network
        if not net: return
        prefix = ".".join(net.split(".")[:3])
        with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
            futs = {ex.submit(ping_one, f"{prefix}.{i}", PING_TIMEOUT): i
                    for i in range(1, 255)}
            for f in as_completed(futs):
                try: f.result()
                except: pass
        self._do_arp_scan_sync()
        for ip in list(self.devices.keys()):
            threading.Thread(target=self._scan_device_sync, args=(ip,), daemon=True).start()

    def toggle_sniff(self):
        if not SCAPY_OK: return
        if self.sniffer and not self.sniffer.stop_flag:
            self.sniffer.stop_flag = True; self.sniffer = None
            self.sniff_btn.config(text="▶ Capture", bg=BG3)
        else:
            self.pkt_count = 0
            self.sniffer = Sniffer(self); self.sniffer.start()
            self.sniff_btn.config(text="■ Stop", bg=DANGER)

    def _stop_sniffer(self):
        if self.sniffer and not self.sniffer.stop_flag:
            self.sniffer.stop_flag = True; self.sniffer = None
            try: self.sniff_btn.config(text="▶ Capture", bg=BG3)
            except: pass

    # ---------- RENDER ----------
    def _render_detail(self):
        d = self.devices.get(self.selected_ip)
        if not d: return
        label, color = d.risk_label()
        status, _ = d.current_status()
        dtype, _, _ = d.get_type()
        if d.ip == self.local_ip:
            title_color = LOCAL_COLOR; marker = f"  {HOUSE_CHAR} YOU"
        else:
            title_color = color; marker = ""
        self.detail_title.config(text=f"{d.ip}{marker}  ·  {d.hostname or dtype or 'Device'}")
        self.detail_sub.config(
            text=f"MAC: {d.mac or '—'}   Type: {dtype}   Status: {status}   "
                 f"Risk: {d.risk_score()}/100 ({label})   ·   {now_hms()}",
            fg=title_color)
        self._render_overview(d); self._render_traffic(d); self._render_timeline(d)
        self._render_ports(d); self._render_domains(d); self._render_flows(d)
        self._render_ja3(d)

    def _render_overview(self, d):
        dtype, dt_conf, dt_reasons = d.get_type()
        p = [(f"Device summary — {d.ip}\n\n", "h")]
        if d.ip == self.local_ip:
            p.append((f"{HOUSE_CHAR}  This is your own device\n\n", "local"))
        status, _ = d.current_status()
        p.append((f"Status    : {status}\n", "ok" if d.is_online else "muted"))
        p.append((f"Refreshed : {now_hms()}\n", "clock"))
        p.append((f"MAC       : {d.mac or '—'}\n", None))
        p.append((f"Hostname  : {d.hostname or '—'}\n", None))
        p.append((f"Vendor    : {d.vendor}\n", None))
        p.append((f"Discovery : {d.discovery_method}\n", None))
        p.append((f"\nType\n", "h"))
        conf_label = "HIGH" if dt_conf >= 0.85 else "MEDIUM" if dt_conf >= 0.5 else "LOW"
        p.append((f"Detected : {dtype}  ({conf_label})\n",
                  "ok" if dt_conf >= 0.85 else "warn" if dt_conf > 0 else "muted"))
        for r in dt_reasons[:8]: p.append((f"  • {r}\n", "muted"))
        to = sum(f["out"] for f in d.flows.values())
        ti = sum(f["in"] for f in d.flows.values())
        p.append((f"\nTraffic\n", "h"))
        p.append((f"Out : {fmt_bytes(to)}\n", None))
        p.append((f"In  : {fmt_bytes(ti)}\n", None))
        p.append((f"Ports : {len(d.ports)}\n", None))
        self._set_text("overview", p)

    def _render_traffic(self, d):
        p = [(f"Live traffic — {d.ip}   ", "h")]
        p.append((f"[{now_hms()}]", "clock"))
        p.append(("\n\n", None))
        p.append(("[Open device traffic window]", ("port_link", f"device:{d.ip}")))
        p.append(("\n\n", None))
        dt = d.device_traffic
        p.append((f"All-port: {dt['pkts']} pkts / {fmt_bytes(dt['bytes'])}\n\n", None))
        to = sum(f["out"] for f in d.flows.values()); ti = sum(f["in"] for f in d.flows.values())
        p.append((f"Out: {fmt_bytes(to)}\n", None))
        p.append((f"In : {fmt_bytes(ti)}\n", None))
        p.append((f"Flows: {len(d.flows)}\n\n", None))
        if d.flows:
            p.append(("Top destinations\n", "h"))
            for dst, f in sorted(d.flows.items(), key=lambda x: -(x[1]["out"] + x[1]["in"]))[:30]:
                p.append((f"  {dst:<16} ↑ {fmt_bytes(f['out']):>9}  "
                          f"↓ {fmt_bytes(f['in']):>9}  ({f['pkts']})\n", None))
        self._set_text("traffic", p)

    def _render_timeline(self, d):
        p = [(f"Timeline\n\n", "h")]
        if d.is_online:
            s = datetime.fromtimestamp(d.session_start).strftime("%H:%M:%S")
            p.append((f"● Online since {s} ({fmt_duration(time.time()-d.session_start)})\n\n", "ok"))
        if d.sessions:
            p.append((f"Total: {len(d.sessions)} / {fmt_duration(d.total_time_online())}\n\n", "muted"))
            for s in d.sessions:
                sd = datetime.fromtimestamp(s["start"]); ed = datetime.fromtimestamp(s["end"])
                p.append((f"  {sd.strftime('%a %d/%m')}  {sd.strftime('%H:%M:%S')} - {ed.strftime('%H:%M:%S')}  ({fmt_duration(s['end']-s['start'])})\n", None))
        else: p.append(("No sessions yet.\n", "muted"))
        self._set_text("timeline", p)

    def _render_ports(self, d):
        p = [(f"Ports on {d.ip}   ", "h")]
        p.append((f"[{now_hms()}]", "clock")); p.append(("\n\n", None))
        if not d.ports: p.append(("No common ports open.\n", "muted"))
        else:
            si = {s["port"]: s for s in d.service_info}
            for port, banner in d.ports:
                svc = COMMON_PORTS.get(port, "?")
                p.append((f"  ● {port:<6} ", "ok")); p.append((f"{svc}", "wiki"))
                p.append((f"   ", None)); p.append(("[inspect]", ("port_link", f"port:{port}")))
                p.append(("\n", None))
                entry = si.get(port, {})
                if entry.get("product"):
                    ver = f" {entry['version']}" if entry.get("version") else ""
                    p.append((f"      {entry['product']}{ver}\n", "muted"))
                if banner: p.append((f"      {banner[:150]}\n", "muted"))
        self._set_text("ports", p)

    def _render_domains(self, d):
        p = [(f"Domains ({len(d.domains)})   ", "h")]
        p.append((f"[{now_hms()}]", "clock")); p.append(("\n\n", None))
        if not d.domains: p.append(("None captured.\n", "muted"))
        else:
            for dom in sorted(d.domains):
                tag = "warn" if re.search(r"\.(tk|ml|ga|cf|gq)$", dom) else None
                p.append((f"  {dom}\n", tag))
        self._set_text("domains", p)

    def _render_flows(self, d):
        p = [(f"Flows   ", "h")]
        p.append((f"[{now_hms()}]", "clock")); p.append(("\n\n", None))
        for dst, f in sorted(d.flows.items(), key=lambda x: -(x[1]["out"] + x[1]["in"]))[:200]:
            p.append((f"  {dst:<16} ↑ {fmt_bytes(f['out']):>9}  "
                      f"↓ {fmt_bytes(f['in']):>9}  ({f['pkts']})\n", None))
        self._set_text("flows", p)

    def _render_ja3(self, d):
        p = [(f"JA3 ({len(d.ja3s)})   ", "h")]
        p.append((f"[{now_hms()}]", "clock")); p.append(("\n\n", None))
        for h in sorted(d.ja3s):
            t = JA3_DB.get(h)
            if t:
                sus = any(x in t for x in SUSPICIOUS_JA3)
                p.append((f"  {h}\n", "danger" if sus else "ok"))
                p.append((f"     → {t}\n\n", "muted"))
            else:
                p.append((f"  {h}\n", "warn"))
                p.append((f"     → unknown\n\n", "muted"))
        self._set_text("ja3", p)

    # ---------- EXPORT ----------
    def export_menu(self):
        m = tk.Menu(self, tearoff=0, bg=BG2, fg=FG, activebackground=ACCENT,
                    activeforeground="white", borderwidth=0)
        m.add_command(label="JSON", command=self.export_json)
        m.add_command(label="HTML", command=self.export_html)
        try: m.tk_popup(self.winfo_pointerx(), self.winfo_pointery())
        finally: m.grab_release()

    def export_json(self):
        if not self.devices: messagebox.showinfo("CubScanner", "Empty."); return
        fn = filedialog.asksaveasfilename(defaultextension=".json",
            initialfile=f"cubscanner_{int(time.time())}.json", filetypes=[("JSON", "*.json")])
        if not fn: return
        data = {"generated_at": datetime.now().isoformat(), "devices": []}
        for ip, d in list(self.devices.items()):
            dtype, dt_conf, dt_reasons = d.get_type()
            data["devices"].append({
                "ip": ip, "mac": d.mac, "vendor": d.vendor, "hostname": d.hostname,
                "risk": d.risk_score(), "device_type": dtype,
                "ports": [{"port": p, "banner": b} for p, b in d.ports],
                "domains": sorted(d.domains), "ja3": sorted(d.ja3s),
                "flows": dict(d.flows)})
        with open(fn, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        messagebox.showinfo("CubScanner", f"Saved:\n{fn}")

    def export_html(self):
        if not self.devices: messagebox.showinfo("CubScanner", "Empty."); return
        fn = filedialog.asksaveasfilename(defaultextension=".html",
            initialfile=f"cubscanner_{int(time.time())}.html", filetypes=[("HTML", "*.html")])
        if not fn: return
        rows = []
        for ip, d in sorted(self.devices.items(), key=lambda x: -x[1].risk_score()):
            label, color = d.risk_label(); status, _ = d.current_status()
            dtype, _, _ = d.get_type()
            to = sum(f["out"] for f in d.flows.values()); ti = sum(f["in"] for f in d.flows.values())
            rows.append(f"""<div class="card">
              <div class="card-head" style="border-left:4px solid {color}">
                <div><div class="ip">{ip}</div><div class="muted">{d.hostname or dtype}</div></div>
                <div class="risk" style="color:{color}">{d.risk_score()}/100 · {label}</div>
              </div>
              <div class="grid">
                <div>Status<br><b>{status}</b></div><div>Type<br><b>{dtype}</b></div>
                <div>MAC<br><b>{d.mac or '—'}</b></div>
                <div>Out<br><b>{fmt_bytes(to)}</b></div>
                <div>In<br><b>{fmt_bytes(ti)}</b></div>
                <div>Ports<br><b>{len(d.ports)}</b></div>
              </div>
            </div>""")
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>CubScanner Free Report</title><style>
body{{margin:0;background:#121214;color:#e4e4e7;font-family:Segoe UI,sans-serif;padding:32px}}
h1{{margin:0 0 4px}}.sub{{color:#a1a1aa;margin-bottom:24px}}
.cards{{display:grid;gap:14px;grid-template-columns:repeat(auto-fill,minmax(480px,1fr))}}
.card{{background:#18181b;border:1px solid #3f3f46;border-radius:10px;padding:16px}}
.card-head{{display:flex;justify-content:space-between;align-items:center;padding-left:12px;margin-bottom:12px}}
.ip{{font-size:16px;font-weight:600;font-family:Consolas,monospace}}
.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;font-size:12px}}
.muted{{color:#a1a1aa;font-size:11px}}
</style></head><body>
<h1>▣ CubScanner Free — Report</h1>
<div class="sub">{ts} · {len(self.devices)} devices</div>
<div class="cards">{''.join(rows)}</div></body></html>"""
        with open(fn, "w", encoding="utf-8") as f: f.write(html)
        try: webbrowser.open(f"file://{os.path.abspath(fn)}")
        except: pass

def main():
    if sys.platform == "win32":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("Warning: run as Administrator.")
        except: pass
    app = CubScanner()
    app.mainloop()

if __name__ == "__main__":
    main()