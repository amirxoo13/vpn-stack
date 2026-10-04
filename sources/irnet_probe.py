#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
irnet_probe.py  -  Iran network reachability prober
====================================================
اندازه‌گیری واقعی این‌که از خط اینترنت شما، چه چیزی از مرز عبور می‌کند.

این اسکریپت هیچ داده‌ای را جایی نمی‌فرستد. فقط به IPهای عمومی وصل می‌شود
و نتیجه را در فایل JSON و روی صفحه چاپ می‌کند.

فقط کتابخانه‌های استاندارد پایتون. هیچ pip install لازم نیست.

اجرا:
    python irnet_probe.py --vm-ip 34.156.152.38 --domain cdn.amirxo.com

--vm-ip و --domain اجباری‌اند: این اسکریپت مقدار پیش‌فرضی برای سرور کسی
ندارد و نباید داشته باشد.
"""

import argparse
import concurrent.futures as cf
import json
import os
import platform
import random
import socket
import ssl
import struct
import sys
import time

# ----------------------------------------------------------------------------
# تنظیمات پیش‌فرض
# ----------------------------------------------------------------------------

CONNECT_TIMEOUT = 6.0
TLS_TIMEOUT = 8.0
UDP_TIMEOUT = 4.0

# IPهای ثابت و شناخته‌شده‌ی هر شبکه‌ی لبه (anycast هستند و تغییر نمی‌کنند)
EDGE_IPS = {
    "cloudflare-104.16": "104.16.132.229",
    "cloudflare-172.67": "172.67.161.218",
    "cloudflare-188.114": "188.114.96.3",
    "cloudflare-162.159": "162.159.140.238",
    "fastly-151.101": "151.101.66.10",
    "fastly-199.232": "199.232.194.10",
    "akamai-23.x": "23.222.157.180",
    "google-frontend-142": "142.250.185.100",
    "google-frontend-216": "216.239.36.21",
    "gcp-globallb-34.117": "34.117.59.81",
    "amazon-cloudfront": "108.138.7.30",
    "azure-frontdoor": "13.107.246.45",
}

# SNIهایی که تست می‌کنیم. هدف: بفهمیم DPI بر اساس SNI می‌کشد یا نه.
SNI_PROBES = [
    # SNIهای «مرجع» که تقریبا همیشه در ایران باز هستند
    "www.microsoft.com",
    "github.com",
    "www.bing.com",
    "cdnjs.cloudflare.com",
    # SNIهای محتملاً مسدود
    "www.youtube.com",
    "twitter.com",
    # دامنه‌ی خود شما (هنوز ساخته نشده - فقط رفتار DPI را می‌سنجیم)
    "__USER_DOMAIN__",
    # یک SNI تصادفی که هیچ‌جا وجود ندارد: آیا DPI SNI ناشناس را می‌کشد؟
    "__RANDOM__",
]

# پورت‌هایی که روی VM خودتان تست می‌شود
VM_TCP_PORTS = [22, 80, 443, 853, 2053, 2083, 2087, 2096, 8443, 3306, 1433]

# resolverهای خارجی برای تست UDP/53
UDP_DNS_TARGETS = {
    "cloudflare-dns": "1.1.1.1",
    "google-dns": "8.8.8.8",
    "quad9-dns": "9.9.9.9",
}

# دامنه‌هایی که برای تشخیص DNS hijack پرس‌وجو می‌کنیم
HIJACK_TEST_DOMAINS = ["www.youtube.com", "twitter.com", "www.bbc.com"]
IRAN_BLOCKPAGE_NETS = ("10.10.34.", "10.10.35.")


# ----------------------------------------------------------------------------
# ابزارهای کمکی
# ----------------------------------------------------------------------------

def classify_exc(e):
    """نوع خطا را به یک برچسب معنادار تبدیل می‌کند."""
    if isinstance(e, socket.timeout):
        return "TIMEOUT(silent-drop)"
    if isinstance(e, ConnectionResetError):
        return "RST(dpi-kill)"
    if isinstance(e, ConnectionRefusedError):
        return "REFUSED(port-closed)"
    if isinstance(e, ssl.SSLError):
        return "TLS-ERROR:%s" % (getattr(e, "reason", None) or "unknown")
    if isinstance(e, OSError):
        msg = str(e)
        if "unreachable" in msg.lower():
            return "UNREACHABLE"
        return "OSERROR:%s" % (e.errno,)
    return "%s:%s" % (type(e).__name__, e)


def tcp_connect(ip, port, timeout=CONNECT_TIMEOUT):
    """فقط TCP handshake. برمی‌گرداند (ok, label, rtt_ms)"""
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        rtt = (time.time() - t0) * 1000.0
        return True, "OPEN", round(rtt, 1)
    except Exception as e:
        return False, classify_exc(e), round((time.time() - t0) * 1000.0, 1)
    finally:
        try:
            s.close()
        except Exception:
            pass


def build_client_hello(sni):
    """
    یک ClientHello واقعی را با MemoryBIO می‌سازد تا بتوانیم آن را
    تکه‌تکه بفرستیم و رفتار DPI را بسنجیم.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
    sobj = ctx.wrap_bio(inb, outb, server_hostname=sni)
    try:
        sobj.do_handshake()
    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
        pass
    except Exception:
        pass
    return outb.read()


def tls_probe(ip, port, sni, timeout=TLS_TIMEOUT, fragment=False):
    """
    TCP وصل می‌شود، بعد ClientHello با SNI مشخص می‌فرستد و می‌بیند
    آیا ServerHello برمی‌گردد یا اتصال کشته می‌شود.

    fragment=True یعنی ClientHello را در چند تکه‌ی کوچک با تاخیر بفرست
    (تست این‌که DPI بازچینی TCP انجام می‌دهد یا نه).
    """
    res = {
        "ip": ip, "port": port, "sni": sni, "fragmented": fragment,
        "tcp": None, "tls": None, "detail": "", "rtt_ms": None,
        "tls_version": None, "cipher": None, "server_hello_bytes": 0,
    }

    if not fragment:
        # مسیر ساده: یک اتصال، هم TCP را می‌سنجد هم TLS را.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        t0 = time.time()
        try:
            s.connect((ip, port))
        except Exception as e:
            res["tcp"] = classify_exc(e)
            res["rtt_ms"] = round((time.time() - t0) * 1000.0, 1)
            res["tls"] = "SKIPPED(no-tcp)"
            s.close()
            return res
        res["tcp"] = "OPEN"
        res["rtt_ms"] = round((time.time() - t0) * 1000.0, 1)
        try:
            s.settimeout(timeout)
            ss = ctx.wrap_socket(s, server_hostname=sni)
            res["tls"] = "HANDSHAKE-OK"
            res["tls_version"] = ss.version()
            try:
                res["cipher"] = ss.cipher()[0]
            except Exception:
                pass
            der = ss.getpeercert(binary_form=True)
            res["detail"] = "cert_len=%d" % (len(der) if der else 0)
            ss.close()
        except Exception as e:
            res["tls"] = classify_exc(e)
        finally:
            try:
                s.close()
            except Exception:
                pass
        return res

    # مسیر تکه‌تکه
    ok, label, rtt = tcp_connect(ip, port, timeout=CONNECT_TIMEOUT)
    res["tcp"] = label
    res["rtt_ms"] = rtt
    if not ok:
        res["tls"] = "SKIPPED(no-tcp)"
        return res

    ch = build_client_hello(sni)
    if not ch:
        res["tls"] = "ERROR(no-clienthello)"
        return res
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        i = 0
        while i < len(ch):
            n = random.randint(8, 24)
            s.sendall(ch[i:i + n])
            i += n
            time.sleep(0.02)
        data = s.recv(4096)
        if not data:
            res["tls"] = "EOF(closed-by-peer)"
        elif data[0] == 0x16:      # TLS Handshake record
            res["tls"] = "SERVER-HELLO-OK"
            res["server_hello_bytes"] = len(data)
        elif data[0] == 0x15:      # TLS Alert
            res["tls"] = "TLS-ALERT"
            res["server_hello_bytes"] = len(data)
        else:
            res["tls"] = "UNEXPECTED(0x%02x)" % data[0]
            res["server_hello_bytes"] = len(data)
    except Exception as e:
        res["tls"] = classify_exc(e)
    finally:
        try:
            s.close()
        except Exception:
            pass
    return res


def make_dns_query(qname, qtype=1):
    """یک پکت پرس‌وجوی DNS خام می‌سازد."""
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    q = b""
    for part in qname.rstrip(".").split("."):
        b = part.encode("idna") if any(ord(c) > 127 for c in part) else part.encode()
        q += bytes([len(b)]) + b
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    return tid, header + q


def parse_dns_a_records(pkt, tid):
    """رکوردهای A را از پاسخ DNS بیرون می‌کشد."""
    if len(pkt) < 12:
        return []
    rtid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", pkt[:12])
    if rtid != tid:
        return []
    off = 12
    # رد کردن بخش question
    for _ in range(qd):
        while off < len(pkt) and pkt[off] != 0:
            if pkt[off] & 0xC0 == 0xC0:
                off += 2
                break
            off += pkt[off] + 1
        else:
            off += 1
        off += 4
    ips = []
    for _ in range(an):
        if off + 12 > len(pkt):
            break
        if pkt[off] & 0xC0 == 0xC0:
            off += 2
        else:
            while off < len(pkt) and pkt[off] != 0:
                off += pkt[off] + 1
            off += 1
        if off + 10 > len(pkt):
            break
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", pkt[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(pkt[off:off + 4]))
        off += rdlen
    return ips


def udp_dns_probe(ip, qname="example.com", timeout=UDP_TIMEOUT, port=53):
    """آیا UDP/53 به یک resolver خارجی از مرز عبور می‌کند؟"""
    tid, pkt = make_dns_query(qname)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.sendto(pkt, (ip, port))
        data, _ = s.recvfrom(2048)
        ips = parse_dns_a_records(data, tid)
        return {"status": "ANSWERED", "rtt_ms": round((time.time() - t0) * 1000, 1),
                "answers": ips, "bytes": len(data)}
    except Exception as e:
        return {"status": classify_exc(e), "rtt_ms": None, "answers": [], "bytes": 0}
    finally:
        try:
            s.close()
        except Exception:
            pass


def udp_echo_probe(ip, port, timeout=UDP_TIMEOUT):
    """
    تست عبور UDP روی پورت غیر ۵۳.
    نیاز دارد که udp_echo_server.py روی VM در حال اجرا باشد.
    """
    token = ("PROBE-%08x" % random.getrandbits(32)).encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.sendto(token, (ip, port))
        data, _ = s.recvfrom(2048)
        ok = token in data
        return {"status": "ECHOED" if ok else "WRONG-REPLY",
                "rtt_ms": round((time.time() - t0) * 1000, 1)}
    except Exception as e:
        return {"status": classify_exc(e), "rtt_ms": None}
    finally:
        try:
            s.close()
        except Exception:
            pass


def system_dns_hijack_test():
    """
    با resolver سیستم چند دامنه‌ی مسدود را resolve می‌کند و می‌بیند
    آیا جواب به 10.10.34.x برمی‌گردد (صفحه‌ی مسدودی ایران).
    """
    out = {}
    for d in HIJACK_TEST_DOMAINS:
        try:
            infos = socket.getaddrinfo(d, 443, socket.AF_INET, socket.SOCK_STREAM)
            ips = sorted({i[4][0] for i in infos})
            hij = any(ip.startswith(IRAN_BLOCKPAGE_NETS) for ip in ips)
            out[d] = {"ips": ips, "hijacked": hij}
        except Exception as e:
            out[d] = {"ips": [], "hijacked": None, "error": classify_exc(e)}
    return out


def mtu_probe(ip, port=443, low=1200, high=1500):
    """
    Path MTU فقط با تأیید خود مسیر معنی دارد (مثلا ICMP fragmentation-needed).

    sendto محلی فقط می‌گوید پشته‌ی خودمان دیتاگرام را قبول کرده، نه اینکه
    از مسیر رد شده باشد. هر OSError هم «بسته بزرگ است» نیست (فقط EMSGSIZE
    این معنی را دارد). بدون تأیید مسیر اندازه گزارش نمی‌شود.
    """
    _ = (low, high)
    if not sys.platform.startswith("linux"):
        return {"status": "UNSUPPORTED(%s: DF در دسترس نیست)" % sys.platform,
                "max_packet": None}
    return {"status": "UNKNOWN(no path confirmation %s:%s)" % (ip, port),
            "max_packet": None}


# ----------------------------------------------------------------------------
# اجرای کلی
# ----------------------------------------------------------------------------

def run(vm_ip, domain, udp_port, workers=12):
    report = {
        "meta": {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S %z"),
            "vm_ip": vm_ip,
            "domain": domain,
            "python": sys.version.split()[0],
            "os": "%s %s" % (platform.system(), platform.release()),
        }
    }

    rnd_sni = "cdn-%08x.example.net" % random.getrandbits(32)
    snis = [domain if s == "__USER_DOMAIN__" else (rnd_sni if s == "__RANDOM__" else s)
            for s in SNI_PROBES]

    # ---- ۱) پورت‌های VM خودتان (مستقیم) -----------------------------------
    print("\n[1/6] تست دسترسی مستقیم به VM شما (%s) ..." % vm_ip, flush=True)
    vm = {}
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(tcp_connect, vm_ip, p): p for p in VM_TCP_PORTS}
        for f in cf.as_completed(futs):
            p = futs[f]
            ok, label, rtt = f.result()
            vm[str(p)] = {"status": label, "rtt_ms": rtt}
            print("      port %-5s -> %-22s %s" % (p, label, ("%sms" % rtt) if ok else ""), flush=True)
    report["vm_direct_tcp"] = vm

    # ---- ۲) شبکه‌های لبه: آیا IP اصلا جواب می‌دهد؟ ------------------------
    print("\n[2/6] تست دسترسی TCP/443 به شبکه‌های لبه (CDN) ...", flush=True)
    edges = {}
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(tcp_connect, ip, 443): name for name, ip in EDGE_IPS.items()}
        for f in cf.as_completed(futs):
            name = futs[f]
            ok, label, rtt = f.result()
            edges[name] = {"ip": EDGE_IPS[name], "status": label, "rtt_ms": rtt}
    for name in EDGE_IPS:
        e = edges[name]
        print("      %-24s %-16s -> %-22s %s" % (
            name, e["ip"], e["status"], ("%sms" % e["rtt_ms"]) if e["status"] == "OPEN" else ""), flush=True)
    report["edge_tcp443"] = edges

    # ---- ۳) رفتار SNI روی کلادفلر ------------------------------------------
    print("\n[3/6] تست SNI روی کلادفلر (مهم‌ترین تست) ...", flush=True)
    cf_ip = EDGE_IPS["cloudflare-104.16"]
    sni_res = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(tls_probe, cf_ip, 443, s, TLS_TIMEOUT, False) for s in snis]
        for f in cf.as_completed(futs):
            sni_res.append(f.result())
    sni_res.sort(key=lambda r: snis.index(r["sni"]))
    for r in sni_res:
        print("      SNI %-32s tcp=%-18s tls=%-22s %s" % (
            r["sni"][:32], r["tcp"], r["tls"], r["detail"]), flush=True)
    report["cloudflare_sni"] = sni_res

    # ---- ۴) تست ClientHello تکه‌تکه ---------------------------------------
    print("\n[4/6] تست ClientHello تکه‌تکه (آیا DPI بازچینی TCP می‌کند؟) ...", flush=True)
    frag = []
    for s in ["www.microsoft.com", "www.youtube.com", domain]:
        r = tls_probe(cf_ip, 443, s, TLS_TIMEOUT, fragment=True)
        frag.append(r)
        print("      SNI %-32s frag-tls=%-24s bytes=%d" % (
            s[:32], r["tls"], r["server_hello_bytes"]), flush=True)
    report["fragmented_clienthello"] = frag

    # ---- ۵) UDP -----------------------------------------------------------
    print("\n[5/6] تست UDP ...", flush=True)
    udp = {"dns53": {}, "nonstandard": {}}
    for name, ip in UDP_DNS_TARGETS.items():
        r = udp_dns_probe(ip)
        udp["dns53"][name] = r
        print("      UDP/53  %-14s (%s) -> %-22s %s" % (
            name, ip, r["status"], r["answers"]), flush=True)
    for p in [53, udp_port, 51820, 1194]:
        r = udp_echo_probe(vm_ip, p)
        udp["nonstandard"][str(p)] = r
        print("      UDP/%-5s به VM شما        -> %s" % (p, r["status"]), flush=True)
    print("      (اگر udp_echo_server.py روی VM اجرا نشده باشد، این سه مورد بی‌معنی است)")
    report["udp"] = udp

    # ---- ۶) DNS hijack + MTU ---------------------------------------------
    print("\n[6/6] تست DNS hijack و MTU ...", flush=True)
    hij = system_dns_hijack_test()
    for d, v in hij.items():
        flag = "HIJACKED" if v.get("hijacked") else ("clean" if v.get("hijacked") is False else "error")
        print("      %-20s -> %-10s %s" % (d, flag, v.get("ips") or v.get("error")), flush=True)
    report["dns_hijack"] = hij

    mtu_ip = cf_ip if edges["cloudflare-104.16"]["status"] == "OPEN" else vm_ip
    m = mtu_probe(mtu_ip)
    print("      MTU probe روی %s -> %s" % (mtu_ip, m), flush=True)
    report["mtu"] = {"target": mtu_ip, **m}

    return report


def summarize(rep):
    """خلاصه‌ی قابل تصمیم‌گیری."""
    lines = []
    A = lines.append
    A("=" * 72)
    A("خلاصه‌ی تصمیم‌گیری")
    A("=" * 72)

    vm443 = rep["vm_direct_tcp"].get("443", {}).get("status")
    vm80 = rep["vm_direct_tcp"].get("80", {}).get("status")
    vm22 = rep["vm_direct_tcp"].get("22", {}).get("status")
    A("• دسترسی مستقیم به VM:  443=%s  80=%s  22=%s" % (vm443, vm80, vm22))
    if vm443 == "OPEN":
        A("  => IP گوگل کلود از این خط قابل دسترسی است. مسیر مستقیم (Reality) ممکن است.")
    else:
        A("  => IP گوگل کلود مستقیم در دسترس نیست. باید از CDN عبور کنیم.")

    open_edges = [n for n, v in rep["edge_tcp443"].items() if v["status"] == "OPEN"]
    A("• شبکه‌های لبه‌ی باز روی 443: %s" % (", ".join(open_edges) if open_edges else "هیچ‌کدام"))

    ok_snis = [r["sni"] for r in rep["cloudflare_sni"] if r["tls"] == "HANDSHAKE-OK"]
    bad_snis = [(r["sni"], r["tls"]) for r in rep["cloudflare_sni"] if r["tls"] != "HANDSHAKE-OK"]
    A("• SNIهایی که روی کلادفلر هندشیک کامل شد: %s" % (", ".join(ok_snis) if ok_snis else "هیچ‌کدام"))
    if bad_snis:
        A("• SNIهای ناموفق: %s" % ", ".join("%s(%s)" % (s, t) for s, t in bad_snis))

    dom = rep["meta"]["domain"]
    dom_r = next((r for r in rep["cloudflare_sni"] if r["sni"] == dom), None)
    if dom_r:
        if dom_r["tls"] == "HANDSHAKE-OK":
            A("  => دامنه‌ی خودتان (%s) روی کلادفلر مشکلی ندارد. عالی." % dom)
        else:
            A("  => دامنه‌ی خودتان (%s) نتیجه: %s  <-- این را به من بگو" % (dom, dom_r["tls"]))

    rnd = [r for r in rep["cloudflare_sni"] if r["sni"].startswith("cdn-")]
    if rnd:
        A("• SNI تصادفیِ ناشناس: %s" % rnd[0]["tls"])
        if rnd[0]["tls"] != "HANDSHAKE-OK":
            A("  => هشدار: DPI شما SNI ناشناس را می‌کشد. یعنی whitelist فعال است.")
        else:
            A("  => خوب: SNI ناشناس کشته نمی‌شود. whitelist سخت‌گیرانه نیست.")

    d53 = [k for k, v in rep["udp"]["dns53"].items() if v["status"] == "ANSWERED"]
    A("• UDP/53 خارجی: %s" % (", ".join(d53) if d53 else "هیچ‌کدام (بسته)"))
    nonstd = [k for k, v in rep["udp"]["nonstandard"].items() if v["status"] == "ECHOED"]
    A("• UDP باز به VM شما: %s" % (", ".join(nonstd) if nonstd else "هیچ‌کدام"))
    if "53" in nonstd:
        A("  => UDP/53 به VM شما عبور می‌کند! AmneziaWG یا Hysteria2 روی پورت ۵۳ گزینه‌ی بسیار خوبی است.")
    if not nonstd:
        A("  => WireGuard/AmneziaWG/Hysteria روی UDP جواب نمی‌دهد (یا سرور echo اجرا نشده).")

    hij = [d for d, v in rep["dns_hijack"].items() if v.get("hijacked")]
    A("• DNS دستکاری‌شده برای: %s" % (", ".join(hij) if hij else "هیچ‌کدام"))

    A("• بزرگ‌ترین بسته‌ی بدون تکه‌شدن (Path MTU): %s  [%s]"
      % (rep["mtu"].get("max_packet"), rep["mtu"].get("status")))
    A("=" * 72)
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Iran network reachability prober")
    ap.add_argument("--vm-ip", required=True, help="IP عمومی VM خودت")
    ap.add_argument("--domain", required=True, help="دامنه‌ای که روی کلادفلر داری یا می‌سازی")
    ap.add_argument("--udp-port", type=int, default=40000,
                    help="پورت UDP که udp_echo_server.py روی VM گوش می‌دهد")
    ap.add_argument("--out", default="irnet_report.json")
    args = ap.parse_args()

    print("irnet_probe - اندازه‌گیری واقعی وضعیت شبکه")
    print("VM: %s   دامنه: %s" % (args.vm_ip, args.domain))
    print("این کار حدود ۱ تا ۳ دقیقه طول می‌کشد.")
    print("!! مهم: قبل از اجرا فیلترشکن را کامل قطع کنید، وگرنه نتیجه بی‌معنی است. !!")

    rep = run(args.vm_ip, args.domain, args.udp_port)
    s = summarize(rep)
    print("\n" + s)
    rep["summary_text"] = s

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=2)
    print("\nگزارش کامل ذخیره شد در: %s" % os.path.abspath(args.out))
    print("این فایل را برای من بفرست.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nلغو شد.")
