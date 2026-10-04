#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
leaktest.py  —  تست واقعی لیک IP و DNS
=======================================
این را **وقتی به تونل وصل هستی** اجرا کن. خودش هیچ پروکسی‌ای ست نمی‌کند؛
از مسیریابی واقعی سیستم استفاده می‌کند، پس همان چیزی را می‌سنجد که
مرورگرت تجربه می‌کند.

چه چیزی را چک می‌کند:
  ۱) IPv4ی که دنیا از تو می‌بیند، و کشورش
  ۲) IPv6 — علت شماره یک لیک. سرور تو IPv6 ندارد، پس اگر IPv6 جواب بدهد
     یعنی آن ترافیک از کنار تونل رد می‌شود و IP واقعی‌ات لو می‌رود
  ۳) کدام resolver واقعا پرس‌وجوهای DNS تو را می‌بیند (تست لیک DNS)
  ۴) آیا DNS دستکاری‌شده‌ی ایران هنوز فعال است (جواب 10.10.34.x)
  ۵) آیا دامنه‌های مسدود الان واقعا باز شده‌اند

اجرا:
    python leaktest.py
    python leaktest.py --expect BE        # کشور سرورت
"""

import argparse
import json
import os
import socket
import ssl
import sys
import urllib.request

TIMEOUT = 12

# opener که متغیرهای محیطی پروکسی را نادیده می‌گیرد،
# تا واقعا مسیریابی سیستم سنجیده شود
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_OPENER.addheaders = [("User-Agent", "Mozilla/5.0 leaktest")]

G = "\033[0;32m"; R = "\033[0;31m"; Y = "\033[1;33m"; B = "\033[0;34m"; N = "\033[0m"
if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        G = R = Y = B = N = ""

PASS = 0
FAIL = 0
TRANSPORT = 0
INCONCLUSIVE = 0


def verdict(good, label, detail=""):
    global PASS, FAIL
    if good:
        PASS += 1
        print(f"  {G}[سالم]{N} {label}" + (f"  — {detail}" if detail else ""))
    else:
        FAIL += 1
        print(f"  {R}[لیک]{N}  {label}" + (f"  — {detail}" if detail else ""))


def transport_error(label, detail=""):
    """خطای شبکه، نه ناسازگاری کشور. جدا از لیک شمرده می‌شود."""
    global TRANSPORT
    TRANSPORT += 1
    print(f"  {Y}[خطای انتقال]{N} {label}" + (f"  — {detail}" if detail else ""))


def inconclusive(label, detail=""):
    global INCONCLUSIVE
    INCONCLUSIVE += 1
    print(f"  {Y}[نامشخص]{N} {label}" + (f"  — {detail}" if detail else ""))


def note(label, detail=""):
    print(f"  {B}[اطلاع]{N} {label}" + (f"  — {detail}" if detail else ""))


def get(url, timeout=TIMEOUT, family=None):
    """یک GET ساده. family=socket.AF_INET6 اتصال را به IPv6 مجبور می‌کند."""
    orig = socket.getaddrinfo
    if family:
        def only(host, port, f=0, t=0, p=0, fl=0):
            return orig(host, port, family, t, p, fl)
        socket.getaddrinfo = only
    try:
        with _OPENER.open(url, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace").strip()
    finally:
        if family:
            socket.getaddrinfo = orig


def ip_geo(ip):
    """کشور و سازمان یک IP. اگر سرویس جواب نداد، None."""
    for url in ("https://ipinfo.io/%s/json" % ip,
                "https://ipapi.co/%s/json/" % ip):
        try:
            d = json.loads(get(url, timeout=8))
            return {
                "country": d.get("country") or d.get("country_code") or "?",
                "org": d.get("org") or d.get("asn") or d.get("org_name") or "?",
                "city": d.get("city") or "?",
            }
        except Exception:
            continue
    return None


def ptr(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def tls_reachable(host, port=443, timeout=10):
    """
    آیا می‌توان با این دامنه هندشیک TLS کامل و *معتبر* کرد؟

    گواهی را تأیید می‌کنیم. اگر این کار را نکنیم، صفحه‌ی مسدودی ایران هم
    یک هندشیک موفق می‌دهد و تست به اشتباه «سالم» نشان می‌دهد.
    برمی‌گرداند (ok, detail, ip)
    """
    ctx = ssl.create_default_context()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    ip = None
    try:
        s.connect((host, port))
        ip = s.getpeername()[0]
        if ip.startswith(("10.10.34.", "10.10.35.")):
            return False, "به صفحه‌ی مسدودی ایران وصل شد", ip
        ss = ctx.wrap_socket(s, server_hostname=host)
        v = ss.version()
        ss.close()
        return True, v, ip
    except ssl.SSLCertVerificationError as e:
        return False, "گواهی تأیید نشد (%s)" % e.verify_message, ip
    except Exception as e:
        return False, type(e).__name__, ip
    finally:
        try:
            s.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--expect", default="BE",
                    help="کد کشور سرورت، مثلا BE برای بلژیک")
    ap.add_argument("--out", default="leaktest_report.json",
                    help="فایل گزارش. با رشته‌ی خالی ذخیره نمی‌شود.")
    args = ap.parse_args()

    report = {"expect": args.expect.upper()}

    print("\nleaktest — تست لیک IP و DNS")
    print("این تست را وقتی به تونل وصل هستی اجرا کن.\n")

    # ---------------------------------------------------------------- ۱) IPv4
    print("── ۱) آدرس IPv4ی که دنیا از تو می‌بیند ──")
    my4 = None
    try:
        trace = get("https://www.cloudflare.com/cdn-cgi/trace")
        kv = dict(l.split("=", 1) for l in trace.splitlines() if "=" in l)
        my4 = kv.get("ip")
        loc = kv.get("loc", "?")
        note("IP دیده‌شده", my4)
        note("کشور طبق کلادفلر", loc)
        note("نزدیک‌ترین دیتاسنتر کلادفلر", kv.get("colo", "?"))
        verdict(loc.upper() == args.expect.upper(),
                "کشور IP خروجی",
                "انتظار %s بود، %s دیده شد" % (args.expect.upper(), loc.upper()))
        if loc.upper() == "IR":
            print(f"  {R}>>> ترافیک تو از تونل عبور نمی‌کند. تونل وصل نیست یا مسیریابی اشتباه است.{N}")
        report["egress"] = {"ip": my4, "loc": loc, "colo": kv.get("colo")}
    except Exception as e:
        transport_error("دریافت trace از کلادفلر ناموفق", type(e).__name__)
        report["egress"] = {"error": type(e).__name__, "kind": "transport"}

    if not my4:
        try:
            my4 = get("https://api.ipify.org")
            note("IP دیده‌شده (ipify)", my4)
        except Exception:
            pass

    if my4:
        g = ip_geo(my4)
        if g:
            note("سازمان این IP", "%s / %s / %s" % (g["country"], g["city"], g["org"]))

    # ---------------------------------------------------------------- ۲) IPv6
    print("\n── ۲) IPv6 (علت شماره یک لیک) ──")
    # آیا سیستم آدرس IPv6 عمومی دارد؟
    globals6 = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6):
            a = info[4][0].split("%")[0]
            if not (a.startswith("fe80") or a.startswith("::1") or a.startswith("fd")):
                globals6.append(a)
    except Exception:
        pass
    if globals6:
        note("آدرس IPv6 عمومی روی کارت شبکه", ", ".join(sorted(set(globals6))))

    v6_leak = False
    v6_ip = None
    try:
        v6_ip = get("https://api6.ipify.org", timeout=10, family=socket.AF_INET6)
        if v6_ip and ":" in v6_ip:
            v6_leak = True
    except Exception:
        pass
    if v6_leak:
        verdict(False, "ترافیک IPv6 از کنار تونل رد می‌شود", "IPv6 دیده‌شده: %s" % v6_ip)
        g6 = ip_geo(v6_ip)
        if g6:
            note("این IPv6 مال کیست", "%s / %s" % (g6["country"], g6["org"]))
        print(f"  {Y}>>> راه حل: IPv6 را در کلاینت و در کارت شبکه ویندوز غیرفعال کن.{N}")
        print(f"  {Y}    سرور تو IPv6 ندارد، پس هر سایت IPv6-دار IP واقعی‌ات را می‌بیند.{N}")
    else:
        verdict(True, "IPv6 نشتی ندارد", "اتصال IPv6 برقرار نشد — همین درست است")
    report["ipv6"] = {"leak": v6_leak, "ip": v6_ip,
                      "local_global_addrs": sorted(set(globals6))}

    # -------------------------------------------------------------- ۳) لیک DNS
    print("\n── ۳) کدام resolver پرس‌وجوهای تو را می‌بیند؟ ──")
    # whoami.akamai.net آدرس IP همان resolverی را برمی‌گرداند که از او پرسیده
    resolver_ip = None
    try:
        resolver_ip = socket.gethostbyname("whoami.akamai.net")
        note("IP رزولور واقعی تو", resolver_ip)
        p = ptr(resolver_ip)
        if p:
            note("نام معکوس رزولور", p)
        gr = ip_geo(resolver_ip)
        if gr:
            note("سازمان رزولور", "%s / %s" % (gr["country"], gr["org"]))
            is_ir = gr["country"].upper() == "IR"
            verdict(not is_ir, "محل رزولور DNS",
                    "در %s است%s" % (gr["country"],
                                     " — پرس‌وجوهای تو را ISP ایران می‌بیند" if is_ir else ""))
            if is_ir:
                print(f"  {Y}>>> راه حل: در کلاینت «Remote DNS» را روی https://1.1.1.1/dns-query{N}")
                print(f"  {Y}    بگذار و domainStrategy را AsIs کن تا سرور نام‌ها را حل کند.{N}")
        else:
            note("جغرافیای رزولور قابل تشخیص نبود",
                 "خودت IP بالا را در ipinfo.io چک کن")
        report["resolver"] = {"ip": resolver_ip, "ptr": ptr(resolver_ip), "geo": gr}
    except Exception as e:
        note("تست رزولور ناموفق", type(e).__name__)
        report["resolver"] = {"error": type(e).__name__}

    # --------------------------------------------- ۴) DNS دستکاری‌شده‌ی ایران
    print("\n── ۴) آیا DNS دستکاری‌شده هنوز فعال است؟ ──")
    hijack = []
    clean = []
    errors = []
    for d in ("www.youtube.com", "twitter.com", "www.bbc.com"):
        try:
            ips = sorted({i[4][0] for i in socket.getaddrinfo(d, 443, socket.AF_INET)})
            bad = [i for i in ips if i.startswith(("10.10.34.", "10.10.35."))]
            if bad:
                hijack.append((d, ips))
            else:
                clean.append((d, ips))
            note(d, ", ".join(ips))
        except Exception as e:
            errors.append(d)
            note(d, "خطا: %s" % type(e).__name__)
    if hijack:
        verdict(False, "پاسخ‌های DNS سالم",
                "دستکاری‌شده: " + ", ".join(d for d, _ in hijack))
    elif not clean:
        inconclusive("پاسخ‌های DNS سالم",
                     "همه‌ی پرس‌وجوها خطا دادند؛ سالم بودن تأیید نشد")
    else:
        verdict(True, "پاسخ‌های DNS سالم", "هیچ پاسخی به 10.10.34.x نرفت")
    report["dns"] = {"hijacked": dict(hijack), "clean": dict(clean), "errors": errors}

    # ------------------------------------- ۵) آیا سایت‌های مسدود باز شده‌اند؟
    print("\n── ۵) آیا دامنه‌های مسدود واقعا باز شده‌اند؟ ──")
    reach = {}
    for d in ("www.youtube.com", "twitter.com"):
        okc, info, rip = tls_reachable(d)
        reach[d] = {"ok": okc, "detail": str(info), "ip": rip}
        verdict(okc, "هندشیک TLS معتبر با %s" % d,
                "%s%s" % (info, "  [%s]" % rip if rip else ""))

    # ------------------------------------------------------------------ نتیجه
    report["blocked_sites"] = reach
    report["summary"] = {"pass": PASS, "fail": FAIL,
                         "transport_error": TRANSPORT, "inconclusive": INCONCLUSIVE}

    print("\n" + "=" * 62)
    if FAIL == 0 and TRANSPORT == 0 and INCONCLUSIVE == 0:
        print(f"{G}نتیجه: {PASS} تست سالم، هیچ لیکی پیدا نشد.{N}")
    elif FAIL == 0:
        print(f"{Y}نتیجه: لیک قطعی نیست، ولی {INCONCLUSIVE} مورد نامشخص و {TRANSPORT} خطای انتقال هست.{N}")
    else:
        print(f"{R}نتیجه: {FAIL} مورد مشکل‌دار، {PASS} مورد سالم.{N}")
        print("راه‌حل هر مورد بالای همان بخش نوشته شده.")
    print("=" * 62)
    print("تأیید نهایی را در مرورگر هم بگیر:")
    print("  ipleak.net                      — IP و DNS و WebRTC")
    print("  browserleaks.com/webrtc         — لیک WebRTC")
    print("  dnsleaktest.com  (Extended)     — همه‌ی رزولورها")
    print("در ipleak.net بخش DNS باید فقط کلادفلر یا گوگل نشان بدهد، هیچ ISP ایرانی.\n")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print("گزارش در %s ذخیره شد.\n" % os.path.abspath(args.out))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nلغو شد.")
