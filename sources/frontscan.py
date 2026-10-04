#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
frontscan.py — کدام شبکه‌ی لبه واقعا می‌تواند front شما باشد؟
=============================================================
منطقی که این ابزار بر آن بنا شده:

  در بلک‌اوت ژانویه ۱۴۰۵، حکومت یک «لیست سفید» ساخت و این‌ها را باز گذاشت:
  گوگل سرچ، جی‌میل، Google Meet، Outlook، Play Store، App Store، اپل،
  سامسونگ، ChatGPT، GitHub، PlayStation، Google Maps.

  مقاوم‌ترین front آن شبکه‌ی لبه‌ای است که همین سرویس‌ها روی آن سوارند،
  چون بستن آن لبه، لیست سفید خودشان را می‌شکند.

این ابزار برای هر لبه دو چیز جدا را می‌سنجد:

  ۱) SNI سرویس   — آیا آن لبه با SNIِ سرویس معروفش زنده است؟
                    (یعنی خود لبه از خط تو در دسترس است)
  ۲) SNI دلخواه  — آیا با یک SNI ناشناس هم هندشیک کامل می‌شود؟
                    (یعنی تو می‌توانی دامنه‌ی خودت را روی آن لبه ببری)

فقط وقتی هر دو سبز باشند، آن لبه به‌عنوان front به کار تو می‌آید.

فقط کتابخانه‌ی استاندارد پایتون.

    python frontscan.py
    python frontscan.py --mydomain cdn.amirxo.com

!! با فیلترشکن قطع اجرا کن. !!
"""

import argparse
import concurrent.futures as cf
import json
import random
import socket
import ssl
import sys
import time

# ---------------------------------------------------------------------------
# لبه‌ها. IPها anycast و پایدارند.
#   proxyable = آیا این لبه می‌تواند به سرور دلخواه تو reverse-proxy کند؟
# ---------------------------------------------------------------------------
FRONTS = [
    # نام,                    IPها,                              SNI سرویس,                  سرویس لیست‌سفید,        proxyable
    ("cloudflare",            ["104.18.32.47", "172.64.150.28",
                               "104.16.132.229", "188.114.96.3"], "chatgpt.com",              "ChatGPT",              True),
    ("google-frontend",       ["216.239.36.21", "173.194.210.121",
                               "216.239.38.21"],                  "ghs.googlehosted.com",     "Gmail / Play Store",   True),
    ("firebase-hosting",      ["199.36.158.100", "199.36.158.99"], "firebaseapp.com",         "روی زیرساخت گوگل",      True),
    ("gcp-global-lb",         ["34.117.59.81", "34.149.100.209"],  "www.google.com",          "زیرساخت خود گوگل",      True),
    ("fastly",                ["151.101.66.10", "199.232.194.10"], "www.fastly.com",          "بخشی از GitHub",        True),
    ("azure-front-door",      ["13.107.246.45", "13.107.213.45"],  "azure.microsoft.com",     "Outlook / مایکروسافت",  True),
    ("aws-cloudfront",        ["108.138.7.30", "18.160.10.30"],    "d1234.cloudfront.net",    "—",                    True),
    ("akamai",                ["23.222.157.180", "23.50.48.10"],   "www.apple.com",           "App Store / اپل",       True),
    # این یکی فقط برای اطلاع — GitHub Pages ایستا است و نمی‌تواند پروکسی کند
    ("github-pages",          ["185.199.110.153", "185.199.111.153"], "github.io",            "GitHub",               False),
    ("github-main",           ["140.82.112.3", "140.82.113.3"],    "github.com",              "GitHub",               False),
]

CONNECT_TO = 4.0
TLS_TO = 7.0


def classify(e):
    if isinstance(e, socket.timeout):
        return "TIMEOUT"
    if isinstance(e, ConnectionResetError):
        return "RST"
    if isinstance(e, ConnectionRefusedError):
        return "REFUSED"
    if isinstance(e, ssl.SSLError):
        r = getattr(e, "reason", None) or ""
        if "HANDSHAKE_FAILURE" in r or "UNRECOGNIZED_NAME" in r:
            return "SNI-REJECT"      # خود لبه رد کرد، نه DPI
        return "TLS:" + (r or "ERR")
    if isinstance(e, OSError):
        return "OSERR"
    return type(e).__name__


def probe(ip, sni, port=443):
    """یک (IP, SNI) را می‌سنجد."""
    out = {"ip": ip, "sni": sni, "tcp": None, "tls": None, "ms": None}
    t0 = time.monotonic()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(CONNECT_TO)
    try:
        s.connect((ip, port))
        out["tcp"] = "OPEN"
        out["ms"] = round((time.monotonic() - t0) * 1000, 1)
    except Exception as e:
        out["tcp"] = classify(e)
        out["tls"] = "-"
        s.close()
        return out

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    try:
        s.settimeout(TLS_TO)
        ss = ctx.wrap_socket(s, server_hostname=sni)
        out["tls"] = "OK"
        out["ver"] = ss.version()
        ss.close()
    except Exception as e:
        out["tls"] = classify(e)
    finally:
        try:
            s.close()
        except Exception:
            pass
    return out


def best(results):
    """از چند IP، بهترین نتیجه را برمی‌گرداند."""
    ok = [r for r in results if r["tls"] == "OK"]
    if ok:
        return min(ok, key=lambda r: r["ms"])
    opened = [r for r in results if r["tcp"] == "OPEN"]
    if opened:
        return min(opened, key=lambda r: r["ms"])
    return results[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mydomain", default="cdn.amirxo.com",
                    help="دامنه‌ی خودت — برای تست SNI دلخواه استفاده می‌شود")
    ap.add_argument("--out", default="frontscan_result.json")
    args = ap.parse_args()

    rnd = "assets-%08x.example.net" % random.getrandbits(32)

    print("\nfrontscan — کدام لبه می‌تواند front تو باشد؟")
    print("SNI دلخواه که تست می‌شود: %s  و  %s" % (args.mydomain, rnd))
    print("!! فیلترشکن باید قطع باشد. !!\n")

    jobs = []
    for name, ips, svc_sni, _, _ in FRONTS:
        for ip in ips:
            jobs.append((name, ip, svc_sni, "service"))
            jobs.append((name, ip, args.mydomain, "mydomain"))
            jobs.append((name, ip, rnd, "random"))

    raw = {}
    with cf.ThreadPoolExecutor(max_workers=60) as ex:
        futs = {ex.submit(probe, ip, sni): (name, kind, ip) for name, ip, sni, kind in jobs}
        done = 0
        for f in cf.as_completed(futs):
            name, kind, ip = futs[f]
            done += 1
            try:
                r = f.result()
            except Exception:
                continue
            raw.setdefault(name, {}).setdefault(kind, []).append(r)
            sys.stdout.write("\r  بررسی‌شده %d/%d" % (done, len(jobs)))
            sys.stdout.flush()
    print("\n")

    hdr = "%-20s %-11s %-13s %-13s %-9s %s" % (
        "لبه", "خودِ لبه", "SNI سرویس", "SNI دلخواه", "تاخیر", "حکم")
    print(hdr)
    print("-" * 96)

    report = {}
    usable = []
    for name, ips, svc_sni, whitelisted, proxyable in FRONTS:
        g = raw.get(name, {})
        b_svc = best(g.get("service", [{"tcp": "?", "tls": "?", "ms": None}]))
        b_mine = best(g.get("mydomain", [{"tcp": "?", "tls": "?", "ms": None}]))
        b_rnd = best(g.get("random", [{"tcp": "?", "tls": "?", "ms": None}]))

        edge_up = b_svc["tcp"] == "OPEN" or b_mine["tcp"] == "OPEN"
        svc_ok = b_svc["tls"] == "OK"
        # SNI دلخواه: اگر دامنه‌ی خودت یا یک SNI تصادفی هندشیک شد، یعنی
        # DPI آن لبه را با SNI ناشناس نمی‌کشد
        arb_ok = b_mine["tls"] == "OK" or b_rnd["tls"] == "OK"
        arb_killed = "RST" in (b_mine["tls"], b_rnd["tls"])

        if not edge_up:
            verdict = "لبه بسته است"
        elif not proxyable:
            verdict = "قابل استفاده نیست (ایستا، پروکسی نمی‌کند)"
        elif arb_killed:
            verdict = "لبه باز، ولی DPI SNI ناشناس را می‌کشد"
        elif arb_ok:
            verdict = "قابل استفاده به عنوان front"
            usable.append((name, b_mine["ms"] or b_rnd["ms"] or 9999,
                           best(g.get("mydomain") or g.get("random"))["ip"]))
        elif b_mine["tls"] == "SNI-REJECT" and b_rnd["tls"] == "SNI-REJECT":
            verdict = "لبه باز؛ باید اول دامنه را روی آن ثبت کنی"
        else:
            verdict = "نامشخص — %s" % b_mine["tls"]

        ms = b_svc["ms"] if b_svc["ms"] else b_mine["ms"]
        print("%-20s %-11s %-13s %-13s %-9s %s" % (
            name,
            "باز" if edge_up else "بسته",
            b_svc["tls"],
            b_mine["tls"] if b_mine["tls"] != "OK" else "OK",
            ("%.0f ms" % ms) if ms else "-",
            verdict))

        report[name] = {
            "whitelisted_service": whitelisted, "proxyable": proxyable,
            "edge_up": edge_up, "service_sni": b_svc, "my_sni": b_mine,
            "random_sni": b_rnd, "verdict": verdict,
        }

    print("\n" + "=" * 96)
    if usable:
        usable.sort(key=lambda t: t[1])
        print("frontهای قابل استفاده، به ترتیب سرعت:")
        for n, ms, ip in usable:
            svc = next(f[3] for f in FRONTS if f[0] == n)
            print("   %-20s %-16s %6.0f ms    (حامل: %s)" % (n, ip, ms, svc))
        print("\nاولویت را در کانفیگ failover به همین ترتیب بگذار.")
    else:
        print("هیچ لبه‌ای به‌عنوان front قابل استفاده نیست. چند دقیقه بعد دوباره امتحان کن.")
    print("=" * 96)
    print("یادآوری: github-pages و github-main فقط برای مرجع تست می‌شوند —")
    print("ایستا هستند و نمی‌توانند به سرور تو پروکسی کنند.\n")

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"mydomain": args.mydomain, "random_sni": rnd,
                   "generated_at": time.strftime("%Y-%m-%d %H:%M:%S %z"),
                   "fronts": report,
                   "usable_sorted": [{"front": n, "ms": m, "ip": i} for n, m, i in usable]},
                  f, ensure_ascii=False, indent=2)
    print("گزارش کامل در %s ذخیره شد.\n" % args.out)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nلغو شد.")
