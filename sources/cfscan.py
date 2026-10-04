#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cfscan.py  —  پیدا کردن سریع‌ترین IP کلادفلر برای خط اینترنت شما
================================================================
چرا لازم است:
  ۱) DNS خط شما دستکاری شده (همه چیز به 10.10.34.36 می‌رود). اگر در کلاینت
     به‌جای دامنه، مستقیم یک IP کلادفلر بگذاریم، DNS کلا از مسیر حذف می‌شود.
  ۲) کلادفلر صدها هزار IP دارد و سرعتشان از ایران بسیار متفاوت است.
     تفاوت بین بهترین و بدترین IP می‌تواند چند برابر باشد.

کلادفلر بر اساس SNI/Host مسیریابی می‌کند، نه IP. پس هر IP کلادفلر
دامنه‌ی شما را سرو می‌کند و می‌توانیم سریع‌ترین را انتخاب کنیم.

فقط کتابخانه‌ی استاندارد پایتون. هیچ pip install لازم نیست.

--- استفاده ---
مرحله‌ی اول (قبل از این‌که سرور بالا بیاید) — فقط سرعت اتصال و TLS:
    python cfscan.py --sni cdn.amirxo.com --count 300

مرحله‌ی دوم (بعد از این‌که سرور بالا آمد) — سرعت واقعی سرتاسری:
    python cfscan.py --sni cdn.amirxo.com --count 300 --download

!! با فیلترشکن قطع اجرا کن. !!
"""

import argparse
import concurrent.futures as cf
import ipaddress
import json
import random
import socket
import ssl
import sys
import time

# رنج‌های رسمی IPv4 کلادفلر (cloudflare.com/ips-v4)
CF_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]


def sample_ips(n, ranges=None):
    """از رنج‌های کلادفلر به‌طور تصادفی n آدرس انتخاب می‌کند."""
    nets = [ipaddress.ip_network(c) for c in (ranges or CF_RANGES)]
    weights = [net.num_addresses for net in nets]
    total = sum(weights)
    out = set()
    guard = 0
    while len(out) < n and guard < n * 50:
        guard += 1
        r = random.randrange(total)
        acc = 0
        for net, w in zip(nets, weights):
            acc += w
            if r < acc:
                # اولین و آخرین آدرس شبکه را رد کن
                off = random.randrange(1, max(2, net.num_addresses - 1))
                out.add(str(net.network_address + off))
                break
    return list(out)


def make_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # برای اندازه‌گیری، HTTP/1.1 لازم است — با h2 نمی‌توان درخواست متنی فرستاد
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


CTX = make_ctx()


def test_ip(ip, sni, port=443, connect_to=2.5, tls_to=4.0,
            download=False, dl_path="/assets/sprite.bin", dl_to=6.0):
    """
    یک IP را می‌سنجد. برمی‌گرداند dict یا None اگر ناموفق بود.
      tcp_ms  : زمان برقراری اتصال TCP
      tls_ms  : زمان هندشیک TLS (نشانه‌ی خوبی از کیفیت مسیر)
      ttfb_ms : زمان رسیدن اولین بایت پاسخ HTTP
      kbps    : سرعت دانلود واقعی (فقط با --download)
    """
    res = {"ip": ip}
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(connect_to)
    t0 = time.monotonic()
    try:
        s.connect((ip, port))
    except Exception:
        s.close()
        return None
    res["tcp_ms"] = round((time.monotonic() - t0) * 1000, 1)

    try:
        s.settimeout(tls_to)
        t1 = time.monotonic()
        ss = CTX.wrap_socket(s, server_hostname=sni)
        res["tls_ms"] = round((time.monotonic() - t1) * 1000, 1)
        res["alpn"] = ss.selected_alpn_protocol() or "-"
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return None

    try:
        path = dl_path if download else "/"
        req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
               "Accept: */*\r\nConnection: close\r\n\r\n" % (path, sni))
        ss.settimeout(dl_to if download else tls_to)
        t2 = time.monotonic()
        ss.sendall(req.encode())
        first = ss.recv(4096)
        res["ttfb_ms"] = round((time.monotonic() - t2) * 1000, 1)
        try:
            res["status"] = int(first.split(b" ")[1])
        except Exception:
            res["status"] = 0
        total = len(first)
        if download:
            while True:
                b = ss.recv(65536)
                if not b:
                    break
                total += len(b)
                if time.monotonic() - t2 > dl_to:
                    break
            dur = max(time.monotonic() - t2, 0.001)
            res["bytes"] = total
            res["kbps"] = round(total / 1024 / dur, 1)
    except Exception as e:
        res["http_err"] = type(e).__name__
    finally:
        try:
            ss.close()
        except Exception:
            pass
    return res


def main():
    ap = argparse.ArgumentParser(description="Cloudflare IP scanner")
    ap.add_argument("--sni", default="cdn.amirxo.com",
                    help="دامنه‌ای که در SNI و Host فرستاده می‌شود")
    ap.add_argument("--count", type=int, default=300, help="چند IP تست شود")
    ap.add_argument("--workers", type=int, default=100)
    ap.add_argument("--top", type=int, default=12, help="چند نتیجه‌ی برتر چاپ شود")
    ap.add_argument("--download", action="store_true",
                    help="سرعت دانلود واقعی را هم اندازه بگیر (بعد از راه‌اندازی سرور)")
    ap.add_argument("--dl-path", default="/assets/sprite.bin",
                    help="فایلی روی سرور برای تست دانلود")
    ap.add_argument("--out", default="cfscan_result.json")
    args = ap.parse_args()

    print("cfscan — جست‌وجوی سریع‌ترین IP کلادفلر")
    print("SNI/Host: %s     تعداد IP: %d     حالت: %s"
          % (args.sni, args.count, "دانلود واقعی" if args.download else "اتصال و TLS"))
    print("!! فیلترشکن باید قطع باشد. !!\n")

    ips = sample_ips(args.count)
    good = []
    done = 0
    t0 = time.monotonic()
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(test_ip, ip, args.sni, 443, 2.5, 4.0,
                          args.download, args.dl_path) for ip in ips]
        for f in cf.as_completed(futs):
            done += 1
            try:
                r = f.result()
            except Exception:
                r = None
            if r and "tls_ms" in r:
                good.append(r)
            if done % 25 == 0 or done == len(futs):
                sys.stdout.write("\r  بررسی‌شده %d/%d   موفق %d   (%.0fs)"
                                 % (done, len(futs), len(good), time.monotonic() - t0))
                sys.stdout.flush()
    print("\n")

    if not good:
        print("هیچ IPی جواب نداد. یعنی یا اینترنت قطع است، یا کلادفلر روی خط شما")
        print("در این لحظه مسدود است. چند دقیقه بعد دوباره امتحان کن.")
        return

    if args.download:
        good.sort(key=lambda r: -r.get("kbps", 0))
        hdr = "%-17s %8s %8s %9s %11s %6s %5s" % (
            "IP", "tcp(ms)", "tls(ms)", "ttfb(ms)", "speed(KB/s)", "alpn", "http")
        row = lambda r: "%-17s %8.1f %8.1f %9.1f %11s %6s %5s" % (
            r["ip"], r["tcp_ms"], r["tls_ms"], r.get("ttfb_ms", -1),
            r.get("kbps", "-"), r.get("alpn", "-"), r.get("status", "-"))
    else:
        good.sort(key=lambda r: (r["tls_ms"] + r["tcp_ms"]))
        hdr = "%-17s %8s %8s %9s %6s %5s" % (
            "IP", "tcp(ms)", "tls(ms)", "ttfb(ms)", "alpn", "http")
        row = lambda r: "%-17s %8.1f %8.1f %9.1f %6s %5s" % (
            r["ip"], r["tcp_ms"], r["tls_ms"], r.get("ttfb_ms", -1),
            r.get("alpn", "-"), r.get("status", "-"))

    print("%d IP از %d پاسخ داد. بهترین‌ها:\n" % (len(good), len(ips)))
    print(hdr)
    print("-" * len(hdr))
    for r in good[:args.top]:
        print(row(r))

    best = good[0]["ip"]
    print("\n" + "=" * 68)
    print("بهترین IP: %s" % best)
    print("این IP را در کلاینت به‌عنوان «آدرس سرور» بگذار و")
    print("SNI و Host را روی %s نگه دار." % args.sni)
    print("چون DNS خط تو دستکاری شده، این کار DNS را کامل از مسیر حذف می‌کند.")
    print("=" * 68)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"sni": args.sni, "download_mode": args.download,
                   "tested": len(ips), "responded": len(good),
                   "results": good[:50]}, f, ensure_ascii=False, indent=2)
    print("\nنتیجه‌ی کامل در %s ذخیره شد." % args.out)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nلغو شد.")
