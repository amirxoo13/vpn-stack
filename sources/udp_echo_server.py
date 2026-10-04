#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
udp_echo_server.py  -  روی VM بلژیک اجرا می‌شود
=================================================
هر بسته‌ی UDP که برسد را عینا برمی‌گرداند، تا irnet_probe.py بتواند
بفهمد آیا UDP روی پورت‌های مختلف از مرز ایران عبور می‌کند یا نه.

اجرا روی VM:
    sudo python3 udp_echo_server.py 53 40000 51820 1194

قبلش باید این پورت‌ها در فایروال گوگل کلود باز شده باشند.
روی پورت ۵۳ به‌طور خودکار به IP داخلی bind می‌کند تا با systemd-resolved
تعارض پیدا نکند.

با Ctrl+C متوقف می‌شود.
"""

import socket
import selectors
import sys
import time


def primary_internal_ip():
    """IP داخلی اصلی کارت شبکه را پیدا می‌کند (بدون نیاز به اتصال واقعی)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except Exception:
        return "0.0.0.0"
    finally:
        s.close()


def main():
    args = sys.argv[1:]
    bad = [a for a in args if a.startswith("-")]
    if bad:
        sys.exit("گزینه‌ی ناشناخته: %s\nاستفاده: sudo python3 udp_echo_server.py 53 40000 51820 1194"
                 % " ".join(bad))
    try:
        ports = [int(p) for p in args] or [40000]
    except ValueError:
        sys.exit("پورت باید عدد باشد.\nاستفاده: sudo python3 udp_echo_server.py 53 40000 51820 1194")
    if any(p < 1 or p > 65535 for p in ports):
        sys.exit("پورت باید بین ۱ تا ۶۵۵۳۵ باشد.")
    internal = primary_internal_ip()
    print("[i] IP داخلی شناسایی‌شده: %s" % internal)

    sel = selectors.DefaultSelector()
    socks = []
    for p in ports:
        # روی پورت ۵۳، systemd-resolved روی 127.0.0.53 نشسته است،
        # پس مستقیم به IP داخلی bind می‌کنیم.
        bind_addrs = [internal, "0.0.0.0"] if p == 53 else ["0.0.0.0", internal]
        bound = False
        for addr in bind_addrs:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((addr, p))
            except OSError as e:
                print("[!] bind روی %s:%d ناموفق: %s" % (addr, p, e))
                s.close()
                continue
            bound = True
            break
        if not bound:
            continue
        s.setblocking(False)
        sel.register(s, selectors.EVENT_READ, p)
        socks.append(s)
        print("[+] گوش دادن روی %s:%d/udp" % (s.getsockname()[0], p))

    if not socks:
        print("هیچ پورتی باز نشد. با sudo اجرا کنید.")
        return

    print("[*] آماده. منتظر بسته... (Ctrl+C برای خروج)")
    try:
        while True:
            for key, _ in sel.select(timeout=1.0):
                sock = key.fileobj
                port = key.data
                try:
                    data, addr = sock.recvfrom(4096)
                except OSError:
                    continue
                sock.sendto(data, addr)
                print("[%s] UDP/%d  <- %s:%d  (%d bytes)  %r" % (
                    time.strftime("%H:%M:%S"), port, addr[0], addr[1],
                    len(data), data[:40]))
    except KeyboardInterrupt:
        print("\n[*] خروج.")
    finally:
        for s in socks:
            s.close()


if __name__ == "__main__":
    main()
