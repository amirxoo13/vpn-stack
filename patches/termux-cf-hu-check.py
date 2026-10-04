#!/usr/bin/env python3
"""Termux check for one HTTPUpgrade path.

Checks DNS, TCP on the edge port, TLS with ALPN http/1.1, and the
HTTPUpgrade status line. It does not send a VLESS UUID, so it cannot
prove login.

The domain, port and path have no safe default: pass them in.

    python3 termux-cf-hu-check.py --domain cdn.example.com --port 8443 --path /yourpath
"""

import argparse
import base64
import json
import os
import re
import socket
import ssl
import subprocess
import time
from datetime import datetime

TIMEOUT = 8

# Edge addresses to try. Any address inside the Cloudflare ranges below is
# also accepted by the range check.
DEFAULT_EDGE_IPS = ["188.114.97.3", "188.114.96.3", "188.114.97.11", "188.114.96.11"]
CF_NETS = [
    ("188.114.96.0", 20),
    ("104.16.0.0", 13),
    ("104.24.0.0", 14),
    ("172.64.0.0", 13),
    ("162.158.0.0", 15),
    ("108.162.192.0", 18),
    ("173.245.48.0", 20),
    ("103.21.244.0", 22),
    ("103.22.200.0", 22),
    ("103.31.4.0", 22),
    ("141.101.64.0", 18),
    ("190.93.240.0", 20),
    ("197.234.240.0", 22),
    ("198.41.128.0", 17),
    ("131.0.72.0", 22),
]

DNS_SERVERS = [
    ("Cloudflare", "1.1.1.1"),
    ("Google", "8.8.8.8"),
    ("Quad9", "9.9.9.9"),
    ("AliDNS", "223.5.5.5"),
]


def title(text):
    print("\n" + "=" * 72)
    print(text)
    print("=" * 72)


def run(cmd, timeout=12):
    if not cmd or shutil_which(cmd[0]) is None:
        return 127, "MISSING TOOL: %s" % (cmd[0] if cmd else "?")
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=timeout)
        return p.returncode, p.stdout.strip()
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"
    except Exception as e:
        return 1, str(e)


def shutil_which(name):
    for folder in os.environ.get("PATH", "").split(":"):
        path = os.path.join(folder, name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def ip4_to_int(ip):
    parts = [int(x) for x in ip.split(".")]
    if len(parts) != 4 or any(x < 0 or x > 255 for x in parts):
        raise ValueError(ip)
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def in_cf(ip):
    if ":" in ip:
        return False
    try:
        n = ip4_to_int(ip)
    except ValueError:
        return False
    for base, bits in CF_NETS:
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        if (n & mask) == (ip4_to_int(base) & mask):
            return True
    return False


def tools():
    title("0. TOOLS")
    for name in ("python3", "nslookup", "curl", "ping", "ip"):
        print("%-12s %s" % (name, shutil_which(name) or "NOT INSTALLED"))


def interfaces():
    title("1. IS A VPN ALREADY UP?")
    _code, out = run(["ip", "addr"], timeout=5)
    print(out or "no ip output")
    # match interface names only, not any occurrence of "tun" in the output
    names = re.findall(r"^\d+:\s+([^:@]+)", out, re.M)
    tunnels = [n for n in names if re.match(r"(tun|tap|wg|utun)\d*$", n.strip())]
    if tunnels:
        print("[WARN] tunnel interface(s) %s exist. Stop the VPN, then run this again."
              % ", ".join(tunnels))
    else:
        print("[PASS] no tun/wg interface seen")
    return names


def dns(domain, port):
    title("2. DNS")
    found = {}
    try:
        infos = socket.getaddrinfo(domain, port, type=socket.SOCK_STREAM)
        ips = sorted(set(x[4][0] for x in infos))
        print("system:", ", ".join(ips) or "none")
        found["system"] = ips
    except Exception as e:
        print("[FAIL] system resolver:", e)
        found["system"] = []
    for name, server in DNS_SERVERS:
        _code, out = run(["nslookup", domain, server], timeout=7)
        ips = []
        for line in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if m and m.group(1) != server:
                ips.append(m.group(1))
        ips = list(dict.fromkeys(ips))
        found[name] = ips
        print("%-12s %s" % (name, ", ".join(ips) if ips else "NO IPv4"))
    print("\nCloudflare-range check:")
    for name, ips in found.items():
        v4 = [x for x in ips if ":" not in x]
        if not v4:
            print("  %-12s NO IPv4" % name)
        elif all(in_cf(x) for x in v4):
            print("  %-12s PASS  %s" % (name, ", ".join(v4)))
        else:
            print("  %-12s FAIL  %s" % (name, ", ".join(v4)))
    return found


def tcp(ip, port):
    started = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.connect((ip, port))
        return True, (time.perf_counter() - started) * 1000, ""
    except Exception as e:
        return False, (time.perf_counter() - started) * 1000, str(e)
    finally:
        sock.close()


def upgrade(ip, domain, port, path):
    title("3. TCP + TLS + HTTPUpgrade  %s" % ip)
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(TIMEOUT)
    try:
        started = time.perf_counter()
        raw.connect((ip, port))
        tcp_ms = (time.perf_counter() - started) * 1000
        print("[PASS] TCP/%d  %.0f ms" % (port, tcp_ms))
        tls = ctx.wrap_socket(raw, server_hostname=domain)
        print("[PASS] TLS %s  ALPN %s" % (tls.version(), tls.selected_alpn_protocol()))
        cert = tls.getpeercert()
        names = []
        for item in cert.get("subjectAltName", []):
            if item[0] == "DNS":
                names.append(item[1])
        print("cert names:", ", ".join(names) or "none")
        if domain not in names:
            print("[WARN] certificate has no DNS name %s" % domain)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "\r\n"
        ) % (path, domain, key)
        tls.sendall(req.encode())
        data = tls.recv(4096)
        text = data.decode("utf-8", errors="replace")
        first = text.splitlines()[0] if text else "EMPTY"
        print("status:", first)
        print(text[:800])
        if first.startswith("HTTP/1.1 101"):
            print("[PASS] HTTPUpgrade accepted. This still does not prove the UUID.")
            return "101"
        print("[FAIL] expected HTTP/1.1 101, got this status")
        return first or "EMPTY"
    except Exception as e:
        print("[FAIL]", e)
        return "ERROR"
    finally:
        try:
            raw.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser(description="HTTPUpgrade edge check")
    ap.add_argument("--domain", required=True, help="your Cloudflare-proxied hostname")
    ap.add_argument("--path", required=True, help="the HTTPUpgrade path, e.g. /abc123")
    ap.add_argument("--port", type=int, default=8443,
                    help="Cloudflare edge port (default 8443)")
    ap.add_argument("--ip", action="append", default=[],
                    help="edge IP to test; repeatable. Defaults to a built-in list "
                         "plus whatever DNS returns for --domain.")
    ap.add_argument("--out", default="", help="write a JSON report to this file")
    args = ap.parse_args()

    title("HTTPUpgrade EDGE CHECK  %s:%d%s" % (args.domain, args.port, args.path))
    print("started", datetime.now().isoformat())
    tools()
    interfaces()
    resolved = dns(args.domain, args.port)

    targets = []
    # ۱) آن‌چه خود کاربر داده، ۲) آن‌چه DNS برگرداند، ۳) فهرست پیش‌فرض
    for ip in list(args.ip) + sorted({x for v in resolved.values() for x in v
                                      if ":" not in x}) + DEFAULT_EDGE_IPS:
        if ip not in targets:
            targets.append(ip)

    results = {}
    for ip in targets:
        ok, ms, err = tcp(ip, args.port)
        if not ok:
            print("[FAIL] %s TCP %s after %.0f ms" % (ip, err, ms))
            results[ip] = "TCP FAIL"
            continue
        results[ip] = upgrade(ip, args.domain, args.port, args.path)
    title("RESULT")
    for ip, status in results.items():
        print("%-16s %s" % (ip, status))
    print("101 means the edge accepted the upgrade. It does not test VLESS or the UUID.")
    print("Any other status means this phone cannot use that edge for this path.")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump({"domain": args.domain, "port": args.port, "path": args.path,
                       "dns": resolved, "results": results,
                       "generated_at": datetime.now().isoformat()},
                      f, ensure_ascii=False, indent=2)
        print("report written to %s" % os.path.abspath(args.out))


if __name__ == "__main__":
    main()
