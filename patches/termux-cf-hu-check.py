#!/usr/bin/env python3
"""Termux check for the working path only.

Checks DNS, TCP/8443, TLS with ALPN http/1.1, and the HTTPUpgrade
status line. It does not send a VLESS UUID, so it cannot prove login.
"""

import base64
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime

DOMAIN = "cdn.amirxo.com"
PORT = 8443
PATH = "/amirhu"
SNI = "cdn.amirxo.com"
TIMEOUT = 8

# Pinned in the working client, plus the two addresses in the older script.
# Any address inside these Cloudflare ranges is also accepted.
PINNED = ["188.114.97.3", "188.114.96.3", "188.114.97.11", "188.114.96.11"]
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
    code, out = run(["ip", "addr"], timeout=5)
    print(out or "no ip output")
    if "tun" in out.lower() or "wg" in out.lower():
        print("[WARN] a tunnel interface exists. Stop the VPN, then run this again.")
    else:
        print("[PASS] no tun/wg interface seen")


def dns():
    title("2. DNS")
    found = {}
    try:
        infos = socket.getaddrinfo(DOMAIN, PORT, type=socket.SOCK_STREAM)
        ips = sorted(set(x[4][0] for x in infos))
        print("system:", ", ".join(ips) or "none")
        found["system"] = ips
    except Exception as e:
        print("[FAIL] system resolver:", e)
        found["system"] = []
    for name, server in DNS_SERVERS:
        code, out = run(["nslookup", DOMAIN, server], timeout=7)
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


def tcp(ip):
    started = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.connect((ip, PORT))
        return True, (time.perf_counter() - started) * 1000, ""
    except Exception as e:
        return False, (time.perf_counter() - started) * 1000, str(e)
    finally:
        sock.close()


def upgrade(ip):
    title("3. TCP + TLS + HTTPUpgrade  %s" % ip)
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(TIMEOUT)
    try:
        started = time.perf_counter()
        raw.connect((ip, PORT))
        tcp_ms = (time.perf_counter() - started) * 1000
        print("[PASS] TCP/8443  %.0f ms" % tcp_ms)
        tls = ctx.wrap_socket(raw, server_hostname=SNI)
        print("[PASS] TLS %s  ALPN %s" % (tls.version(), tls.selected_alpn_protocol()))
        cert = tls.getpeercert()
        names = []
        for item in cert.get("subjectAltName", []):
            if item[0] == "DNS":
                names.append(item[1])
        print("cert names:", ", ".join(names) or "none")
        if DOMAIN not in names:
            print("[WARN] certificate has no DNS name %s" % DOMAIN)
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
        ) % (PATH, SNI, key)
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
    title("CF-HU-8443 CHECK")
    print("domain", DOMAIN, "port", PORT, "path", PATH)
    print("started", datetime.now().isoformat())
    tools()
    interfaces()
    dns()
    targets = []
    for ip in PINNED:
        if ip not in targets:
            targets.append(ip)
    results = {}
    for ip in targets:
        ok, ms, err = tcp(ip)
        if not ok:
            print("[FAIL] %s TCP %s after %.0f ms" % (ip, err, ms))
            results[ip] = "TCP FAIL"
            continue
        results[ip] = upgrade(ip)
    title("RESULT")
    for ip, status in results.items():
        print("%-16s %s" % (ip, status))
    print("101 means the edge accepted the upgrade. It does not test VLESS or the UUID.")
    print("Any other status means this phone cannot use that edge for the working path.")


if __name__ == "__main__":
    main()
