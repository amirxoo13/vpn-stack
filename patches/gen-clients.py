#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen-clients.py — ساخت کانفیگ چند مسیره با failover خودکار
==========================================================
روی VM اجرا می‌شود. از /etc/vpnstack/state.env می‌خواند و برای هر کاربر
دو کانفیگ می‌سازد:

  xray-<user>.json     هسته‌ی Xray  — شامل XHTTP و WebSocket
                       failover با  observatory + balancer(leastPing)
                       برای: ویندوز (v2rayN) و اندروید (v2rayNG)

  singbox-<user>.json  هسته‌ی sing-box — فقط WebSocket
                       failover با  urltest
                       برای: آیفون و NekoBox
                       (sing-box از XHTTP پشتیبانی نمی‌کند)

چطور failover کار می‌کند:
  هر «front» یک outbound جداست: یک IP کلادفلر + یک ترنسپورت.
  هسته هر چند دقیقه همه را پینگ می‌کند و ترافیک را روی سالم‌ترین و
  سریع‌ترین می‌اندازد. اگر یکی بیفتد، بی‌صدا رد می‌شود. کاربر
  هیچ کاری نمی‌کند و هیچ چیزی نمی‌بیند.

ضد لیک:
  - queryStrategy / strategy = فقط IPv4   (سرور IPv6 ندارد)
  - DNS با DoH و از داخل تونل، نه از خط محلی
  - دامنه‌های .ir مستقیم، بقیه از تونل
  - domainStrategy = AsIs  یعنی کلاینت هیچ دامنه‌ای را محلی resolve نمی‌کند
  - IPهای خصوصی و متادیتای کلود بلاک

--- استفاده ---
  sudo python3 gen-clients.py --ips 104.16.132.229,172.64.150.28,188.114.96.3,162.159.140.238

  IPها را از خروجی cfscan.py بردار (سریع‌ترین‌ها).

  اضافه کردن front دیگر (مثلا وقتی Cloud Run را راه انداختی):
  sudo python3 gen-clients.py --ips ... --extra-front cloudrun:relay-abc.a.run.app:216.239.36.21
"""

import argparse
import json
import os
import re
import subprocess
import sys

STATE = "/etc/vpnstack/state.env"
CFG_DEFAULT = "/usr/local/etc/xray/config.json"
OUTDIR = "/root/vpn-info/clients"

SOCKS_PORT = 10808      # پورت پیش‌فرض v2rayN — حالت TUN خودکار کار می‌کند
HTTP_PORT = 10809
DOH = "https://1.1.1.1/dns-query"
PROBE_URL = "https://www.gstatic.com/generate_204"


# ---------------------------------------------------------------- خواندن state
def load_state(path=STATE):
    if not os.path.isfile(path):
        sys.exit("فایل %s پیدا نشد. اول vpn-setup.sh را اجرا کن." % path)
    st = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = re.match(r"^\s*([A-Z_]+)\s*=\s*'(.*)'\s*$", line)
            if m:
                st[m.group(1)] = m.group(2)
    for k in ("DOMAIN", "PATH_XH", "PATH_WS"):
        if not st.get(k):
            sys.exit("کلید %s در %s نیست." % (k, path))
    return st


def users_from_config(path):
    """کاربر را از config.json می‌خواند، نه از UUID_LIST قدیمی."""
    if not path or not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    out, seen = [], set()
    for ib in cfg.get("inbounds") or []:
        clients = (ib.get("settings") or {}).get("clients") or []
        for c in clients:
            uid = c.get("id")
            if not uid or uid in seen:
                continue
            seen.add(uid)
            out.append((c.get("email") or ("user%d" % (len(out) + 1)), uid))
    return out


def write_uuid_list(state_path, users):
    ids = " ".join(uid for _, uid in users)
    lines = []
    if os.path.isfile(state_path):
        with open(state_path, encoding="utf-8") as f:
            lines = [ln for ln in f.readlines() if not ln.startswith("UUID_LIST=")]
    lines.append("UUID_LIST='%s'\n" % ids)
    tmp = state_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.writelines(lines)
    os.chmod(tmp, 0o600)
    os.replace(tmp, state_path)


# ------------------------------------------------------- ساخت لیست frontها
def build_fronts(ips, domain, path_xh, path_ws, extra, ws_count=1):
    """
    هر front = (tag, ip, host, transport, path)

    اکثر frontها XHTTP هستند و فقط ws_count تای آخر WebSocket.
    دلیلش: Xray نسخه ۲۶ برای WebSocket هشدار deprecated می‌دهد و
    گفته ممکن است حذفش کند. پس WS را فقط به‌عنوان پشتیبان نگه می‌داریم.
    تنوع اصلی از «چند front مختلف» می‌آید، نه از چند ترنسپورت.
    """
    fronts = []
    n_xh = max(1, len(ips) - max(0, ws_count))
    for i, ip in enumerate(ips):
        if i < n_xh:
            fronts.append(("front-cf%d-xh" % (i + 1), ip, domain, "xhttp", path_xh))
        else:
            fronts.append(("front-cf%d-ws" % (i + 1), ip, domain, "ws", path_ws))
    for spec in extra:
        parts = spec.split(":")
        if len(parts) != 3:
            sys.exit("قالب --extra-front باید NAME:HOST:IP باشد، این را دادی: %s" % spec)
        name, host, ip = parts
        # frontهای غیرکلادفلر را روی WebSocket می‌گذاریم چون همه‌ی
        # لبه‌ها WS را پروکسی می‌کنند ولی XHTTP را نه
        fronts.append(("front-%s-ws" % re.sub(r"[^a-z0-9]", "", name.lower()),
                       ip, host, "ws", path_ws))
    return fronts


# =========================================================== کانفیگ Xray
def xray_front_outbound(tag, ip, host, transport, path, uuid):
    tls = {
        "serverName": host,
        "allowInsecure": False,
        "fingerprint": "chrome",
        # WebSocket به HTTP/1.1 نیاز دارد. اگر h2 انتخاب شود، upgrade شکست می‌خورد.
        "alpn": ["h2", "http/1.1"] if transport == "xhttp" else ["http/1.1"],
    }
    stream = {"network": transport, "security": "tls", "tlsSettings": tls}
    if transport == "xhttp":
        stream["xhttpSettings"] = {
            "host": host,
            "path": path,
            "mode": "packet-up",
            "xPaddingBytes": "100-1000",
        }
    else:
        stream["wsSettings"] = {"path": path, "host": host}

    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {"vnext": [{
            "address": ip,
            "port": 443,
            "users": [{"id": uuid, "encryption": "none", "level": 0}],
        }]},
        "streamSettings": stream,
        "mux": {"enabled": False},
    }


def build_xray(fronts, uuid, user):
    outs = [xray_front_outbound(t, ip, h, tr, p, uuid)
            for (t, ip, h, tr, p) in fronts]
    outs.append({"tag": "direct", "protocol": "freedom",
                 "settings": {"domainStrategy": "UseIPv4"}})
    outs.append({"tag": "block", "protocol": "blackhole", "settings": {}})

    return {
        "log": {"loglevel": "warning"},

        # ---- DNS: .ir از رزولور محلی، بقیه با DoH از داخل تونل ----
        "dns": {
            "servers": [
                {"address": "localhost", "domains": ["domain:ir"], "skipFallback": True},
                DOH,
            ],
            "queryStrategy": "UseIPv4",
        },

        "inbounds": [
            {"tag": "socks-in", "listen": "127.0.0.1", "port": SOCKS_PORT,
             "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
             "sniffing": {"enabled": True,
                          "destOverride": ["http", "tls", "quic"],
                          "routeOnly": False}},
            {"tag": "http-in", "listen": "127.0.0.1", "port": HTTP_PORT,
             "protocol": "http",
             "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}},
        ],

        "outbounds": outs,

        # ---- قلب failover: همه‌ی frontها را پینگ می‌کند ----
        "observatory": {
            "subjectSelector": ["front-"],
            "probeURL": PROBE_URL,
            "probeInterval": "3m",
            "enableConcurrency": True,
        },

        "routing": {
            # AsIs یعنی کلاینت هیچ دامنه‌ای را محلی resolve نمی‌کند -> بدون لیک
            "domainStrategy": "AsIs",
            "balancers": [{
                "tag": "bal-auto",
                "selector": ["front-"],
                "strategy": {"type": "leastPing"},
            }],
            "rules": [
                {"type": "field", "ip": ["geoip:private", "169.254.0.0/16"],
                 "outboundTag": "direct"},
                {"type": "field", "domain": ["domain:ir"], "outboundTag": "direct"},
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
                {"type": "field", "network": "tcp,udp", "balancerTag": "bal-auto"},
            ],
        },

        "policy": {"levels": {"0": {"handshake": 4, "connIdle": 180}}},
        "remarks": "multi-front failover — %s" % user,
    }


# ======================================================== کانفیگ sing-box
def singbox_front_outbound(tag, ip, host, path, uuid):
    return {
        "type": "vless",
        "tag": tag,
        "server": ip,
        "server_port": 443,
        "uuid": uuid,
        "packet_encoding": "xudp",
        "tls": {
            "enabled": True,
            "server_name": host,
            "insecure": False,
            "alpn": ["http/1.1"],
            "utls": {"enabled": True, "fingerprint": "chrome"},
        },
        "transport": {"type": "ws", "path": path, "headers": {"Host": host}},
    }


def build_singbox(fronts, uuid, user, path_ws):
    # sing-box از XHTTP پشتیبانی نمی‌کند، پس همه‌ی frontها را WebSocket می‌کنیم
    ws = []
    for (tag, ip, host, _tr, _p) in fronts:
        ws.append(singbox_front_outbound(
            re.sub(r"[^a-z0-9-]", "", tag.replace("front-", "")), ip, host, path_ws, uuid))
    tags = [o["tag"] for o in ws]

    return {
        "log": {"level": "warn", "timestamp": True},

        "dns": {
            "servers": [
                {"tag": "dns-remote", "address": DOH,
                 "address_resolver": "dns-local", "detour": "proxy",
                 "strategy": "ipv4_only"},
                {"tag": "dns-local", "address": "local", "detour": "direct",
                 "strategy": "ipv4_only"},
            ],
            "rules": [{"domain_suffix": [".ir"], "server": "dns-local"}],
            "final": "dns-remote",
            "strategy": "ipv4_only",
            "independent_cache": True,
        },

        # از sing-box ۱.۱۱ به بعد، sniff یک «action» در route است نه گزینه‌ی inbound
        "inbounds": [
            {"type": "tun", "tag": "tun-in",
             "address": ["172.19.0.1/30"],
             "mtu": 1400,
             "auto_route": True,
             "strict_route": False,
             "stack": "mixed"},
            {"type": "mixed", "tag": "mixed-in",
             "listen": "127.0.0.1", "listen_port": 2080},
        ],

        "outbounds": [
            {"type": "selector", "tag": "proxy",
             "outbounds": ["auto"] + tags, "default": "auto"},
            # ---- قلب failover ----
            {"type": "urltest", "tag": "auto", "outbounds": tags,
             "url": "https://cp.cloudflare.com/generate_204",
             "interval": "3m", "tolerance": 60,
             "idle_timeout": "30m",
             "interrupt_exist_connections": False},
        ] + ws + [
            # outboundهای نوع dns و block از ۱.۱۲ حذف شده‌اند و
            # sing-box اجرای کانفیگ حاوی آن‌ها را رد می‌کند.
            # جایشان «action» در قواعد route آمده.
            {"type": "direct", "tag": "direct"},
        ],

        "route": {
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"protocol": "bittorrent", "action": "reject"},
                {"ip_is_private": True, "outbound": "direct"},
                {"domain_suffix": [".ir"], "outbound": "direct"},
            ],
            "final": "proxy",
            "auto_detect_interface": True,
        },

        "experimental": {
            "cache_file": {"enabled": True, "store_fakeip": False},
        },
    }


# ================================================================== اجرا
def validate_xray(path):
    """کانفیگ را با خود xray اعتبارسنجی می‌کند."""
    try:
        r = subprocess.run(["xray", "-test", "-config", path],
                           capture_output=True, text=True, timeout=30)
        return r.returncode == 0, (r.stderr or r.stdout).strip()
    except FileNotFoundError:
        return None, "دستور xray پیدا نشد — اعتبارسنجی رد شد"
    except Exception as e:
        return None, str(e)


def validate_singbox(path):
    """اگر sing-box روی سرور نصب باشد، کانفیگ را اعتبارسنجی می‌کند."""
    for exe in ("sing-box", "/usr/local/bin/sing-box", "/tmp/sb/sing-box"):
        try:
            r = subprocess.run([exe, "check", "-c", path],
                               capture_output=True, text=True, timeout=30)
            out = (r.stderr or r.stdout).strip()
            return r.returncode == 0, out
        except FileNotFoundError:
            continue
        except Exception as e:
            return None, str(e)
    return None, "sing-box نصب نیست — اعتبارسنجی رد شد"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ips", required=True,
                    help="IPهای کلادفلر جدا شده با کاما (از خروجی cfscan.py)")
    ap.add_argument("--extra-front", action="append", default=[],
                    metavar="NAME:HOST:IP",
                    help="front اضافه، مثلا cloudrun:relay-x.a.run.app:216.239.36.21")
    ap.add_argument("--ws-count", type=int, default=1,
                    help="چند front روی WebSocket باشد (پیش‌فرض ۱، بقیه XHTTP)")
    ap.add_argument("--outdir", default=OUTDIR)
    ap.add_argument("--config", default=CFG_DEFAULT,
                    help="منبع کاربر: clients داخل config.json")
    ap.add_argument("--state", default=STATE)
    args = ap.parse_args()

    st = load_state(args.state)
    domain = st["DOMAIN"]
    path_xh = st["PATH_XH"]
    path_ws = st["PATH_WS"]
    users = users_from_config(args.config)
    if users:
        write_uuid_list(args.state, users)
        print("کاربرها از %s خوانده شد و UUID_LIST به‌روز شد (%d)." % (args.config, len(users)))
    else:
        users = [("user%d" % (i + 1), u) for i, u in enumerate(st.get("UUID_LIST", "").split()) if u]
        if not users:
            sys.exit("نه در config.json کلاینتی هست، نه UUID_LIST در state.env.")
        print("config.json کلاینت نداشت؛ از UUID_LIST استفاده شد.")

    ips = [x.strip() for x in args.ips.split(",") if x.strip()]
    if len(ips) < 2:
        sys.exit("حداقل دو IP بده، وگرنه failover معنی ندارد.")

    fronts = build_fronts(ips, domain, path_xh, path_ws,
                          args.extra_front, args.ws_count)

    print("\nfrontهایی که ساخته می‌شوند:")
    for (tag, ip, host, tr, p) in fronts:
        print("   %-18s %-16s  %-8s host=%s  path=%s" % (tag, ip, tr, host, p))
    print("\n%d کاربر × ۲ کانفیگ\n" % len(users))
    print("این فایل‌ها پروفایل CF-HU-8443 را عوض نمی‌کنند. تا وقتی خودت import نکنی، اتصال فعلی قطع نمی‌شود.")

    os.makedirs(args.outdir, exist_ok=True)
    os.chmod(args.outdir, 0o700)

    ok = bad = 0
    for user, uuid in users:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", user) or "user"
        xp = os.path.join(args.outdir, "xray-%s.json" % safe)
        with open(xp, "w", encoding="utf-8") as f:
            json.dump(build_xray(fronts, uuid, user), f, ensure_ascii=False, indent=2)
        os.chmod(xp, 0o600)

        sp = os.path.join(args.outdir, "singbox-%s.json" % safe)
        with open(sp, "w", encoding="utf-8") as f:
            json.dump(build_singbox(fronts, uuid, user, path_ws), f,
                      ensure_ascii=False, indent=2)
        os.chmod(sp, 0o600)

        line = "  %-8s" % user
        vx, mx = validate_xray(xp)
        if vx is True:
            line += "  xray [✓]"
            ok += 1
        elif vx is False:
            line += "  xray [✗]"
            bad += 1
        else:
            line += "  xray [?]"

        vs, ms = validate_singbox(sp)
        if vs is True:
            line += "   sing-box [✓]"
        elif vs is False:
            line += "   sing-box [✗]"
            bad += 1
        else:
            line += "   sing-box [-]"
        print(line)
        if vx is False:
            print("      xray: %s" % mx[:400])
        if vs is False:
            print("      sing-box: %s" % ms[:400])

    print("\n" + "=" * 68)
    print("کانفیگ‌ها در %s" % args.outdir)
    if bad:
        print("!! %d کانفیگ ایراد داشت — متن خطای بالا را بفرست." % bad)
    print("=" * 68)
    print("""
نحوه‌ی استفاده:

ویندوز — v2rayN
  ۱) فایل xray-userN.json را روی کامپیوتر بیاور
  ۲) v2rayN → سرورها → «افزودن کانفیگ سفارشی» (Add custom config server)
  ۳) فایل را انتخاب کن. هسته را روی Xray بگذار.
  ۴) حالت TUN را روشن کن. کانفیگ روی پورت socks %d گوش می‌دهد،
     که همان پیش‌فرض v2rayN است، پس TUN خودکار وصل می‌شود.

اندروید — v2rayNG
  همان فایل xray-userN.json را import کن (Custom config).

آیفون / NekoBox
  فایل singbox-userN.json را import کن.
  نیازمند sing-box نسخه‌ی ۱.۱۱ یا بالاتر.

چطور بفهمی failover کار می‌کند:
  در v2rayN، منوی «Real ping» یا صفحه‌ی Routing، پینگ هر front را
  نشان می‌دهد. یکی از frontها را با بستن پورتش در فایروال گوگل کلود
  از کار بینداز — نباید هیچ قطعی حس کنی.

بعدش:
  python leaktest.py --expect BE
""" % SOCKS_PORT)


if __name__ == "__main__":
    main()
