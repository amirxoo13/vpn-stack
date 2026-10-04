#!/usr/bin/env bash
# =============================================================================
#  vpn-setup.sh — نصب کامل روی VM اوبونتو ۲۲.۰۴ در گوگل کلود
# =============================================================================
#  چه چیزی نصب می‌کند:
#
#   مسیر A (اصلی، از طریق کلادفلر):
#       کلاینت → IP کلادفلر:443 → nginx روی VM:8443 → Xray (XHTTP / WebSocket)
#       مزیت: IPی که کلاینت می‌بیند مال کلادفلر است، پس IP شما هرگز
#              بلاک نمی‌شود. پورت 8443 فقط برای کلادفلر باز است.
#
#   مسیر B (پشتیبان، مستقیم):
#       کلاینت → VM:443 → Xray VLESS + REALITY (XTLS-Vision)
#       مزیت: بدون واسطه، سریع‌تر. عیب: IP قابل بلاک شدن است.
#
#   سایت پوششی واقعی روی / تا هر کسی که IP یا دامنه را اسکن کند
#   یک سایت معمولی ببیند، نه یک سرور پروکسی.
#
#  اجرا:
#       sudo bash vpn-setup.sh
#  یا بدون سوال:
#       sudo DOMAIN=cdn.amirxo.com CF_TOKEN=xxx EMAIL=you@mail.com \
#            USERS=8 bash vpn-setup.sh
# =============================================================================

set -euo pipefail

# ---------- رنگ‌ها ----------
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; N='\033[0m'
say()  { echo -e "${B}[*]${N} $*"; }
ok()   { echo -e "${G}[✓]${N} $*"; }
warn() { echo -e "${Y}[!]${N} $*"; }
die()  { echo -e "${R}[✗]${N} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "این اسکریپت باید با sudo اجرا شود:  sudo bash $0"

# =============================================================================
#  ۰. پیکربندی
# =============================================================================
STATE_DIR=/etc/vpnstack
CRED_DIR=/root/vpn-info
CERT_DIR=/etc/ssl/vpnstack
WEBROOT=/var/www/cdnsite

ORIGIN_PORT=${ORIGIN_PORT:-8443}     # پورتی که کلادفلر به آن وصل می‌شود
REALITY_PORT=${REALITY_PORT:-443}    # پورت مسیر مستقیم
XHTTP_LOCAL=${XHTTP_LOCAL:-2001}
WS_LOCAL=${WS_LOCAL:-2002}
USERS=${USERS:-8}

mkdir -p "$STATE_DIR" "$CRED_DIR" "$CERT_DIR"
chmod 700 "$STATE_DIR" "$CRED_DIR"

# اگر قبلا اجرا شده، مقادیر قبلی را بازیابی کن (idempotent)
# shellcheck disable=SC1091
[[ -f $STATE_DIR/state.env ]] && source "$STATE_DIR/state.env"

ask() {                          # ask VAR "پرسش" "پیش‌فرض"
  local var=$1 prompt=$2 def=${3:-} cur=${!1:-}
  [[ -n $cur ]] && { echo "    $var = $cur (از اجرای قبلی)"; return; }
  local val
  if [[ -t 0 ]]; then
    read -r -p "    $prompt${def:+ [$def]}: " val
  else
    val=""
  fi
  val=${val:-$def}
  [[ -n $val ]] || die "$var خالی است."
  printf -v "$var" '%s' "$val"
}

echo
echo "=============================================================="
echo "  نصب سرور — پیکربندی"
echo "=============================================================="
ask DOMAIN "ساب‌دامینی که روی کلادفلر برای این کار می‌سازی" "cdn.amirxo.com"
APEX="${DOMAIN#*.}"
ask EMAIL  "ایمیل برای گواهی Let's Encrypt" "admin@$APEX"

# دامنه‌ی مرجع (SNI) برای REALITY.
# باید: TLS 1.3 + HTTP/2 + X25519 داشته باشد، در ایران فیلتر نباشد،
# و بهتر است در اروپا میزبانی شود تا تاخیرش با سرور بلژیک جور باشد.
ask REALITY_SNI "دامنه‌ی مرجع REALITY" "www.samsung.com"

if [[ -z ${CF_TOKEN:-} ]]; then
  echo
  echo "  برای گرفتن گواهی SSL خودکار، یک API Token کلادفلر لازم است."
  echo "  ساختنش: dash.cloudflare.com → My Profile → API Tokens →"
  echo "          Create Token → Edit zone DNS → Zone Resources = amirxo.com"
  echo "  اگر نمی‌خواهی، Enter بزن و بعدا Origin Certificate دستی می‌گذاریم."
  ask CF_TOKEN "Cloudflare API Token (اختیاری)" "none"
fi

PUBLIC_IP=$(curl -fsS --max-time 10 https://api.ipify.org || \
            curl -fsS --max-time 10 -H 'Metadata-Flavor: Google' \
            http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip || echo "")
[[ -n $PUBLIC_IP ]] || warn "IP عمومی تشخیص داده نشد؛ در لینک‌ها دستی جایگزین کن."
ok "IP عمومی سرور: ${PUBLIC_IP:-نامشخص}"

# =============================================================================
#  ۱. بسته‌های سیستم
# =============================================================================
say "نصب بسته‌های لازم ..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  curl wget socat unzip jq qrencode openssl ca-certificates \
  nginx dnsutils uuid-runtime python3 cron >/dev/null
ok "بسته‌ها نصب شد."

# =============================================================================
#  ۲. تنظیمات هسته: BBR + بهینه‌سازی شبکه
# =============================================================================
say "فعال‌سازی TCP BBR و بهینه‌سازی شبکه ..."
cat >/etc/sysctl.d/99-vpnstack.conf <<'EOF'
# --- صف‌بندی و کنترل ازدحام: BBR سرعت را در مسیرهای پرتاخیر خیلی بهتر می‌کند
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# --- بافرها برای پهنای باند بالا
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_notsent_lowat = 16384

# --- ظرفیت اتصال‌های همزمان
net.core.somaxconn = 8192
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.ip_local_port_range = 10000 65000
net.netfilter.nf_conntrack_max = 262144

# --- فورواردینگ (لازم برای عبور ترافیک)
net.ipv4.ip_forward = 1
EOF
modprobe tcp_bbr 2>/dev/null || true
sysctl --system >/dev/null 2>&1 || true
CC=$(sysctl -n net.ipv4.tcp_congestion_control)
[[ $CC == bbr ]] && ok "BBR فعال است." || warn "الگوریتم فعلی: $CC (BBR فعال نشد)"

# محدودیت فایل برای Xray
mkdir -p /etc/systemd/system/xray.service.d
cat >/etc/systemd/system/xray.service.d/10-limits.conf <<'EOF'
[Service]
LimitNOFILE=1048576
EOF

# =============================================================================
#  ۳. سایت پوششی
# =============================================================================
say "ساخت سایت پوششی ..."
mkdir -p "$WEBROOT/assets"
cat >"$WEBROOT/index.html" <<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Static Assets</title>
<link rel="stylesheet" href="/assets/site.css">
</head>
<body>
<main>
  <h1>Static assets</h1>
  <p>This host serves static files &mdash; images, stylesheets, fonts and
     archives &mdash; for personal projects. There is no application here and
     nothing to sign in to.</p>
  <h2>Cache policy</h2>
  <ul>
    <li>Immutable assets under <code>/assets/</code> are cached for one year.</li>
    <li>Everything else revalidates on each request.</li>
  </ul>
  <h2>Contact</h2>
  <p>Write to the address listed in the WHOIS record for this domain.</p>
  <footer><p>Last updated $(date -u +%Y-%m-%d).</p></footer>
</main>
</body>
</html>
HTML

cat >"$WEBROOT/assets/site.css" <<'CSS'
:root { --ink:#1b1b1f; --bg:#fbfbfd; --mut:#5e5e6b; --line:#e3e3ea; }
@media (prefers-color-scheme: dark) {
  :root { --ink:#e9e9ef; --bg:#16161a; --mut:#a0a0ad; --line:#2c2c34; }
}
* { box-sizing:border-box }
body { margin:0; background:var(--bg); color:var(--ink);
  font:16px/1.65 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
main { max-width:44rem; margin:0 auto; padding:4rem 1rem; }
h1 { font-size:1.75rem; letter-spacing:-.02em; margin:0 0 1rem }
h2 { font-size:1.05rem; margin:2.25rem 0 .5rem }
p,li { color:var(--mut) }
code { background:var(--line); padding:.1em .35em; border-radius:4px; font-size:.9em }
footer { margin-top:3rem; padding-top:1rem; border-top:1px solid var(--line); font-size:.85rem }
CSS

cat >"$WEBROOT/robots.txt" <<'EOF'
User-agent: *
Disallow:
EOF

# چند فایل حجیم تا آمار ترافیک سایت طبیعی به نظر برسد
head -c 262144 /dev/urandom >"$WEBROOT/assets/sprite.bin" 2>/dev/null || true
chown -R www-data:www-data "$WEBROOT"
ok "سایت پوششی در $WEBROOT ساخته شد."

# =============================================================================
#  ۴. گواهی TLS
# =============================================================================
say "آماده‌سازی گواهی TLS برای $DOMAIN ..."
FULLCHAIN="$CERT_DIR/fullchain.pem"
KEYFILE="$CERT_DIR/privkey.pem"

issue_with_acme() {
  local acme="$HOME/.acme.sh/acme.sh"
  if [[ ! -x $acme ]]; then
    curl -fsS https://get.acme.sh | sh -s email="$EMAIL" >/dev/null
  fi
  acme="$HOME/.acme.sh/acme.sh"
  [[ -x $acme ]] || return 1
  "$acme" --set-default-ca --server letsencrypt >/dev/null
  CF_Token="$CF_TOKEN" "$acme" --issue --dns dns_cf \
      -d "$DOMAIN" --keylength ec-256 --force >/dev/null
  "$acme" --install-cert -d "$DOMAIN" --ecc \
      --fullchain-file "$FULLCHAIN" \
      --key-file "$KEYFILE" \
      --reloadcmd "systemctl reload nginx" >/dev/null
}

if [[ -s $FULLCHAIN && -s $KEYFILE ]]; then
  ok "گواهی از قبل موجود است."
elif [[ ${CF_TOKEN:-none} != none && -n ${CF_TOKEN:-} ]]; then
  if issue_with_acme; then
    ok "گواهی Let's Encrypt صادر و نصب شد (تمدید خودکار فعال است)."
  else
    warn "صدور خودکار ناموفق بود — به گواهی موقت می‌رویم."
  fi
fi

if [[ ! -s $FULLCHAIN || ! -s $KEYFILE ]]; then
  warn "گواهی معتبر نداریم. یک گواهی self-signed موقت می‌سازم."
  warn "بعدا حتما Origin Certificate کلادفلر را در این دو فایل بگذار:"
  warn "   $FULLCHAIN   و   $KEYFILE"
  openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -days 3650 -keyout "$KEYFILE" -out "$FULLCHAIN" \
    -subj "/CN=$DOMAIN" -addext "subjectAltName=DNS:$DOMAIN" 2>/dev/null
fi
chmod 600 "$KEYFILE"

# =============================================================================
#  ۵. کلیدها، UUIDها و مسیرهای مخفی
# =============================================================================
say "تولید کلیدها و شناسه‌ها ..."

# نصب Xray اگر نیست (برای دستور x25519 لازم است)
if ! command -v xray >/dev/null 2>&1; then
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" \
       @ install >/dev/null
fi
command -v xray >/dev/null || die "نصب Xray ناموفق بود."
XRAY_VER=$(xray version 2>/dev/null | head -1)
ok "Xray: $XRAY_VER"

if [[ -z ${REALITY_PRIV:-} ]]; then
  KP=$(xray x25519)
  REALITY_PRIV=$(echo "$KP" | grep -iE 'private' | sed 's/.*: *//' | tr -d '[:space:]')
  REALITY_PUB=$(echo  "$KP" | grep -iE 'public|password' | sed 's/.*: *//' | tr -d '[:space:]')
fi
[[ -n ${REALITY_PRIV:-} && -n ${REALITY_PUB:-} ]] || die "تولید کلید REALITY ناموفق بود."

REALITY_SID=${REALITY_SID:-$(openssl rand -hex 8)}
PATH_XH=${PATH_XH:-/$(openssl rand -hex 6)}
PATH_WS=${PATH_WS:-/$(openssl rand -hex 6)}

# UUIDها
if [[ -z ${UUID_LIST:-} ]]; then
  UUID_LIST=""
  for i in $(seq 1 "$USERS"); do
    UUID_LIST+="$(cat /proc/sys/kernel/random/uuid) "
  done
  UUID_LIST=$(echo "$UUID_LIST" | xargs)
fi
read -r -a UUIDS <<<"$UUID_LIST"
ok "تعداد کاربر: ${#UUIDS[@]}"

# ذخیره‌ی وضعیت برای اجراهای بعدی
cat >"$STATE_DIR/state.env" <<EOF
DOMAIN='$DOMAIN'
EMAIL='$EMAIL'
CF_TOKEN='${CF_TOKEN:-none}'
REALITY_SNI='$REALITY_SNI'
REALITY_PRIV='$REALITY_PRIV'
REALITY_PUB='$REALITY_PUB'
REALITY_SID='$REALITY_SID'
PATH_XH='$PATH_XH'
PATH_WS='$PATH_WS'
UUID_LIST='$UUID_LIST'
PUBLIC_IP='$PUBLIC_IP'
ORIGIN_PORT='$ORIGIN_PORT'
REALITY_PORT='$REALITY_PORT'
EOF
chmod 600 "$STATE_DIR/state.env"

# =============================================================================
#  ۶. بررسی مناسب بودن دامنه‌ی مرجع REALITY
# =============================================================================
say "بررسی $REALITY_SNI برای REALITY ..."
SNI_OK=1
if ! timeout 10 openssl s_client -connect "$REALITY_SNI:443" -servername "$REALITY_SNI" \
      -tls1_3 </dev/null 2>/dev/null | grep -q "TLSv1.3"; then
  warn "$REALITY_SNI از TLS 1.3 پشتیبانی نمی‌کند یا در دسترس نیست."
  SNI_OK=0
fi
if ! timeout 10 curl -fsS -o /dev/null -w '%{http_version}' \
      "https://$REALITY_SNI" 2>/dev/null | grep -q '^2'; then
  warn "$REALITY_SNI روی HTTP/2 جواب نداد."
  SNI_OK=0
fi
[[ $SNI_OK -eq 1 ]] && ok "$REALITY_SNI مناسب است (TLS 1.3 + HTTP/2)." \
  || warn "دامنه‌ی مرجع را عوض کن. گزینه‌ها: www.samsung.com، www.cisco.com، www.lg.com، www.asus.com"

# =============================================================================
#  ۷. تنظیم nginx
# =============================================================================
say "تنظیم nginx روی پورت $ORIGIN_PORT ..."
rm -f /etc/nginx/sites-enabled/default

# --- سازگاری: IPv6 فقط اگر هسته پشتیبانی کند، وگرنه nginx بالا نمی‌آید
LISTEN80_V6=""
if [[ -f /proc/net/if_inet6 ]]; then
  LISTEN80_V6="    listen [::]:80 default_server;"
  ok "IPv6 در هسته موجود است."
else
  warn "IPv6 موجود نیست — خط listen مربوط به IPv6 حذف می‌شود."
fi

# --- سازگاری: nginx >= 1.25 از «http2 on;» استفاده می‌کند، قبل‌ترها از «listen ... http2»
NGX_VER=$(nginx -v 2>&1 | sed -n 's#.*nginx/\([0-9.]*\).*#\1#p')
NGX_MAJ=${NGX_VER%%.*}; NGX_MIN=$(echo "$NGX_VER" | cut -d. -f2)
if (( NGX_MAJ > 1 || (NGX_MAJ == 1 && NGX_MIN >= 26) )); then
  LISTEN_SSL="    listen $ORIGIN_PORT ssl default_server;
    http2 on;"
else
  LISTEN_SSL="    listen $ORIGIN_PORT ssl http2 default_server;"
fi
ok "nginx نسخه $NGX_VER"

cat >/etc/nginx/conf.d/00-vpnstack-upstream.conf <<'EOF'
map $http_upgrade $conn_upgrade {
    default  upgrade;
    ''       close;
}
EOF

cat >/etc/nginx/sites-available/vpnstack.conf <<NGINX
# ---------- HTTP روی ۸۰: فقط سایت پوششی ----------
server {
    listen 80 default_server;
$LISTEN80_V6
    server_name _;
    root $WEBROOT;
    index index.html;
    server_tokens off;
    location / { try_files \$uri \$uri/ =404; }
}

# ---------- مبدأ کلادفلر روی $ORIGIN_PORT ----------
server {
$LISTEN_SSL
    server_name $DOMAIN;
    server_tokens off;

    ssl_certificate     $FULLCHAIN;
    ssl_certificate_key $KEYFILE;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache   shared:SSLCDN:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    root $WEBROOT;
    index index.html;

    # ---- مسیر XHTTP (گزینه‌ی اصلی: شبیه ترافیک HTTP عادی) ----
    location $PATH_XH {
        if (\$http_upgrade) { return 404; }
        proxy_pass              http://127.0.0.1:$XHTTP_LOCAL;
        proxy_http_version      1.1;
        proxy_set_header        Host \$host;
        proxy_set_header        X-Real-IP \$remote_addr;
        proxy_set_header        X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header        X-Forwarded-Proto \$scheme;
        proxy_buffering         off;
        proxy_request_buffering off;
        chunked_transfer_encoding on;
        proxy_read_timeout      300s;
        proxy_send_timeout      300s;
    }

    # ---- مسیر WebSocket (پشتیبان) ----
    location $PATH_WS {
        proxy_pass         http://127.0.0.1:$WS_LOCAL;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade \$http_upgrade;
        proxy_set_header   Connection \$conn_upgrade;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    # ---- بقیه: سایت پوششی ----
    location /assets/ {
        expires 365d;
        add_header Cache-Control "public, immutable";
    }
    location / { try_files \$uri \$uri/ =404; }
}
NGINX

ln -sf /etc/nginx/sites-available/vpnstack.conf /etc/nginx/sites-enabled/vpnstack.conf
nginx -t >/dev/null 2>&1 || { nginx -t; die "تنظیمات nginx ایراد دارد."; }
systemctl enable nginx >/dev/null 2>&1
systemctl restart nginx
ok "nginx راه‌اندازی شد."

# =============================================================================
#  ۸. تنظیم Xray
# =============================================================================
say "نوشتن کانفیگ Xray ..."

clients_json() {                 # clients_json <flow>
  local flow=$1 out="" i=1
  for u in "${UUIDS[@]}"; do
    [[ -n $out ]] && out+=","
    if [[ -n $flow ]]; then
      out+="{\"id\":\"$u\",\"flow\":\"$flow\",\"email\":\"user$i\"}"
    else
      out+="{\"id\":\"$u\",\"email\":\"user$i\"}"
    fi
    ((i++))
  done
  echo "$out"
}

CL_VISION=$(clients_json "xtls-rprx-vision")
CL_PLAIN=$(clients_json "")

cat >/usr/local/etc/xray/config.json <<XRAYCFG
{
  "log": { "loglevel": "warning", "access": "none", "error": "/var/log/xray/error.log" },

  "dns": {
    "servers": [
      { "address": "https://1.1.1.1/dns-query", "skipFallback": false },
      "1.1.1.1",
      "8.8.8.8"
    ],
    "queryStrategy": "UseIPv4",
    "disableFallbackIfMatch": false
  },

  "inbounds": [
    {
      "tag": "reality-direct",
      "listen": "0.0.0.0",
      "port": $REALITY_PORT,
      "protocol": "vless",
      "settings": { "clients": [ $CL_VISION ], "decryption": "none" },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "target": "$REALITY_SNI:443",
          "xver": 0,
          "serverNames": [ "$REALITY_SNI" ],
          "privateKey": "$REALITY_PRIV",
          "shortIds": [ "$REALITY_SID" ]
        }
      },
      "sniffing": { "enabled": true, "destOverride": [ "http", "tls", "quic" ], "routeOnly": false }
    },
    {
      "tag": "xhttp-cdn",
      "listen": "127.0.0.1",
      "port": $XHTTP_LOCAL,
      "protocol": "vless",
      "settings": { "clients": [ $CL_PLAIN ], "decryption": "none" },
      "streamSettings": {
        "network": "xhttp",
        "security": "none",
        "xhttpSettings": {
          "host": "$DOMAIN",
          "path": "$PATH_XH",
          "mode": "auto",
          "xPaddingBytes": "100-1000"
        }
      },
      "sniffing": { "enabled": true, "destOverride": [ "http", "tls", "quic" ], "routeOnly": false }
    },
    {
      "tag": "ws-cdn",
      "listen": "127.0.0.1",
      "port": $WS_LOCAL,
      "protocol": "vless",
      "settings": { "clients": [ $CL_PLAIN ], "decryption": "none" },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": { "path": "$PATH_WS", "host": "$DOMAIN" }
      },
      "sniffing": { "enabled": true, "destOverride": [ "http", "tls", "quic" ], "routeOnly": false }
    }
  ],

  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": { "domainStrategy": "UseIPv4" }
    },
    { "tag": "block", "protocol": "blackhole", "settings": {} }
  ],

  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "protocol": [ "bittorrent" ], "outboundTag": "block" },
      { "type": "field", "ip": [ "geoip:private", "169.254.0.0/16" ], "outboundTag": "block" },
      { "type": "field", "domain": [ "metadata.google.internal" ], "outboundTag": "block" },
      { "type": "field", "port": "25,465,587", "outboundTag": "block" },
      { "type": "field", "network": "tcp,udp", "outboundTag": "direct" }
    ]
  },

  "policy": {
    "levels": { "0": { "handshake": 4, "connIdle": 180, "uplinkOnly": 0, "downlinkOnly": 0, "statsUserUplink": true, "statsUserDownlink": true } },
    "system": { "statsInboundUplink": true, "statsInboundDownlink": true }
  },
  "stats": {},
  "api": { "tag": "api", "services": [ "StatsService" ] }
}
XRAYCFG

mkdir -p /var/log/xray && chown -R nobody:nogroup /var/log/xray 2>/dev/null || true

# نام برخی کلیدها بین نسخه‌های Xray عوض شده است.
# اگر اعتبارسنجی رد شد، نام‌های جایگزین را امتحان می‌کنیم.
CFG=/usr/local/etc/xray/config.json
try_variants() {
  local variants=(
    "noop"
    's/"target": "/"dest": "/'                               # target -> dest
    's/"xhttp"/"splithttp"/; s/"xhttpSettings"/"splithttpSettings"/'
    's/"target": "/"dest": "/; s/"xhttp"/"splithttp"/; s/"xhttpSettings"/"splithttpSettings"/'
  )
  cp "$CFG" "$CFG.orig"
  for v in "${variants[@]}"; do
    cp "$CFG.orig" "$CFG"
    [[ $v != noop ]] && sed -i "$v" "$CFG"
    if xray -test -config "$CFG" >/tmp/xraytest.log 2>&1; then
      [[ $v == noop ]] && ok "کانفیگ Xray معتبر است." \
        || ok "کانفیگ با نام‌های سازگار نسخه‌ی قدیمی‌تر معتبر شد."
      rm -f "$CFG.orig"
      return 0
    fi
  done
  cp "$CFG.orig" "$CFG"; rm -f "$CFG.orig"
  return 1
}
if ! try_variants; then
  echo "----- خروجی xray -test -----"
  cat /tmp/xraytest.log
  echo "----------------------------"
  die "کانفیگ Xray ایراد دارد. متن خطای بالا را برای من بفرست."
fi

systemctl daemon-reload
systemctl enable xray >/dev/null 2>&1
systemctl restart xray
sleep 2
systemctl is-active --quiet xray && ok "Xray در حال اجراست." || {
  journalctl -u xray -n 30 --no-pager; die "Xray بالا نیامد."; }

# =============================================================================
#  ۹. بررسی سلامت
# =============================================================================
say "بررسی سلامت سرویس‌ها ..."
ss -lntp 2>/dev/null | grep -E ":($REALITY_PORT|$ORIGIN_PORT|$XHTTP_LOCAL|$WS_LOCAL)\b" || true
curl -fsS -o /dev/null -w "   سایت پوششی روی 127.0.0.1:$ORIGIN_PORT → HTTP %{http_code}\n" \
  --resolve "$DOMAIN:$ORIGIN_PORT:127.0.0.1" -k "https://$DOMAIN:$ORIGIN_PORT/" || \
  warn "سایت پوششی روی مبدأ جواب نداد."

# =============================================================================
#  ۱۰. تولید لینک‌های کلاینت
# =============================================================================
say "تولید لینک‌های اتصال ..."
ENC_XH=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$PATH_XH")
ENC_WS=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$PATH_WS")

LINKS="$CRED_DIR/links.txt"
: >"$LINKS"
{
  echo "==============================================================="
  echo " لینک‌های اتصال — $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo " دامنه: $DOMAIN    IP سرور: $PUBLIC_IP"
  echo "==============================================================="
  echo
  echo "### مسیر A — XHTTP از طریق کلادفلر  (پیشنهاد اول)"
  echo "### پایدارترین گزینه: IP دیده‌شده مال کلادفلر است، پس بلاک نمی‌شود."
  i=1
  for u in "${UUIDS[@]}"; do
    echo "user$i:"
    echo "vless://$u@$DOMAIN:443?encryption=none&security=tls&sni=$DOMAIN&fp=chrome&alpn=h2%2Chttp%2F1.1&type=xhttp&host=$DOMAIN&path=$ENC_XH&mode=packet-up#A-xhttp-user$i"
    echo
    ((i++))
  done

  echo "### مسیر B — WebSocket از طریق کلادفلر  (پشتیبان مسیر A)"
  i=1
  for u in "${UUIDS[@]}"; do
    echo "user$i:"
    echo "vless://$u@$DOMAIN:443?encryption=none&security=tls&sni=$DOMAIN&fp=chrome&type=ws&host=$DOMAIN&path=$ENC_WS#B-ws-user$i"
    echo
    ((i++))
  done

  echo "### مسیر C — REALITY مستقیم به IP سرور  (سریع‌ترین، ولی IP قابل بلاک)"
  i=1
  for u in "${UUIDS[@]}"; do
    echo "user$i:"
    echo "vless://$u@$PUBLIC_IP:$REALITY_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$REALITY_SNI&fp=chrome&pbk=$REALITY_PUB&sid=$REALITY_SID&type=tcp&headerType=none#C-reality-user$i"
    echo
    ((i++))
  done

  echo "==============================================================="
  echo "پارامترهای خام (برای وارد کردن دستی):"
  echo "  دامنه (SNI/Host) : $DOMAIN"
  echo "  IP سرور          : $PUBLIC_IP"
  echo "  پورت مسیر مستقیم : $REALITY_PORT"
  echo "  پورت مبدأ کلادفلر: $ORIGIN_PORT"
  echo "  مسیر XHTTP       : $PATH_XH   (mode = packet-up)"
  echo "  مسیر WebSocket   : $PATH_WS"
  echo "  REALITY SNI      : $REALITY_SNI"
  echo "  REALITY PublicKey: $REALITY_PUB"
  echo "  REALITY ShortId  : $REALITY_SID"
  echo "  UUIDها           :"
  i=1; for u in "${UUIDS[@]}"; do echo "      user$i = $u"; ((i++)); done
  echo "==============================================================="
} >>"$LINKS"
chmod 600 "$LINKS"

# QR کد برای user1 فقط روی مسیر A و C. مسیر B در این بلوک ساخته نمی‌شود.
QR="$CRED_DIR/qr-user1.txt"
{
  echo "--- QR مسیر A (XHTTP/CDN) — user1 ---"
  qrencode -t ANSIUTF8 -o - "vless://${UUIDS[0]}@$DOMAIN:443?encryption=none&security=tls&sni=$DOMAIN&fp=chrome&alpn=h2%2Chttp%2F1.1&type=xhttp&host=$DOMAIN&path=$ENC_XH&mode=packet-up#A-xhttp-user1"
  echo
  echo "--- QR مسیر C (REALITY مستقیم) — user1 ---"
  qrencode -t ANSIUTF8 -o - "vless://${UUIDS[0]}@$PUBLIC_IP:$REALITY_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$REALITY_SNI&fp=chrome&pbk=$REALITY_PUB&sid=$REALITY_SID&type=tcp&headerType=none#C-reality-user1"
} >"$QR" 2>/dev/null || warn "ساخت QR ناموفق بود."

ok "لینک‌ها در $LINKS ذخیره شد."

# =============================================================================
#  ۱۱. دستورات فایروال گوگل کلود
# =============================================================================
FW="$CRED_DIR/gcloud-firewall.sh"
cat >"$FW" <<'FWEOF'
#!/usr/bin/env bash
# این دستورات را در Google Cloud Shell اجرا کن (نه روی VM).
# رنج IPهای کلادفلر از https://www.cloudflare.com/ips-v4 گرفته می‌شود.
set -e

CF=$(curl -fsS https://www.cloudflare.com/ips-v4 | paste -sd, -)
echo "رنج‌های کلادفلر: $CF"

# مسیر مستقیم REALITY — از همه‌جا
gcloud compute firewall-rules create vpn-reality-443 \
  --direction=INGRESS --action=ALLOW --rules=tcp:443 \
  --source-ranges=0.0.0.0/0 --priority=1000 2>/dev/null || \
gcloud compute firewall-rules update vpn-reality-443 --rules=tcp:443

# مبدأ کلادفلر — فقط از IPهای کلادفلر. این مهم‌ترین قدم امنیتی است:
# هیچ‌کس جز کلادفلر نمی‌تواند سرور اصلی را ببیند یا پروب کند.
gcloud compute firewall-rules create vpn-origin-8443 \
  --direction=INGRESS --action=ALLOW --rules=tcp:8443 \
  --source-ranges="$CF" --priority=1000 2>/dev/null || \
gcloud compute firewall-rules update vpn-origin-8443 --source-ranges="$CF"

# سایت پوششی روی ۸۰ (اختیاری ولی طبیعی‌تر است)
gcloud compute firewall-rules create vpn-web-80 \
  --direction=INGRESS --action=ALLOW --rules=tcp:80 \
  --source-ranges=0.0.0.0/0 --priority=1000 2>/dev/null || true

# پورت‌های تست UDP — بعد از اتمام تست حتما حذف کن
gcloud compute firewall-rules create vpn-udp-test \
  --direction=INGRESS --action=ALLOW --rules=udp:53,udp:1194,udp:40000,udp:51820 \
  --source-ranges=0.0.0.0/0 --priority=1000 2>/dev/null || true

echo
echo "قواعد فعلی:"
gcloud compute firewall-rules list --format="table(name,allowed[].map().firewall_rule().list(),sourceRanges.list())"
echo
echo "برای حذف قواعد تست UDP بعد از اتمام کار:"
echo "  gcloud compute firewall-rules delete vpn-udp-test"
FWEOF
chmod +x "$FW"

# =============================================================================
#  پایان
# =============================================================================
echo
echo -e "${G}===============================================================${N}"
echo -e "${G}  نصب تمام شد.${N}"
echo -e "${G}===============================================================${N}"
cat <<EOM

قدم‌های بعدی، به ترتیب:

 ۱) فایروال گوگل کلود را باز کن. این اسکریپت را در Cloud Shell اجرا کن:
       $FW
    (محتوایش را کپی کن و در Cloud Shell بچسبان)

 ۲) در کلادفلر یک رکورد DNS بساز:
       Type: A     Name: ${DOMAIN%%.*}     Content: $PUBLIC_IP
       Proxy status: Proxied  (ابر نارنجی — حتما روشن)
    بعد در تب SSL/TLS:
       Encryption mode = Full (strict)
    و در تب Network:
       WebSockets = On

 ۳) لینک‌های اتصال اینجاست:
       cat $LINKS
    و QR برای موبایل:
       cat $QR

 ۴) هر سه مسیر A، B و C را روی خط ایران تست کن و ببین کدام پایدار است.

EOM
