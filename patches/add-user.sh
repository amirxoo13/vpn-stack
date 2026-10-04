#!/usr/bin/env bash
# =============================================================================
#  add-user.sh — اضافه/حذف کاربر بدون دست زدن به بقیه‌ی کانفیگ
# =============================================================================
#   sudo bash add-user.sh add  ali
#   sudo bash add-user.sh del  ali
#   sudo bash add-user.sh list
#   sudo bash add-user.sh links            # چاپ همه‌ی لینک‌ها
# =============================================================================
set -euo pipefail

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; N='\033[0m'
ok()   { echo -e "${G}[✓]${N} $*"; }
warn() { echo -e "${Y}[!]${N} $*"; }
die()  { echo -e "${R}[✗]${N} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "با sudo اجرا کن."
command -v jq >/dev/null || die "jq نصب نیست:  apt-get install -y jq"

CFG=/usr/local/etc/xray/config.json
STATE=/etc/vpnstack/state.env
[[ -f $CFG   ]] || die "کانفیگ Xray پیدا نشد. اول vpn-setup.sh را اجرا کن."
# shellcheck disable=SC1090
[[ -f $STATE ]] && source "$STATE" || die "$STATE پیدا نشد."

ACTION=${1:-list}
NAME=${2:-}

apply_new() {                         # CFG.new باید آماده باشد؛ اصلی تا تست سالم نماند
  local bak="$CFG.bak.$(date +%s)"
  cp "$CFG" "$bak"
  if ! xray -test -config "$CFG.new" >/tmp/addusr.log 2>&1; then
    cat /tmp/addusr.log
    rm -f "$CFG.new"
    die "تست رد شد. کانفیگ در حال اجرا دست نخورد و Xray ری‌استارت نشد."
  fi
  mv "$CFG.new" "$CFG"
  systemctl restart xray
  sleep 1
  if ! systemctl is-active --quiet xray; then
    cp "$bak" "$CFG"
    systemctl restart xray || true
    die "Xray بالا نیامد. کانفیگ قبلی برگردانده شد."
  fi
  ok "Xray بازنشانی شد. پشتیبان: $bak"
}

sync_uuid_list() {
  local ids tmp
  ids=$(jq -r '[.inbounds[].settings.clients[]?.id | select(. != null and . != "")] | unique | join(" ")' "$CFG")
  [[ -n $ids ]] || return 0
  tmp=$(mktemp)
  if [[ -f $STATE ]] && grep -q '^UUID_LIST=' "$STATE"; then
    grep -v '^UUID_LIST=' "$STATE" >"$tmp"
  elif [[ -f $STATE ]]; then
    cat "$STATE" >"$tmp"
  fi
  printf "UUID_LIST='%s'\n" "$ids" >>"$tmp"
  mv "$tmp" "$STATE"
  chmod 600 "$STATE"
  UUID_LIST=$ids
  ok "UUID_LIST در state.env با config.json یکی شد."
}

print_links_for() {                     # print_links_for <uuid> <name>
  local u=$1 nm=$2
  local exh ews
  exh=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$PATH_XH")
  ews=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$PATH_WS")
  echo
  echo "── $nm ──"
  echo "A) XHTTP از کلادفلر:"
  echo "vless://$u@$DOMAIN:443?encryption=none&security=tls&sni=$DOMAIN&fp=chrome&alpn=h2%2Chttp%2F1.1&type=xhttp&host=$DOMAIN&path=$exh&mode=packet-up#A-$nm"
  echo "B) WebSocket از کلادفلر:"
  echo "vless://$u@$DOMAIN:443?encryption=none&security=tls&sni=$DOMAIN&fp=chrome&type=ws&host=$DOMAIN&path=$ews#B-$nm"
  echo "C) REALITY مستقیم:"
  echo "vless://$u@$PUBLIC_IP:$REALITY_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$REALITY_SNI&fp=chrome&pbk=$REALITY_PUB&sid=$REALITY_SID&type=tcp&headerType=none#C-$nm"
}

case "$ACTION" in

  add)
    [[ -n $NAME ]] || die "نام کاربر را بده:  sudo bash add-user.sh add ali"
    if jq -e --arg n "$NAME" '[.inbounds[].settings.clients[]?.email] | index($n)' "$CFG" >/dev/null; then
      die "کاربر «$NAME» از قبل وجود دارد."
    fi
    UUID=$(cat /proc/sys/kernel/random/uuid)
    jq --arg id "$UUID" --arg em "$NAME" '
      .inbounds |= map(
        if (.settings.clients | type) != "array" then .
        elif .tag == "reality-direct" then
          .settings.clients += [{ "id":$id, "flow":"xtls-rprx-vision", "email":$em }]
        else
          .settings.clients += [{ "id":$id, "email":$em }]
        end)
    ' "$CFG" >"$CFG.new"
    apply_new
    sync_uuid_list
    ok "کاربر «$NAME» اضافه شد.  UUID = $UUID"
    print_links_for "$UUID" "$NAME"
    ;;

  del)
    [[ -n $NAME ]] || die "نام کاربر را بده:  sudo bash add-user.sh del ali"
    jq -e --arg n "$NAME" '[.inbounds[].settings.clients[]?.email] | index($n)' "$CFG" >/dev/null \
      || die "کاربری با نام «$NAME» نیست."
    jq --arg em "$NAME" '
      .inbounds |= map(
        if (.settings.clients | type) == "array" then
          .settings.clients |= map(select(.email != $em))
        else . end)
    ' "$CFG" >"$CFG.new"
    apply_new
    sync_uuid_list
    ok "کاربر «$NAME» حذف شد. اتصال‌های فعالش قطع می‌شود."
    ;;

  list)
    echo "کاربران فعال:"
    jq -r '.inbounds[] | select(.settings.clients) |
           "  [\(.tag)]  " + ([.settings.clients[] | .email + " = " + .id] | join("\n            "))' "$CFG"
    ;;

  links)
    mapfile -t rows < <(jq -r '.inbounds[] | select(.tag=="reality-direct") |
                               .settings.clients[] | .email + " " + .id' "$CFG")
    for row in "${rows[@]}"; do
      print_links_for "${row##* }" "${row%% *}"
    done
    ;;

  qr)
    [[ -n $NAME ]] || die "نام کاربر را بده:  sudo bash add-user.sh qr ali"
    command -v qrencode >/dev/null || die "qrencode نصب نیست:  apt-get install -y qrencode"
    UUID=$(jq -r --arg n "$NAME" '.inbounds[] | select(.tag=="reality-direct") |
             .settings.clients[] | select(.email==$n) | .id' "$CFG")
    [[ -n $UUID && $UUID != null ]] || die "کاربر «$NAME» پیدا نشد."
    exh=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$PATH_XH")
    echo "QR مسیر A (XHTTP/CDN) برای $NAME:"
    qrencode -t ANSIUTF8 -o - "vless://$UUID@$DOMAIN:443?encryption=none&security=tls&sni=$DOMAIN&fp=chrome&alpn=h2%2Chttp%2F1.1&type=xhttp&host=$DOMAIN&path=$exh&mode=packet-up#A-$NAME"
    ;;

  *)
    die "دستور نامعتبر. یکی از این‌ها: add | del | list | links | qr"
    ;;
esac
