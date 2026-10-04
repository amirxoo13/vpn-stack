#!/usr/bin/env bash
# روی VM، بعد از کپی. فقط فیلد listen را به api اضافه می‌کند.
# سند: https://xtls.github.io/en/config/api.html  (از 1.8.12 listen کافی است)
# ری‌استارت چند ثانیه اتصال را قطع می‌کند. اگر نخواهی، این فایل را اجرا نکن.
set -euo pipefail

CFG=/usr/local/etc/xray/config.json
[[ $EUID -eq 0 ]] || { echo "با sudo اجرا کن."; exit 1; }
[[ -f $CFG ]] || { echo "config.json نیست."; exit 1; }
command -v jq >/dev/null || { echo "jq نیست."; exit 1; }

bak="$CFG.bak.stats.$(date +%s)"
cp "$CFG" "$bak"
echo "پشتیبان: $bak"

jq '.api.tag = "api" | .api.services = ["StatsService"] | .api.listen = "127.0.0.1:10085"' \
  "$CFG" >"$CFG.new"

if ! xray -test -config "$CFG.new" >/tmp/stats-patch.log 2>&1; then
  echo "تست رد شد. کانفیگ اصلی دست نخورد."
  cat /tmp/stats-patch.log
  rm -f "$CFG.new"
  exit 1
fi

mv "$CFG.new" "$CFG"
systemctl restart xray
sleep 1
if ! systemctl is-active --quiet xray; then
  cp "$bak" "$CFG"
  systemctl restart xray || true
  echo "بالا نیامد. قبلی برگردانده شد."
  exit 1
fi

echo "listen فعال است. این را بزن:"
echo "  xray api statsquery --server=127.0.0.1:10085 | head"
xray api statsquery --server=127.0.0.1:10085 | head -20 || true
