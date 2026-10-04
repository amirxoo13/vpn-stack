#!/usr/bin/env bash
# در Google Cloud Shell اجرا شود، نه روی VM.
#
# این فایل برای سرورهایی است که با نسخه‌ی قدیمی vpn-setup.sh نصب شده‌اند و
# چهار قاعده‌ی فایروال دارند. سه قاعده‌ی اضافه را پاک می‌کند:
#   vpn-reality-443، vpn-web-80، vpn-udp-test
# و این دو را می‌سازد یا به‌روز می‌کند:
#   vpn-origin-8443 (فقط از IP کلادفلر)، allow-iap-ssh (فقط از رنج IAP)
#
# به هیچ قاعده‌ی دیگری دست نمی‌زند. اگر خودت جای دیگری پورتی باز کرده‌ای،
# این اسکریپت آن را نمی‌بیند و پاک نمی‌کند.
set -euo pipefail

echo "قبل از تغییر:"
gcloud compute firewall-rules list \
  --format="table(name,allowed[].map().firewall_rule().list(),sourceRanges.list())"

CF=$(curl -fsS https://www.cloudflare.com/ips-v4 | paste -sd, -)
CF=${CF//[[:space:]]/}
[[ -n $CF ]] || { echo "لیست IP کلادفلر خالی است. بدون آن ادامه نمی‌دهم." >&2; exit 1; }
echo "رنج کلادفلر گرفته شد."

if gcloud compute firewall-rules describe vpn-origin-8443 >/dev/null 2>&1; then
  gcloud compute firewall-rules update vpn-origin-8443 \
    --rules=tcp:8443 --source-ranges="$CF"
else
  gcloud compute firewall-rules create vpn-origin-8443 \
    --direction=INGRESS --action=ALLOW --rules=tcp:8443 \
    --source-ranges="$CF" --priority=1000
fi
echo "8443 فقط از IP کلادفلر باز است."

if gcloud compute firewall-rules describe allow-iap-ssh >/dev/null 2>&1; then
  gcloud compute firewall-rules update allow-iap-ssh \
    --rules=tcp:22 --source-ranges=35.235.240.0/20
else
  gcloud compute firewall-rules create allow-iap-ssh \
    --direction=INGRESS --action=ALLOW --rules=tcp:22 \
    --source-ranges=35.235.240.0/20 --priority=1000
fi
echo "SSH از IAP (35.235.240.0/20) باز است."

gcloud compute firewall-rules describe vpn-origin-8443 >/dev/null
for name in vpn-reality-443 vpn-web-80 vpn-udp-test; do
  if gcloud compute firewall-rules describe "$name" >/dev/null 2>&1; then
    gcloud compute firewall-rules delete "$name" --quiet
    echo "حذف شد: $name"
  else
    echo "نبود، رد شد: $name"
  fi
done

echo "بعد از تغییر:"
gcloud compute firewall-rules list \
  --format="table(name,allowed[].map().firewall_rule().list(),sourceRanges.list())"
echo "پورت 8443 و قاعده‌ی SSH به‌روز شدند. هر قاعده‌ی دیگری که خودت ساخته باشی دست نخورده است."
