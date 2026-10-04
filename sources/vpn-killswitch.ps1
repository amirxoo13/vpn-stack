<#
=============================================================================
 vpn-killswitch.ps1  —  کیل‌سوییچ واقعی + غیرفعال‌سازی IPv6 برای ویندوز
=============================================================================
 مشکلی که حل می‌کند:
   v2rayN و NekoBox کیل‌سوییچ واقعی ندارند. وقتی تونل قطع می‌شود،
   ویندوز بی‌صدا ترافیک را از مسیر معمولی می‌فرستد و IP واقعی‌ات لو می‌رود.
   این اسکریپت با فایروال خود ویندوز، خروجی پیش‌فرض را Block می‌کند و فقط
   به برنامه‌ی تونل و کارت شبکه‌ی مجازی اجازه‌ی عبور می‌دهد.

 دستورها (PowerShell را «Run as Administrator» باز کن):

   .\vpn-killswitch.ps1 -Status         نشان می‌دهد الان چه وضعی است
   .\vpn-killswitch.ps1 -DisableIPv6    IPv6 را روی همه‌ی کارت‌ها خاموش می‌کند
   .\vpn-killswitch.ps1 -Enable         کیل‌سوییچ را روشن می‌کند
   .\vpn-killswitch.ps1 -Disable        همه چیز را به حالت اول برمی‌گرداند
   .\vpn-killswitch.ps1 -EnableIPv6     IPv6 را برمی‌گرداند

 اگر اینترنتت قطع شد، فقط این را بزن:
   .\vpn-killswitch.ps1 -Disable
 (به اینترنت نیاز ندارد.)

 اگر اجازه‌ی اجرای اسکریپت را نداشتی، یک‌بار این را بزن:
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
=============================================================================
#>

[CmdletBinding()]
param(
    [switch]$Enable,
    [switch]$Disable,
    [switch]$Status,
    [switch]$DisableIPv6,
    [switch]$EnableIPv6,
    [string[]]$Program = @(),
    [string]$TunAlias = ""
)

$TAG = "VPNKS"

# ---------------------------------------------------------------- بررسی ادمین
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "این اسکریپت باید با دسترسی Administrator اجرا شود." -ForegroundColor Red
    Write-Host "روی Start راست کلیک کن -> Terminal (Admin) -> بعد اسکریپت را اجرا کن."
    exit 1
}

function Say  ($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Good ($m) { Write-Host "[+] $m" -ForegroundColor Green }
function Warn ($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Bad  ($m) { Write-Host "[x] $m" -ForegroundColor Red }

# --------------------------------------------- پیدا کردن برنامه‌ی تونل در حال اجرا
function Find-TunnelPrograms {
    $names = @("xray", "sing-box", "sing_box", "v2rayN", "nekobox_core",
               "nekoray_core", "NekoBox", "Xray", "hysteria", "clash",
               "mihomo", "clash-verge-service", "verge-mihomo")
    $paths = @()
    foreach ($n in $names) {
        Get-Process -Name $n -ErrorAction SilentlyContinue | ForEach-Object {
            try { if ($_.Path) { $paths += $_.Path } } catch { }
        }
    }
    return ($paths | Sort-Object -Unique)
}

# ---------------------------------------------- پیدا کردن کارت شبکه‌ی مجازی تونل
function Find-TunAdapters {
    # فقط نام‌های شناخته‌شده. tun|tap بدون مرز، «Teredo Tunneling» و ISATAP را هم می‌گیرد.
    $pat = '(^|[^A-Za-z0-9])(wintun|wireguard|sing-box|singbox|v2ray|neko|clash|mihomo|openvpn|tun[0-9]*|tap[0-9]*)([^A-Za-z0-9]|$)'
    Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceDescription -match $pat -or $_.Name -match $pat } |
        Select-Object -ExpandProperty Name
}

# ============================================================== وضعیت
if ($Status) {
    Write-Host ""
    Say "وضعیت فایروال ویندوز:"
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultOutboundAction |
        Format-Table -AutoSize

    Say "قواعد ساخته‌شده توسط این اسکریپت:"
    $rules = @(Get-NetFirewallRule -DisplayName "$TAG-*" -ErrorAction SilentlyContinue)
    if ($rules.Count -gt 0) {
        $rules | Select-Object DisplayName, Direction, Action, Enabled | Format-Table -AutoSize
    } else {
        Write-Host "    هیچ قاعده‌ای نیست. کیل‌سوییچ خاموش است." -ForegroundColor Gray
    }

    Say "وضعیت IPv6 روی کارت‌های شبکه:"
    Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue |
        Select-Object Name, Enabled | Format-Table -AutoSize

    Say "کارت‌های مجازی تونل که پیدا شد:"
    $t = Find-TunAdapters
    if ($t) { $t | ForEach-Object { Write-Host "    $_" } }
    else { Write-Host "    هیچ‌کدام (تونل وصل نیست؟)" -ForegroundColor Gray }

    Say "برنامه‌های تونل در حال اجرا:"
    $p = Find-TunnelPrograms
    if ($p) { $p | ForEach-Object { Write-Host "    $_" } }
    else { Write-Host "    هیچ‌کدام" -ForegroundColor Gray }
    Write-Host ""
    exit 0
}

# ============================================================== خاموش کردن IPv6
if ($DisableIPv6) {
    Say "خاموش کردن IPv6 روی همه‌ی کارت‌های شبکه ..."
    Warn "سرور تو IPv6 ندارد. تا وقتی IPv6 روشن باشد، هر سایتی که IPv6 دارد"
    Warn "از کنار تونل رد می‌شود و IP واقعی‌ات را می‌بیند. این مهم‌ترین علت لیک است."
    $n = 0
    Get-NetAdapter | ForEach-Object {
        try {
            Disable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 `
                -ErrorAction Stop
            Write-Host "    خاموش شد: $($_.Name)"
            $n++
        } catch {
            Write-Host "    رد شد: $($_.Name)  ($($_.Exception.Message))" -ForegroundColor Gray
        }
    }
    # ترجیح IPv4 بر IPv6 در سطح سیستم (لایه‌ی دوم حفاظت)
    try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
            -Name "DisabledComponents" -Value 0x20 -PropertyType DWord -Force | Out-Null
        Good "IPv4 در سطح سیستم بر IPv6 ترجیح داده شد (بعد از ریستارت کامل می‌شود)."
    } catch { Warn "تنظیم رجیستری ناموفق بود (مهم نیست)." }
    Good "IPv6 روی $n کارت خاموش شد."
    Write-Host "برای برگرداندن:  .\vpn-killswitch.ps1 -EnableIPv6" -ForegroundColor Gray
    exit 0
}

if ($EnableIPv6) {
    Say "برگرداندن IPv6 ..."
    Get-NetAdapter | ForEach-Object {
        try { Enable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -ErrorAction Stop }
        catch { }
    }
    try {
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
            -Name "DisabledComponents" -ErrorAction SilentlyContinue
    } catch { }
    Good "IPv6 برگشت."
    exit 0
}

# ============================================================== روشن کردن کیل‌سوییچ
if ($Enable) {
    # ---- ۱) برنامه‌های مجاز
    $progs = @()
    if ($Program.Count -gt 0) { $progs = @($Program) }
    else {
        $progs = @(Find-TunnelPrograms)
        if ($progs.Count -eq 0) {
            Bad "هیچ برنامه‌ی تونلی در حال اجرا پیدا نشد."
            Write-Host ""
            Write-Host "دو راه داری:" -ForegroundColor Yellow
            Write-Host "  الف) اول به تونل وصل شو، بعد این اسکریپت را اجرا کن."
            Write-Host "  ب ) مسیر فایل exe را خودت بده، مثلا:"
            Write-Host '       .\vpn-killswitch.ps1 -Enable -Program "C:\v2rayN\bin\xray\xray.exe","C:\v2rayN\bin\sing_box\sing-box.exe"'
            exit 1
        }
    }

    foreach ($p in $progs) {
        if (-not (Test-Path -LiteralPath $p)) {
            Bad "این مسیر وجود ندارد: $p"
            Write-Host "کیل‌سوییچ روشن نشد (چون اگر مسیر غلط باشد اینترنتت کامل قطع می‌شود)."
            exit 1
        }
    }

    Say "برنامه‌هایی که اجازه‌ی عبور دارند:"
    $progs | ForEach-Object { Write-Host "    $_" }

    # ---- ۲) کارت مجازی تونل
    $tuns = if ($TunAlias) { @($TunAlias) } else { @(Find-TunAdapters) }
    if ($tuns.Count -gt 0) {
        Say "کارت‌های مجازی تونل:"
        $tuns | ForEach-Object { Write-Host "    $_" }
    } else {
        Warn "کارت مجازی تونل پیدا نشد. اگر حالت TUN را روشن نکرده‌ای اشکالی ندارد."
    }

    Write-Host ""
    Warn "الان خروجی پیش‌فرض ویندوز روی Block می‌رود."
    Warn "اگر تونل قطع شود، هیچ بایتی از کامپیوترت بیرون نمی‌رود."
    $ans = Read-Host "ادامه بدهم؟ (yes/no)"
    if ($ans -notmatch '^(y|yes|بله)$') { Write-Host "لغو شد."; exit 0 }

    # ---- ۳) پاک کردن قواعد قبلی
    Get-NetFirewallRule -DisplayName "$TAG-*" -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue

    # ---- ۴) ساخت قواعد اجازه، *قبل* از بستن خروجی
    $i = 0
    foreach ($p in $progs) {
        $i++
        New-NetFirewallRule -DisplayName "$TAG-Allow-Program-$i" `
            -Direction Outbound -Program $p -Action Allow `
            -Profile Any -Enabled True `
            -Description "kill-switch: allow tunnel process" | Out-Null
    }
    Good "$i قاعده برای برنامه‌ی تونل ساخته شد."

    $j = 0
    foreach ($t in $tuns) {
        $j++
        try {
            New-NetFirewallRule -DisplayName "$TAG-Allow-Tun-$j" `
                -Direction Outbound -InterfaceAlias $t -Action Allow `
                -Profile Any -Enabled True `
                -Description "kill-switch: allow all traffic on tunnel adapter" | Out-Null
        } catch { Warn "قاعده برای کارت «$t» ساخته نشد: $($_.Exception.Message)" }
    }
    if ($j -gt 0) { Good "$j قاعده برای کارت مجازی ساخته شد." }

    # شبکه‌ی محلی، DHCP و لوپ‌بک — تا شبکه‌ی خانه از کار نیفتد.
    # عمدا هیچ قاعده‌ای برای DNS (UDP/53) به بیرون ساخته نمی‌شود: آن قاعده
    # دقیقا همان راه لیکی است که این اسکریپت می‌خواهد ببندد. DNS باید از
    # داخل تونل برود.
    New-NetFirewallRule -DisplayName "$TAG-Allow-LocalSubnet" `
        -Direction Outbound -RemoteAddress LocalSubnet -Action Allow `
        -Profile Any -Enabled True | Out-Null
    New-NetFirewallRule -DisplayName "$TAG-Allow-DHCP" `
        -Direction Outbound -Protocol UDP -RemotePort 67,68 -Action Allow `
        -Profile Any -Enabled True | Out-Null
    New-NetFirewallRule -DisplayName "$TAG-Allow-Loopback" `
        -Direction Outbound -RemoteAddress 127.0.0.0/8 -Action Allow `
        -Profile Any -Enabled True | Out-Null
    Good "قواعد شبکه‌ی محلی و DHCP ساخته شد."

    # ---- ۵) روشن کردن همه‌ی پروفایل‌ها، بعد بستن خروجی پیش‌فرض.
    # اگر پروفایل خاموش بماند، DefaultOutboundAction اثری ندارد.
    try {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction Stop
        Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block -ErrorAction Stop
    } catch {
        Bad "کیل‌سوییچ روشن نشد: $($_.Exception.Message)"
        exit 1
    }
    $stillOff = @(Get-NetFirewallProfile | Where-Object { "$($_.Enabled)" -eq 'False' })
    if ($stillOff.Count -gt 0) {
        Bad ("کیل‌سوییچ روشن نشد. این پروفایل‌ها هنوز خاموش‌اند: " + ($stillOff.Name -join ', '))
        exit 1
    }
    Good "کیل‌سوییچ روشن شد."

    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor Green
    Write-Host " از این لحظه اگر تونل قطع شود، اینترنت کامل قطع می‌شود" -ForegroundColor Green
    Write-Host " و IP واقعی‌ات لو نمی‌رود." -ForegroundColor Green
    Write-Host "=========================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "نکته‌ی مهم: هر بار که v2rayN یا هسته‌اش را آپدیت کنی، مسیر یا" -ForegroundColor Yellow
    Write-Host "امضای فایل exe عوض می‌شود و باید این اسکریپت را دوباره اجرا کنی." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "برای خاموش کردن:  .\vpn-killswitch.ps1 -Disable" -ForegroundColor Gray
    exit 0
}

# ============================================================== خاموش کردن
if ($Disable) {
    Say "برگرداندن خروجی پیش‌فرض به Allow ..."
    Set-NetFirewallProfile -All -DefaultOutboundAction Allow
    Say "پاک کردن قواعد ..."
    $r = @(Get-NetFirewallRule -DisplayName "$TAG-*" -ErrorAction SilentlyContinue)
    if ($r.Count -gt 0) { $r | Remove-NetFirewallRule; Good "$($r.Count) قاعده پاک شد." }
    else { Write-Host "    قاعده‌ای نبود." -ForegroundColor Gray }
    Good "کیل‌سوییچ خاموش شد. اینترنت عادی برگشت."
    Write-Host "توجه: IPv6 اگر خاموش کرده بودی همچنان خاموش است." -ForegroundColor Gray
    Write-Host "برای برگرداندنش:  .\vpn-killswitch.ps1 -EnableIPv6" -ForegroundColor Gray
    exit 0
}

# ============================================================== راهنما
Write-Host ""
Write-Host "vpn-killswitch.ps1 — کیل‌سوییچ و کنترل IPv6" -ForegroundColor Cyan
Write-Host ""
Write-Host "  .\vpn-killswitch.ps1 -Status         وضعیت فعلی"
Write-Host "  .\vpn-killswitch.ps1 -DisableIPv6    خاموش کردن IPv6  <- این را اول بزن"
Write-Host "  .\vpn-killswitch.ps1 -Enable         روشن کردن کیل‌سوییچ (بعد از وصل شدن به تونل)"
Write-Host "  .\vpn-killswitch.ps1 -Disable        برگرداندن همه چیز"
Write-Host "  .\vpn-killswitch.ps1 -EnableIPv6     برگرداندن IPv6"
Write-Host ""
Write-Host "ترتیب پیشنهادی:" -ForegroundColor Yellow
Write-Host "  ۱) -DisableIPv6"
Write-Host "  ۲) به تونل وصل شو (حالت TUN روشن)"
Write-Host "  ۳) -Enable"
Write-Host "  ۴) python leaktest.py"
Write-Host ""
