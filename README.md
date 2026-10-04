# vpn-stack

Private copy of the project scripts.

- `sources/` is the canonical set. Every script here is the current version.
- `patches/` holds only migration and diagnostic helpers for a panel that is
  already running an older install. Nothing here duplicates `sources/`.
- The live link list is not in this repo.

Do not add client ids, reality keys, secret paths, or live links to this repo.
`sources/xray-cdn-compat.json` ships with `PUT-YOUR-UUID-HERE` and
`PUT-YOUR-PATH-N-HERE` placeholders for that reason; fill them from
`/etc/vpnstack/state.env` on the server, not here.

## What runs where

| file | runs on | what it does |
|---|---|---|
| `sources/vpn-setup.sh` | server | full install: nginx, Xray, cert, decoy site, links |
| `sources/add-user.sh` | server | add / del / list / links / qr |
| `sources/gen-clients.py` | server | per-user Xray and sing-box configs with failover |
| `sources/cfscan.py` | your PC | fastest Cloudflare IPs for your line |
| `sources/frontscan.py` | your PC | which edge network can be a front |
| `sources/irnet_probe.py` | your PC | what crosses the border |
| `sources/leaktest.py` | your PC, while connected | IP and DNS leak test |
| `sources/udp_echo_server.py` | server | UDP echo, only for `irnet_probe.py` |
| `sources/vpn-killswitch.ps1` | Windows, as Administrator | kill switch and IPv6 control |
| `sources/xray-cdn-compat.json` | client | 18-front template, placeholders inside |
| `patches/gcloud-firewall-fix.sh` | Cloud Shell | trims an old 4-rule firewall down to 2 |
| `patches/xray-stats-listen.sh` | server | adds `api.listen` to an old `config.json` |
| `patches/termux-cf-hu-check.py` | phone | checks one HTTPUpgrade path on the edge |

New installs do not need `patches/`: `vpn-setup.sh` already writes
`api.listen` and already generates the two-rule firewall script.

## Ports

`vpn-setup.sh` takes these from the environment and stores them in
`/etc/vpnstack/state.env`, so every other script reads the same values:

| variable | default | meaning |
|---|---|---|
| `EDGE_PORT` | 443 | port the client dials on the Cloudflare edge |
| `ORIGIN_PORT` | 8443 | port Cloudflare dials on your server |
| `REALITY_PORT` | 443 | direct path C, on the server itself |
| `XHTTP_LOCAL` / `WS_LOCAL` | 2001 / 2002 | loopback ports nginx proxies to |
| `OPEN_DIRECT` | 0 | also open path C and port 80 in the firewall |
| `OPEN_UDP_TEST` | 0 | open the temporary UDP test ports |

The edge-port to origin-port mapping lives in the Cloudflare dashboard, not in
this repo.

## Known gap: the PDF

`sources/guide-2026-10-01.pdf` is a historical document and was not rewritten.
Where it disagrees with the scripts, the scripts are now right:

- the guide says "exactly two firewall rules" — that is now the default
- the guide says to drop path C — path C is now off unless `OPEN_DIRECT=1`
- the guide says per-user stats are live — `api.listen` is now in the config
- the guide says `gen-clients.py` reads users from `state.env` — it now reads
  them from `config.json` and rewrites `UUID_LIST` to match
- the guide shows `python irnet_probe.py` with no arguments — `--vm-ip` and
  `--domain` are now required
