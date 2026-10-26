# Third-party sources and software

The dark web module reads the services and lists below at run time. It vendors none of their code.

## RansomLook

Project: github.com/RansomLook/RansomLook. Code licensed GPL-3.0 (the project website states AGPL-3.0).
Data from ransomlook.io, API responses included: CC BY 4.0. Commercial use is allowed with credit.
Use: `app/ransomlook.py` reads the HTTP API of the public instance or of Vendetta's self-hosted instance. Items and sources carry `attribution` and `license` in meta. The self-hosted instance (`infra/ransomlook`) builds RansomLook unmodified from upstream at a pinned commit and runs it as a separate container on the internal network. `infra/ransomlook/bootstrap_groups.py` runs inside that container against RansomLook's code and is GPL-3.0-or-later.

## Hudson Rock

Service: Cavalier free OSINT tools (hudsonrock.com/free-tools), endpoint `cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain`. No key.
Use: `app/collectors/infostealers.py`, one request per client domain per day. The request and response shape was read from theHarvester (github.com/laramies/theHarvester, GPL-2.0), `theHarvester/discovery/hudsonrocksearch.py`; no code was copied. Terms of use for the free tools were not readable from the build sandbox and should be reviewed.

## deepdarkCTI

Project: github.com/fastfire/deepdarkCTI. Repository licensed GPL-3.0; the lists are names, addresses and statuses.
Use: `app/deepdarkcti.py` fetches the raw markdown daily and keeps online onion leak sites and public Telegram channels. Seeded sources carry `attribution` in meta.

## Telegram

Service: the public channel web preview at t.me/s/<channel>. No account or API key.
Use: `app/collectors/telegram_web.py`.

## ransomware.live

Service: api-pro.ransomware.live, free PRO key from my.ransomware.live. See `app/ransomware_live.py`.
