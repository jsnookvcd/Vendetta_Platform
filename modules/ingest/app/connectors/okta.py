"""Okta System Log puller.

A read-only admin API token (SSWS) from the client's Okta org, or an OAuth service app
with okta.logs.read; this puller takes the SSWS token. The org domain must be an Okta
hosted domain (*.okta.com, *.oktapreview.com, *.okta-emea.com); custom domains are
refused so the token is only ever sent to Okta.

GET https://{okta_domain}/api/v1/logs?since=...&sortOrder=ASCENDING&limit=1000, then
the Link rel="next" URL until a page is empty. In ascending polling mode Okta always
returns a next link, so an empty page ends the run. `since` is inclusive; the event at
the boundary is fetched again and dropped by its uuid.
"""
from __future__ import annotations

from .. import ocsf
from . import ConnectorError, Puller, puller
from ._util import from_ms, https_base, json_body, same_host, z

SUFFIXES = (".okta.com", ".oktapreview.com", ".okta-emea.com")
LIMIT = 1000

SPEC = {
    "credentials": {"api_token": "Okta API token (SSWS) of a read-only administrator"},
    "config": {"okta_domain": "Okta org domain, e.g. acme.okta.com"},
}


@puller
class OktaSystemLog(Puller):
    source = "okta_system_log"
    spec = SPEC

    def pages(self):
        base = https_base(self.config.get("okta_domain"), suffixes=SUFFIXES, what="okta_domain")
        host = base.split("://", 1)[1]
        self.need("api_token")
        headers = {"Authorization": f"SSWS {self.credentials['api_token']}", "Accept": "application/json"}
        since = self.since()
        newest = since
        url = f"{base}/api/v1/logs"
        params = {"since": z(since, ms=True), "sortOrder": "ASCENDING", "limit": str(LIMIT)}
        seen_urls = set()
        while url:
            r = self.request("GET", url, headers=headers, params=params)
            rows = json_body(r, host)
            if not isinstance(rows, list):
                raise ConnectorError("Okta returned an unexpected response")
            if not rows:
                return
            for row in rows:
                ms = ocsf.to_epoch_ms(row.get("published")) if isinstance(row, dict) else None
                if ms is not None:
                    newest = max(newest, from_ms(ms))
            nxt = (r.links.get("next") or {}).get("url")
            yield rows, {"since": newest.isoformat()}
            if not nxt:
                return
            nxt = same_host(nxt, host)
            if nxt in seen_urls:
                return
            seen_urls.add(nxt)
            url, params = nxt, None
