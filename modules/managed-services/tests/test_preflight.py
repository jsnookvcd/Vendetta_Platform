"""Preflight: the per-tool connectivity check, with fake connectors in the
registry, and the Settings route that renders it."""
from app import connectors, preflight
from app.connectors import ConnectorError


class _Conn:
    configured = True

    def __init__(self, tool, raise_err=None, n=2):
        self.tool = tool
        self._raise = raise_err
        self._n = n

    def _rows(self):
        if self._raise:
            raise self._raise
        return list(range(self._n))

    list_clients = sites = children = organizations = tenants = lambda self: self._rows()


class _Unconfigured:
    configured = False


def _install(**tools):
    for t, conn in tools.items():
        connectors._instances[t] = conn


def test_run_reports_ok_fail_and_unconfigured():
    _install(
        superops=_Conn("superops", n=3),
        sentinelone=_Conn("sentinelone", raise_err=ConnectorError("SentinelOne: invalid API token")),
        crowdstrike=_Unconfigured(),
        huntress=_Conn("huntress", n=1),
        acronis=_Conn("acronis", n=5),
    )
    by = {r.tool: r for r in preflight.run()}
    assert by["superops"].ok and "3 clients" in by["superops"].detail
    assert by["sentinelone"].configured and not by["sentinelone"].ok
    assert "invalid API token" in by["sentinelone"].detail
    assert not by["crowdstrike"].configured and by["crowdstrike"].detail == "not configured"
    assert by["huntress"].ok and "1 organization" in by["huntress"].detail
    assert by["acronis"].ok and "5 customer tenants" in by["acronis"].detail


def test_unexpected_error_is_caught():
    _install(superops=_Conn("superops", raise_err=RuntimeError("boom")))
    r = [x for x in preflight.run(["superops"])][0]
    assert not r.ok and "unexpected" in r.detail


def test_main_returns_nonzero_on_failure(capsys):
    _install(
        superops=_Conn("superops", n=1),
        sentinelone=_Conn("sentinelone", raise_err=ConnectorError("down")),
        crowdstrike=_Unconfigured(), huntress=_Unconfigured(), acronis=_Unconfigured(),
    )
    code = preflight.main()
    out = capsys.readouterr().out
    assert code == 1 and "FAIL" in out and "SentinelOne" in out


def test_settings_route_renders_results(admin):
    _install(
        superops=_Conn("superops", n=2), sentinelone=_Unconfigured(), crowdstrike=_Unconfigured(),
        huntress=_Unconfigured(), acronis=_Unconfigured(),
    )
    r = admin.post("/settings/preflight")
    assert r.status_code == 200
    assert "2 clients visible" in r.text and "Test connections" in r.text
