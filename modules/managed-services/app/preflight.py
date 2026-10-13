"""Connectivity preflight for the five tools.

Each check makes the lightest real read a tool offers and reports ok/fail with a
one-line detail (a count, or the error). It is what turns a live shakeout into one
action: drop real credentials in the environment, run the check, and see green or a
precise reason. Run it from Settings in the console, or on the command line:

    python -m app.preflight

A check only runs for a configured tool; unconfigured tools report "not
configured" and are skipped, not failed."""
from __future__ import annotations

from dataclasses import dataclass

from . import connectors
from .config import TOOL_NAMES, TOOLS
from .connectors import ConnectorError


@dataclass
class Result:
    tool: str
    ok: bool
    configured: bool
    detail: str


def _check(tool: str) -> Result:
    conn = connectors.get(tool)
    if not getattr(conn, "configured", False):
        return Result(tool, False, False, "not configured")
    try:
        if tool == "superops":
            n = len(conn.list_clients())
            detail = f"{n} client{'s' if n != 1 else ''} visible"
        elif tool == "sentinelone":
            n = len(conn.sites())
            detail = f"{n} site{'s' if n != 1 else ''} visible"
        elif tool == "crowdstrike":
            n = len(conn.children())
            detail = f"{n} child CID{'s' if n != 1 else ''} visible"
        elif tool == "huntress":
            n = len(conn.organizations())
            detail = f"{n} organization{'s' if n != 1 else ''} visible"
        elif tool == "acronis":
            n = len(conn.tenants())
            detail = f"{n} customer tenant{'s' if n != 1 else ''} visible"
        else:  # pragma: no cover
            return Result(tool, False, True, "no check defined")
        return Result(tool, True, True, detail)
    except ConnectorError as e:
        return Result(tool, False, True, str(e))
    except Exception as e:  # noqa: BLE001
        return Result(tool, False, True, f"unexpected: {type(e).__name__}: {e}")


def run(tools: list[str] | None = None) -> list[Result]:
    return [_check(t) for t in (tools or TOOLS)]


def main() -> int:
    results = run()
    worst = 0
    for r in results:
        if not r.configured:
            mark, state = "-", "skipped"
        elif r.ok:
            mark, state = "ok", "ok"
        else:
            mark, state = "FAIL", "fail"
            worst = 1
        print(f"[{mark:>4}] {TOOL_NAMES[r.tool]:<20} {r.detail}")
    return worst


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
