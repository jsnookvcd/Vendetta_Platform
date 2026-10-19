"""Bounded CSS selector evaluation for parser profiles.

Profile selectors come from analysts (the Priority Groups editor) and YAML
files, and they run against HTML from hostile sites. A pathological selector or
page can make soupsieve run for a very long time, so every extraction that
uses profile selectors goes through this module:

  limits    a selector longer than MAX_SELECTOR_LENGTH (200) characters or with
            more than MAX_SELECTOR_PARTS (10) comma-separated parts is refused
  timeout   extraction runs in a separate spawned process that is terminated
            after TIMEOUT_SECONDS (5); the caller gets SelectorTimeout

The editor preview shows the error to the analyst. The crawl treats a refused
profile or a timeout as yielding no entries for that run."""
from __future__ import annotations

import multiprocessing

MAX_SELECTOR_LENGTH = 200
MAX_SELECTOR_PARTS = 10
TIMEOUT_SECONDS = 5

LEAK_FIELDS = ("list_selector", "title_selector", "link_selector", "desc_selector", "date_selector",
               "post_title_selector", "post_body_selector")
FORUM_FIELDS = ("thread_selector", "thread_title_selector", "thread_link_selector", "post_selector",
                "author_selector", "date_selector", "body_selector")


class SelectorTimeout(Exception):
    """Extraction did not finish within the timeout and its process was terminated."""


class SelectorFailed(Exception):
    """Extraction raised inside the subprocess or the subprocess died."""


def selector_problem(selector: str) -> str:
    """Empty string when the selector is within the limits, else the reason."""
    sel = selector or ""
    if len(sel) > MAX_SELECTOR_LENGTH:
        return f"selector is {len(sel)} characters; the limit is {MAX_SELECTOR_LENGTH}"
    if len(sel.split(",")) > MAX_SELECTOR_PARTS:
        return f"selector has {len(sel.split(','))} comma-separated parts; the limit is {MAX_SELECTOR_PARTS}"
    return ""


def profile_problem(profile: dict, fields: tuple[str, ...]) -> str:
    """The first selector field of a profile that breaks the limits, as text."""
    for f in fields:
        reason = selector_problem(str(profile.get(f) or ""))
        if reason:
            return f"{f.replace('_', ' ')}: {reason}"
    return ""


def _child(conn, fn, args) -> None:
    try:
        conn.send((True, fn(*args)))
    except BaseException as e:  # noqa: BLE001
        conn.send((False, f"{type(e).__name__}: {e}"[:500]))
    finally:
        conn.close()


def run_bounded(fn, *args, timeout: float | None = None):
    """fn(*args) in a fresh spawned process, killed after the timeout. fn must be
    a module-level function and its arguments and result picklable."""
    ctx = multiprocessing.get_context("spawn")
    recv, send = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_child, args=(send, fn, args), daemon=True)
    proc.start()
    send.close()
    try:
        if not recv.poll(TIMEOUT_SECONDS if timeout is None else timeout):
            raise SelectorTimeout(f"selector extraction took longer than {TIMEOUT_SECONDS if timeout is None else timeout} seconds")
        try:
            ok, value = recv.recv()
        except EOFError as e:
            raise SelectorFailed("selector extraction process exited without a result") from e
    finally:
        recv.close()
        if proc.is_alive():
            proc.terminate()
            proc.join(1)
            if proc.is_alive():
                proc.kill()
        proc.join(1)
    if not ok:
        raise SelectorFailed(value)
    return value


# ---------------------------------------------------------------- work done in the subprocess
def extract_entries(html: str, prof: dict, base_url: str = "", limit: int | None = None) -> list[dict]:
    from .profile_store import extract

    return extract(html, prof, base_url=base_url, limit=limit)


def post_fields(html: str, title_selector: str, body_selector: str) -> tuple[str, str]:
    from .fetch import select_text, soup_of

    soup = soup_of(html)
    return select_text(soup, title_selector), select_text(soup, body_selector)


def forum_rows(html: str, profile: dict) -> list[tuple[str, str]]:
    from .fetch import select_href, select_text, soup_of

    try:
        rows = soup_of(html).select(profile["thread_selector"]) if profile.get("thread_selector") else []
    except Exception:  # noqa: BLE001
        return []
    return [(select_text(r, profile.get("thread_title_selector", "")),
             select_href(r, profile.get("thread_link_selector", ""))) for r in rows]


def forum_posts(html: str, profile: dict) -> list[tuple[str, str, str]]:
    from .fetch import select_text, soup_of

    try:
        posts = soup_of(html).select(profile["post_selector"]) if profile.get("post_selector") else []
    except Exception:  # noqa: BLE001
        return []
    return [(select_text(p, profile.get("author_selector", "")), select_text(p, profile.get("date_selector", "")),
             select_text(p, profile.get("body_selector", ""))) for p in posts]


# ---------------------------------------------------------------- bounded entry points
# Each looks the worker function up at call time, so tests can replace it.
def safe_extract_entries(html: str, prof: dict, base_url: str = "", limit: int | None = None) -> list[dict]:
    return run_bounded(extract_entries, html, prof, base_url, limit)


def safe_post_fields(html: str, title_selector: str, body_selector: str) -> tuple[str, str]:
    return run_bounded(post_fields, html, title_selector, body_selector)


def safe_forum_rows(html: str, profile: dict) -> list[tuple[str, str]]:
    return run_bounded(forum_rows, html, profile)


def safe_forum_posts(html: str, profile: dict) -> list[tuple[str, str, str]]:
    return run_bounded(forum_posts, html, profile)
