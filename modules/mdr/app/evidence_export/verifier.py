"""Library access to the verification logic.

The authoritative implementation lives in the standalone ``verify_evidence.py`` at the
package root, because that file is what gets embedded into every export and handed to
third parties. This wrapper loads it so the builder and the tests use the exact same
code, rather than a second copy that could drift.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_STANDALONE = Path(__file__).resolve().parent.parent / "verify_evidence.py"


def _load():
    spec = importlib.util.spec_from_file_location("vendetta_verify_evidence", _STANDALONE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_impl = _load()

verify_chain = _impl.verify_chain
verify_package = _impl.verify_package
GENESIS = _impl.GENESIS
SCHEME = _impl.SCHEME
