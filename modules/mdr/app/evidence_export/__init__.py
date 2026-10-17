"""Vendetta evidence export: build sealed, self-verifying chain-of-custody packages.

The two entry points a module needs:

    from evidence_export import build_package          # produce a sealed package
    from evidence_export import verify_package          # verify one (same code the
                                                        # standalone verifier runs)
"""
from .exporter import SCHEME, build_package
from .verifier import verify_chain, verify_package

__all__ = ["build_package", "verify_package", "verify_chain", "SCHEME"]
