"""Connector registry: one instance per tool, created on demand."""
from __future__ import annotations

from .acronis import Acronis
from .aws import AWS
from .base import ConnectorError  # noqa: F401  (re-exported for callers)
from .crowdstrike import CrowdStrike
from .entra import Entra
from .huntress import Huntress
from .sentinelone import SentinelOne
from .superops import SuperOps

_CLASSES = {c.tool: c for c in (SuperOps, SentinelOne, CrowdStrike, Huntress, Acronis, Entra, AWS)}
_instances: dict[str, object] = {}


def get(tool: str):
    if tool not in _CLASSES:
        raise ConnectorError(f"unknown tool {tool!r}")
    if tool not in _instances:
        _instances[tool] = _CLASSES[tool]()
    return _instances[tool]


def reset() -> None:
    """Drop cached instances (tests, or after settings change)."""
    _instances.clear()
