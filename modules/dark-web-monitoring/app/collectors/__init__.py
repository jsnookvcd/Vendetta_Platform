"""Collectors. Each exposes run(db), which returns a small summary dict ({"ok", "error", counts}).
The worker schedules them through the registry in app/connectors.py."""
