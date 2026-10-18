"""The container starts the worker with `python -m app.worker`. Running the module
that way must reach main() with every name it uses already defined, which the
build_scheduler unit tests cannot catch because they import the module first."""
import os
import subprocess
import sys

MODULE_DIR = os.path.dirname(os.path.dirname(__file__))

PROBE = r"""
import runpy, sys, types
import app.boot, app.db
app.boot.check = lambda: None
app.db.init_db = lambda: None
import app.fetch
app.fetch.tor_check = lambda: {"IsTor": True, "IP": "198.51.100.7"}
from apscheduler.schedulers.blocking import BlockingScheduler
started = []
BlockingScheduler.start = lambda self, *a, **k: started.append(len(self.get_jobs()))
import app.worker as w
for name in dir(w):
    if name.startswith(("_seed", "_recover", "phase2_startup")):
        setattr(w, name, lambda *a, **k: None)
sys.modules.pop("app.worker", None)
try:
    runpy.run_module("app.worker", run_name="__main__", alter_sys=True)
except SystemExit:
    pass
print("STARTED", started)
"""


def test_worker_runs_as_main_without_name_errors():
    env = {**os.environ, "SECRET_KEY": "x", "ALLOW_INSECURE_DEFAULTS": "true"}
    r = subprocess.run([sys.executable, "-c", PROBE], cwd=MODULE_DIR, env=env,
                       capture_output=True, text=True, timeout=120)
    out = r.stdout + r.stderr
    assert "NameError" not in out, out[-3000:]
    assert "STARTED [" in out, out[-3000:]
