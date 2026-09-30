"""Root pytest configuration: pin engine binary paths before any import.

Why this exists (test-isolation bug, fixed 2026-10-01):
``scanner/scan_engine.py`` freezes ``SEMGREP_BIN`` / ``GITLEAKS_BIN`` at
import time from the environment (``os.environ.get(..., "semgrep")``).
Test modules used to set those variables with ``os.environ.setdefault``
at their own import time, so whether the e2e tests saw the real binaries
depended on import order. In a full ``api/ + scanner/`` run,
``api/test_async_queue.py`` imports ``tasks``, which imports
``scan_engine`` before any scanner test module ran its ``setdefault``;
the binary then resolved to bare ``"semgrep"`` (not on PATH) and 4 e2e
tests failed with ``EngineError: binary not found: semgrep`` while the
same files passed standalone.

pytest imports this ``conftest.py`` before any test module, so the paths
are pinned deterministically regardless of collection order.
``setdefault`` (not assignment) keeps an explicitly exported environment
authoritative over these defaults.
"""
import os

_SEMGREP = os.path.expanduser("~/workspace/venvs/sgvenv/bin/semgrep")
_GITLEAKS = os.path.expanduser("~/workspace/bin/gitleaks")

os.environ.setdefault("SEMGREP_BIN", _SEMGREP)
os.environ.setdefault("GITLEAKS_BIN", _GITLEAKS)
