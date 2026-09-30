"""Regression test for the scan_engine binary-path isolation bug.

Invariant: SEMGREP_BIN / GITLEAKS_BIN must be pinned in the environment
BEFORE scan_engine is first imported, because scan_engine freezes them
into module-level constants at import time. The root conftest.py
guarantees this for every pytest run; these tests fail if the pinning is
ever lost (e.g. conftest removed) and an api test imports scan_engine
first via tasks.py.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SG = os.path.expanduser("~/workspace/venvs/sgvenv/bin/semgrep")
GL = os.path.expanduser("~/workspace/bin/gitleaks")

import scan_engine  # noqa: E402

needs_bins = pytest.mark.skipif(
    not (os.path.isfile(SG) and os.path.isfile(GL)),
    reason="engine binaries not installed",
)


@needs_bins
def test_semgrep_bin_pinned_before_scan_engine_import():
    assert os.environ.get("SEMGREP_BIN") == SG
    assert scan_engine.SEMGREP_BIN == SG
    assert os.path.isfile(scan_engine.SEMGREP_BIN)


@needs_bins
def test_gitleaks_bin_pinned_before_scan_engine_import():
    assert os.environ.get("GITLEAKS_BIN") == GL
    assert scan_engine.GITLEAKS_BIN == GL
    assert os.path.isfile(scan_engine.GITLEAKS_BIN)
