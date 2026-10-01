"""End-to-end: API -> queue -> REAL Semgrep/Gitleaks, no mocks.

Unlike the engine unit tests, this exercises the whole production path:
POST /api/scans, queue routing (inline BackgroundTasks here), the real
scan worker, and the real engine binaries writing real findings rows.

The target is crafted to trip deterministic, network-free rules:
- a GitHub workflow with script injection -> our own semgrep rule
  ``braimsec.gha.script-injection``
- a stripe test key -> gitleaks ``stripe-access-token``

If either engine regresses (binary missing, rule broken, worker crash),
this test fails. Nothing here is mocked.
"""
import os
import sys
import tempfile
import time

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-e2eeng-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-key-123")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
from billing import create_org, ensure_owner_org, provision_key  # noqa: E402
from database import init_db  # noqa: E402

init_db()


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


@pytest.fixture()
def ctx():
    ensure_owner_org()
    org = create_org("E2ECorp", plan="free")
    member = provision_key(org, "e2e", actor="owner", role="member")
    return {"org": org, "member": member}


def _target():
    from pathlib import Path
    d = Path(main.SCAN_ROOT) / "pytest-e2e-real"
    wf = d / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "ci.yml").write_text(
        "name: ci\non: [pull_request]\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n"
        '      - run: echo "building ${{ github.event.pull_request.title }}"\n')
    # NOTE: built at runtime via concatenation so the committed file never
    # contains a literal sk_live_* secret (GitHub push protection would
    # block it). This is Stripe's public documentation example key, not real.
    _stripe = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
    (d / "config.py").write_text(f'stripe_key = "{_stripe}"\n')
    return str(d)


def _h(key):
    return {"x-api-key": key}


def test_api_to_queue_to_real_engines(ctx):
    with TestClient(main.app) as c:
        r = c.post("/api/scans", headers=_h(ctx["member"]),
                   data={"target_path": _target()})
        assert r.status_code == 200, r.text
        scan_id = r.json()["scan_id"]

        # The inline queue runs the worker as a background task; poll
        # honestly in case scheduling ever becomes asynchronous.
        status = None
        for _ in range(60):
            s = c.get(f"/api/scans/{scan_id}",
                      headers=_h(ctx["member"])).json()
            status = s["status"]
            if status in ("done", "failed"):
                break
            time.sleep(2)
        assert status == "done", f"scan ended as {status}: {s.get('error')}"

        findings = c.get(f"/api/scans/{scan_id}/results",
                         headers=_h(ctx["member"])).json()
        by_rule = {(f["tool"], f["rule_id"]) for f in findings}
        assert any(t == "semgrep" and "script-injection" in r_
                   for t, r_ in by_rule), f"no semgrep hit in {by_rule}"
        assert ("gitleaks", "stripe-access-token") in by_rule, \
            f"no gitleaks hit in {by_rule}"
