"""Tests for the subscription foundation: orgs, API keys, quotas, isolation.

Run: BRAIMSEC_DB must be isolated per run (set below before importing main).
"""
import os
import sys
import tempfile

os.environ["BRAIMSEC_API_KEY"] = "master-key-for-tests"
os.environ["BRAIMSEC_DB"] = os.path.join(tempfile.gettempdir(), "braimsec_test_billing.db")
os.environ["BRAIMSEC_SCAN_ROOT"] = os.path.join(tempfile.gettempdir(), "braimsec_test_scans")
# Real engine binaries so API-level scans complete end-to-end.
os.environ["SEMGREP_BIN"] = os.path.expanduser("~/.sttenv/bin/semgrep")
os.environ["GITLEAKS_BIN"] = os.path.expanduser("~/workspace/bin/gitleaks")
for p in (os.environ["BRAIMSEC_DB"],):
    if os.path.exists(p):
        os.remove(p)
os.makedirs(os.environ["BRAIMSEC_SCAN_ROOT"], exist_ok=True)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import main  # noqa: E402
from billing import (  # noqa: E402
    OWNER_ORG_ID, consume_scan, create_org, ensure_owner_org, provision_key,
    quota_status, revoke_key, set_plan, verify_key,
)
from database import init_db  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

init_db()
ensure_owner_org()

results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


# --- Module-level: keys -------------------------------------------------------
org_a = create_org("Acme", plan="free")
key_a = provision_key(org_a, "ci")
check("provision_key returns raw key once", key_a.startswith("bs_") and len(key_a) > 40)

v = verify_key(key_a)
check("verify_key maps key -> org+plan", v and v["org_id"] == org_a and v["plan"] == "free")
check("verify_key rejects garbage", verify_key("bs_nope") is None)

# Raw key must NOT be stored anywhere recoverable
from database import get_db  # noqa: E402
db = get_db()
row = db.execute("SELECT key_hash, key_prefix FROM api_keys WHERE org_id=?", (org_a,)).fetchone()
check("only hash stored (not raw key)", key_a not in row["key_hash"] and row["key_prefix"] == key_a[:8])
db.close()

# --- Module-level: quotas ------------------------------------------------------
for _ in range(10):
    assert consume_scan(org_a), "free plan should allow 10 scans"
allowed, used, quota = quota_status(org_a)
check("free quota exhausted after 10", not allowed and used == 10 and quota == 10)
check("consume_scan refuses 11th", consume_scan(org_a) is False)

set_plan(org_a, "pro")
allowed, used, quota = quota_status(org_a)
check("upgrade to pro re-opens quota", allowed and quota == 500)
check("usage counter preserved across upgrade", used == 10)

# --- API-level -----------------------------------------------------------------
with TestClient(main.app) as client:
    H = {"x-api-key": key_a}

    check("no key -> 401", client.get("/api/scans").status_code == 401)
    check("wrong key -> 401",
          client.get("/api/scans", headers={"x-api-key": "bs_wrong"}).status_code == 401)

    # Org A is on pro now with 10 used -> API scan allowed
    target = os.environ["BRAIMSEC_SCAN_ROOT"]
    r = client.post("/api/scans", headers=H, data={"target_path": target})
    check("scan created on pro plan", r.status_code == 200 and "scan_id" in r.json())

    # Exhaust quota at module level, then API must return 402
    for _ in range(500 - 11):
        consume_scan(org_a)
    allowed, used, quota = quota_status(org_a)
    assert not allowed, f"expected exhausted, got {allowed} {used}/{quota}"
    r = client.post("/api/scans", headers=H, data={"target_path": target})
    check("quota exhausted -> 402", r.status_code == 402)

    # Master key (backward compat): still works, maps to owner org
    MH = {"x-api-key": "master-key-for-tests"}
    r = client.post("/api/scans", headers=MH, data={"target_path": target})
    check("master key still works", r.status_code == 200)
    scan_id = r.json()["scan_id"]
    r = client.get(f"/api/scans/{scan_id}", headers=H)
    check("org A cannot see owner's scan (isolation)", r.status_code == 404)
    r = client.get("/api/scans", headers=H)
    check("org A list_scans excludes owner scans",
          all(s.get("org_id") == org_a for s in r.json()))

    # Revoked key -> 401
    key_b = provision_key(org_a, "temp")
    v2 = verify_key(key_b)
    revoke_key(v2["key_id"])
    check("revoked key -> 401",
          client.get("/api/scans", headers={"x-api-key": key_b}).status_code == 401)

print(f"\n{sum(1 for _, ok in results if ok)}/{len(results)} billing tests passed")
sys.exit(0 if all(ok for _, ok in results) else 1)
