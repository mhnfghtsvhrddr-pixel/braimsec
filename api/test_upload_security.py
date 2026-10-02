"""Upload-handler hardening tests (pre-launch security).

Covers a genuine path-traversal hole in POST /api/scans: the multipart
``file.filename`` was joined directly onto the per-upload workdir, so a
client sending ``filename="../../evil.zip"`` wrote outside the sandbox.
The handler now stores ``os.path.basename(...)`` (with "." / ".." / empty
falling back to ``upload.zip``).

- traversal filename  -> contained in workdir, DB target_name sanitized
- dot-dot filename    -> falls back to upload.zip
- normal upload       -> still works end to end (extract + scan created)
- non-zip upload      -> 400, nothing stored
"""
import io
import os
import sys
import tempfile
import zipfile

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-upload-")
os.environ["BRAIMSEC_DB"] = os.path.join(_tmp, "test.db")
os.environ["BRAIMSEC_API_KEY"] = "test-key-123"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
from database import get_db  # noqa: E402

HEADERS = {"x-api-key": "test-key-123"}


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """Fresh rate-limiter budget; never run a real scan in these tests."""
    main.limiter._storage.reset()
    monkeypatch.setattr(main, "enqueue_scan", lambda *a, **k: "inline")
    yield
    main.limiter._storage.reset()


def _zip_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("app.py", "print('hello')\n")
    return buf.getvalue()


def _upload(client, filename, payload, workdir, monkeypatch):
    """Route tempfile.mkdtemp into a known dir so we can assert containment."""
    workdir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(main.tempfile, "mkdtemp", lambda prefix="", dir=None: str(workdir))
    return client.post(
        "/api/scans",
        headers=HEADERS,
        files={"file": (filename, payload, "application/zip")},
    )


def _target_name(scan_id):
    db = get_db()
    row = db.execute("SELECT target_name FROM scans WHERE id=?",
                     (scan_id,)).fetchone()
    db.close()
    return row["target_name"]


def test_traversal_filename_is_contained(tmp_path, monkeypatch):
    workdir = tmp_path / "workdir"
    with TestClient(main.app) as client:
        r = _upload(client, "../../evil.zip", _zip_bytes(), workdir, monkeypatch)
    assert r.status_code == 200, r.text
    # Nothing escaped the workdir...
    assert not (tmp_path / "evil.zip").exists()
    # ...the stored file uses the sanitized basename...
    assert (workdir / "evil.zip").is_file()
    # ...and the DB records the sanitized name.
    assert _target_name(r.json()["scan_id"]) == "evil.zip"


def test_dotdot_filename_falls_back(tmp_path, monkeypatch):
    workdir = tmp_path / "workdir"
    with TestClient(main.app) as client:
        r = _upload(client, "..", _zip_bytes(), workdir, monkeypatch)
    assert r.status_code == 200, r.text
    assert (workdir / "upload.zip").is_file()
    assert _target_name(r.json()["scan_id"]) == "upload.zip"


def test_normal_upload_still_works(tmp_path, monkeypatch):
    workdir = tmp_path / "workdir"
    with TestClient(main.app) as client:
        r = _upload(client, "myproject.zip", _zip_bytes(), workdir, monkeypatch)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "queued" and body["scan_id"]
    assert _target_name(body["scan_id"]) == "myproject.zip"
    # Zip was extracted for scanning.
    assert (workdir / "src" / "app.py").is_file()


def test_non_zip_rejected(tmp_path, monkeypatch):
    workdir = tmp_path / "workdir"
    with TestClient(main.app) as client:
        r = _upload(client, "evil.exe", b"MZ\x90\x00not a zip", workdir,
                    monkeypatch)
    assert r.status_code == 400, r.text
    assert "zip" in r.json()["detail"].lower()
