"""Unit tests for scanner/incremental.py (no engines, no DB)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from incremental import (  # noqa: E402
    fingerprint_tree, diff_fingerprints, import_hops, plan_incremental,
    merge_findings, escape_rate,
)


@pytest.fixture()
def tree(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("y = 2\n")
    (tmp_path / "notes.txt").write_text("not scanned\n")
    return tmp_path


def test_fingerprint_only_scannable_exts(tree):
    fp = fingerprint_tree(str(tree))
    assert set(fp) == {"a.py", "b.py"}


def test_fingerprint_changes_on_edit(tree):
    before = fingerprint_tree(str(tree))
    (tree / "a.py").write_text("x = 2\n")
    after = fingerprint_tree(str(tree))
    assert before["a.py"] != after["a.py"]
    assert before["b.py"] == after["b.py"]


def test_diff_added_modified_deleted(tree):
    old = fingerprint_tree(str(tree))
    (tree / "a.py").write_text("x = 2\n")
    (tree / "c.py").write_text("z = 3\n")
    (tree / "b.py").unlink()
    new = fingerprint_tree(str(tree))
    added, modified, deleted = diff_fingerprints(old, new)
    assert added == {"c.py"} and modified == {"a.py"} and deleted == {"b.py"}


def test_diff_empty_old_is_all_added(tree):
    new = fingerprint_tree(str(tree))
    added, modified, deleted = diff_fingerprints({}, new)
    assert added == {"a.py", "b.py"} and not modified and not deleted


@pytest.fixture()
def import_tree(tmp_path):
    # main.py -> imports lib ; views.py -> imports main ; lib.py -> standalone
    (tmp_path / "lib.py").write_text("def helper():\n    return 1\n")
    (tmp_path / "main.py").write_text("import lib\n\nprint(lib.helper())\n")
    (tmp_path / "views.py").write_text("import main\n\nmain.x = 1\n")
    (tmp_path / "other.py").write_text("x = 1\n")
    return tmp_path


def test_import_hops_reverse(import_tree):
    # lib changed -> main.py imports lib -> in scope
    scope = import_hops(str(import_tree), {"lib.py"})
    assert {"lib.py", "main.py"} <= scope
    assert "other.py" not in scope


def test_import_hops_forward_and_reverse(import_tree):
    # main changed -> lib (forward) + views (reverse) in scope
    scope = import_hops(str(import_tree), {"main.py"})
    assert {"main.py", "lib.py", "views.py"} <= scope
    assert "other.py" not in scope


def test_import_hops_non_python_is_self_only(tmp_path):
    (tmp_path / "app.js").write_text("var x = 1;\n")
    assert import_hops(str(tmp_path), {"app.js"}) == {"app.js"}


def test_plan_no_change(tree):
    fp = fingerprint_tree(str(tree))
    plan = plan_incremental(fp, dict(fp), str(tree))
    assert plan["no_change"] and plan["scope_files"] == []
    assert plan["sca_needed"] is False


def test_plan_manifest_change_triggers_sca(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "requirements.txt").write_text("django==3.2.0\n")
    old = {"app.py": "x"}
    new = fingerprint_tree(str(tmp_path))
    plan = plan_incremental(old, new, str(tmp_path))
    assert plan["sca_needed"] is True
    assert not plan["no_change"]


def test_plan_code_change_skips_sca(tree):
    old = fingerprint_tree(str(tree))
    (tree / "a.py").write_text("x = 99\n")
    plan = plan_incremental(old, fingerprint_tree(str(tree)), str(tree))
    assert plan["sca_needed"] is False
    assert plan["scope_files"] == ["a.py"]


def test_merge_findings_carries_and_prunes():
    old = [
        {"tool": "semgrep", "rule_id": "r1", "file": "keep.py", "line": 1},
        {"tool": "semgrep", "rule_id": "r2", "file": "chg.py", "line": 2},
        {"tool": "semgrep", "rule_id": "r3", "file": "gone.py", "line": 3},
    ]
    fresh = [{"tool": "semgrep", "rule_id": "r9", "file": "chg.py", "line": 5}]
    merged = merge_findings(old, fresh, {"chg.py", "gone.py"})
    keys = {(f["rule_id"], f["file"]) for f in merged}
    assert keys == {("r1", "keep.py"), ("r9", "chg.py")}


def test_escape_rate_zero_when_equal():
    fs = [{"tool": "t", "rule_id": "r", "file": "a.py", "line": 1}]
    n, total, escaped = escape_rate(list(fs), list(fs))
    assert (n, total, escaped) == (0, 1, [])


def test_escape_rate_counts_missed():
    full = [{"tool": "t", "rule_id": "r", "file": "a.py", "line": 1},
            {"tool": "t", "rule_id": "r2", "file": "b.py", "line": 2}]
    incr = [full[0]]
    n, total, escaped = escape_rate(incr, full)
    assert n == 1 and total == 2 and len(escaped) == 1
