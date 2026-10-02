"""Dashboard smoke tests for the latency-threshold controls."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "index.html")


def _html():
    with open(HTML, encoding="utf-8") as f:
        return f.read()


def test_latency_input_markup():
    h = _html()
    for needle in ['id="up-lat"', "حد البطء ms",
                   "payload.latency_warn_ms"]:
        assert needle in h, needle


def test_latency_table_column():
    h = _html()
    assert "حد البطء" in h
    assert "t.latency_warn_ms" in h


def test_slow_fast_event_options_and_labels():
    h = _html()
    assert '<option value="uptime.slow">' in h
    assert '<option value="uptime.fast">' in h
    assert '"uptime.slow": "🟡 بطء الاستجابة"' in h
    assert '"uptime.fast": "🟢 تحسّن الاستجابة"' in h
