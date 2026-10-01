"""Scan status badges (shields.io-style SVG).

Public, unauthenticated: embed in a README as
``https://<host>/api/scans/<scan_id>/badge.svg``.

Privacy: the badge exposes only *aggregate* severity counts — never file
names, messages, target names, org ids or any other scan metadata. Scan ids
are unguessable (12 hex chars from uuid4), so enumeration is impractical.
"""
from xml.sax.saxutils import escape as _xml_escape

# (display label, badge color)
_STATUS_BADGES = {
    "queued": ("queued…", "#9e9e9e"),
    "running": ("scanning…", "#9e9e9e"),
    "failed": ("failed", "#9e9e9e"),
}

_SEV_ORDER = (
    ("error", "critical", "#e05d44"),
    ("warning", "high", "#fe7d37"),
    ("note", "low", "#dfb317"),
)


def badge_text_and_color(status: str, counts: dict) -> tuple:
    """Return (right_text, right_color) for a scan status + severity counts."""
    if status in _STATUS_BADGES:
        return _STATUS_BADGES[status]
    if status != "done":
        return ("unknown", "#9e9e9e")
    for sev, label, color in _SEV_ORDER:
        n = counts.get(sev, 0)
        if n:
            return (f"{n} {label}", color)
    return ("clean", "#4c1")


def _text_width(text: str) -> int:
    # ~6.8px per char at 11px Verdana + horizontal padding, shields.io style.
    return int(round(len(text) * 6.8)) + 12


def build_badge_svg(status: str, counts: dict) -> str:
    """Build a deterministic shields.io-style flat badge SVG.

    Pure function of (status, counts) — same input always yields the same
    bytes. Only aggregate counts influence the output.
    """
    left = "BraimSec"
    right, color = badge_text_and_color(status, counts)
    lw, rw = _text_width(left), _text_width(right)
    total = lw + rw
    rx = lw  # right block starts here
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" '
        f'role="img" aria-label="{_xml_escape(left)}: {_xml_escape(right)}">'
        f'<title>{_xml_escape(left)}: {_xml_escape(right)}</title>'
        f'<linearGradient id="s" x2="0" y2="100%">'
        f'<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        f'<stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<clipPath id="r"><rect width="{total}" height="20" rx="3" fill="#fff"/></clipPath>'
        f'<g clip-path="url(#r)">'
        f'<rect width="{lw}" height="20" fill="#555"/>'
        f'<rect x="{rx}" width="{rw}" height="20" fill="{color}"/>'
        f'<rect width="{total}" height="20" fill="url(#s)"/></g>'
        f'<g fill="#fff" text-anchor="middle" '
        f'font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{lw / 2}" y="15" fill="#010101" fill-opacity=".3">{_xml_escape(left)}</text>'
        f'<text x="{lw / 2}" y="14">{_xml_escape(left)}</text>'
        f'<text x="{rx + rw / 2}" y="15" fill="#010101" fill-opacity=".3">{_xml_escape(right)}</text>'
        f'<text x="{rx + rw / 2}" y="14">{_xml_escape(right)}</text>'
        f"</g></svg>"
    )
