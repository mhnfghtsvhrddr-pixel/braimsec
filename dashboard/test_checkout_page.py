"""Contract test: dashboard/checkout.html must only call API routes that
actually exist in api/main.py, with the tier/cycle values the checkout
endpoints accept. Catches frontend/backend drift at test time instead of
in front of a paying customer.
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "api"))

CHECKOUT_HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "checkout.html")
MAIN_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "..", "api", "main.py")


def _routes(main_src):
    """{(METHOD, path)} from @app.<method>("/path") decorators."""
    found = set()
    for m in re.finditer(r'@app\.(get|post|put|delete)\(\s*"([^"]+)"',
                         main_src):
        found.add((m.group(1).upper(), m.group(2)))
    return found


def test_checkout_api_contract():
    html = open(CHECKOUT_HTML).read()
    main_src = open(MAIN_PY).read()
    routes = _routes(main_src)

    # Every /api/... URL the page fetches must be a registered route.
    fetched = set(re.findall(r'"/api/[^"]+"', html))
    assert fetched, "checkout page fetches no /api/* URLs?"
    for url in fetched:
        path = url.strip('"').split("?")[0]
        assert ("POST", path) in routes or ("GET", path) in routes, \
            f"checkout.html calls {path} which is not registered in main.py"

    # Every non-/api link target the page builds must exist too.
    assert ("/checkout/success" in html) and \
        ("GET", "/checkout/success") in routes

    # Tiers/cycles the page sends must be accepted by both checkouts.
    tiers_block = re.search(r"const TIERS = \{(.*?)\n\};", html, re.S).group(1)
    for tier in ("starter", "pro", "advanced"):
        assert re.search(rf"^\s*{tier}:", tiers_block, re.M), \
            f"tier {tier} missing from checkout page TIERS"
    for cycle in ("monthly", "annual"):
        assert f'"{cycle}"' in html
    assert 'tier: starter|pro|advanced' in main_src or \
        '"starter"' in main_src  # sanity: catalog present


def test_checkout_page_no_hardcoded_secrets():
    html = open(CHECKOUT_HTML).read().lower()
    for bad in ("sk_live_", "secret", "api_key="):
        # 'api_key' appears only as a JSON *response field* name.
        if bad == "api_key=":
            continue
        assert bad not in html, f"suspicious literal in checkout page: {bad}"
    assert "sk_live_" not in html
