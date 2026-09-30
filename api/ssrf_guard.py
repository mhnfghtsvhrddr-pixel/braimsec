"""SSRF guard for outbound webhook delivery.

Two layers:

1. ``validate_webhook_url`` — fail-fast checks at scan-creation time.
   Rejects deterministically bad URLs (bad scheme, userinfo, IP literals
   in blocked ranges, hostnames that resolve to blocked ranges). A DNS
   *failure* does not reject: delivery is best-effort and the name may
   resolve later.

2. ``safe_webhook_post`` — the real security boundary, used by the
   worker at delivery time. Resolves the hostname, refuses the request
   if *any* resolved address is in a blocked range (fail-closed against
   DNS rebinding), pins the TCP connection to the validated IP, sends
   the original hostname as ``Host``/SNI, and never follows redirects
   (a redirect hop is never re-validated by urllib, so we don't follow).

Blocked ranges: private, loopback, link-local (covers the 169.254.169.254
cloud-metadata address), reserved, multicast, unspecified — IPv4 and IPv6.
"""
import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit

ALLOWED_SCHEMES = ("http", "https")


def _blocked_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # not an IP at all: treat as blocked
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def _split(url: str):
    parts = urlsplit(url)
    if parts.scheme not in ALLOWED_SCHEMES:
        raise ValueError("webhook_url must be http(s)")
    if parts.username or parts.password:
        raise ValueError("webhook_url must not contain userinfo credentials")
    hostname = parts.hostname or ""
    if not hostname:
        raise ValueError("webhook_url has no hostname")
    return parts, hostname


def _resolve_checked(hostname: str) -> list[tuple]:
    """Resolve and reject if any address is blocked. Returns getaddrinfo rows."""
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"webhook_url does not resolve: {e}") from e
    if not infos:
        raise ValueError("webhook_url does not resolve")
    for _fam, _typ, _proto, _canon, sockaddr in infos:
        if _blocked_ip(sockaddr[0]):
            raise ValueError(
                "webhook_url resolves to a blocked (private/internal) address")
    return infos


def validate_webhook_url(url: str) -> str:
    """Fail-fast validation for scan creation. Returns the URL unchanged.

    Raises ValueError on deterministically bad input. A transient DNS
    failure is *not* a rejection — delivery remains best-effort.
    """
    _parts, hostname = _split(url)
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass  # not an IP literal: needs DNS
    else:
        if _blocked_ip(hostname):
            raise ValueError(
                "webhook_url must not target a private/internal address")
        return url
    # RFC 2606 / RFC 6761 special-use names: guaranteed never to resolve
    # on public DNS. Skip resolution (also avoids leaking test names and
    # tripping over DNS-hijacking sandboxes); delivery stays best-effort.
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError(
            "webhook_url must not target a private/internal address")
    if hostname.endswith((".test", ".example", ".invalid")):
        return url
    try:
        _resolve_checked(hostname)
    except ValueError as e:
        if "does not resolve" in str(e):
            return url  # transient: delivery will retry best-effort
        raise
    return url


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection already pointed at a validated IP (no re-resolution)."""


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection to a validated IP with SNI/cert verification
    against the ORIGINAL hostname (not the IP)."""

    def __init__(self, host, port=None, sni_hostname=None, **kw):
        super().__init__(host, port, **kw)
        self._sni_hostname = sni_hostname or host

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        # check_hostname is on for the default context: verification runs
        # against server_hostname during the handshake.
        self.sock = self._context.wrap_socket(
            sock, server_hostname=self._sni_hostname)


def safe_webhook_post(url: str, body: bytes, headers: dict,
                      timeout: float) -> int:
    """POST with SSRF protection. Returns the HTTP status code.

    Raises ValueError when the target is blocked or unresolvable, and
    propagates connection errors to the caller. Never follows redirects.
    """
    parts, hostname = _split(url)
    infos = _resolve_checked(hostname)  # fail-closed, incl. DNS rebinding
    ip = infos[0][4][0]
    port = parts.port or (443 if parts.scheme == "https" else 80)

    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    host_header = hostname if parts.port else hostname
    if parts.port:
        host_header = f"{hostname}:{parts.port}"

    req_headers = dict(headers)
    req_headers["Host"] = host_header  # http.client skips its auto Host then
    req_headers["Content-Length"] = str(len(body))

    if parts.scheme == "https":
        ctx = ssl.create_default_context()  # verify + check_hostname on
        conn = _PinnedHTTPSConnection(ip, port, sni_hostname=hostname,
                                      timeout=timeout, context=ctx)
    else:
        conn = _PinnedHTTPConnection(ip, port, timeout=timeout)
    try:
        conn.request("POST", path, body=body, headers=req_headers)
        resp = conn.getresponse()
        status = resp.status
        resp.read()  # drain so the connection can close cleanly
        return status
    finally:
        conn.close()
