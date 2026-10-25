"""Target URL check shared by the MCP server and the REST API.

The live BOLA probe sends HTTP requests with bearer tokens, so a caller must
not be able to point it at a cloud metadata service. The host is resolved and
every address it resolves to is checked, which also catches numeric forms such
as http://2852039166/ (decimal), 0xA9FEA9FE, IPv4-mapped IPv6 and names that
resolve to link-local addresses. PRUFGATE_ALLOW_LINK_LOCAL=1 turns the check off.

ponytail: the address is checked when the URL is validated; DNS can change
before the probe connects (rebinding). Pin the resolved address in the probe
if that matters.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import urllib.parse

BLOCKED_HOSTNAMES = {"metadata.google.internal", "metadata", "metadata.azure.com"}
BLOCKED_ADDRESSES = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
}


def _blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return ip.is_link_local or ip in BLOCKED_ADDRESSES


def target_url_error(target_url: object) -> str | None:
    """Return why `target_url` may not be probed, or None when it may."""
    if not isinstance(target_url, str) or not target_url.startswith(("http://", "https://")):
        return f"Invalid target URL scheme: only http:// and https:// are supported: {target_url}"
    try:
        host = (urllib.parse.urlparse(target_url).hostname or "").strip().lower().rstrip(".")
    except ValueError as e:
        return f"Malformed target URL: {e}"
    if not host:
        return f"Invalid target URL: missing hostname: {target_url}"
    if os.environ.get("PRUFGATE_ALLOW_LINK_LOCAL") == "1":
        return None
    if host in BLOCKED_HOSTNAMES:
        return f"Blocked SSRF target hostname (cloud metadata endpoint): {host}"
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError) as e:
        return f"Target host does not resolve: {host} ({e})"
    for info in infos:
        try:
            ip = ipaddress.ip_address(str(info[4][0]).split("%", 1)[0])
        except ValueError:
            continue
        if _blocked(ip):
            return f"Blocked SSRF target IP (link-local/metadata address): {host} -> {ip}"
    return None
