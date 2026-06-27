"""
SSRF prevention for DAST target URLs.

Resolves the target hostname and rejects any URL that maps to a private,
loopback, link-local, or otherwise reserved IP address.  Raises
HTTPException(400) on any violation so callers don't need to inspect the
return value — the absence of an exception means the URL is safe to probe.
"""

import ipaddress
import socket
from urllib.parse import urlparse

from fastapi import HTTPException

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("169.254.0.0/16"),    # link-local / AWS metadata endpoint
    ipaddress.ip_network("100.64.0.0/10"),     # shared address space (RFC 6598)
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]

_BLOCKED_HOSTNAMES = frozenset({"localhost", "ip6-localhost", "ip6-loopback"})


def _is_private(addr_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(addr_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def validate_dast_target(url: str) -> None:
    """
    Raises HTTPException(400) if *url* resolves to a private/reserved address.

    Checks both IP literals and DNS-resolved hostnames; all returned addresses
    must be public for the URL to pass.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        raise HTTPException(status_code=400, detail="URL inválida — debe incluir dominio")

    if hostname.lower() in _BLOCKED_HOSTNAMES:
        raise HTTPException(status_code=400, detail="localhost no está permitido como objetivo DAST")

    # Fast path: hostname is already an IP literal
    try:
        if _is_private(hostname):
            raise HTTPException(
                status_code=400,
                detail="Dirección IP privada o reservada no permitida como objetivo DAST",
            )
        return  # Valid public IP literal
    except HTTPException:
        raise
    except ValueError:
        pass  # Not an IP literal — fall through to DNS resolution

    # Resolve all IPs for the hostname and check each one
    try:
        _, _, addresses = socket.gethostbyname_ex(hostname)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail=f"No se puede resolver el hostname: {hostname}")

    for addr in addresses:
        if _is_private(addr):
            raise HTTPException(
                status_code=400,
                detail="El hostname resuelve a una dirección IP privada o reservada",
            )
