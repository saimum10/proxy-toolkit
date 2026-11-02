"""Parse proxy lists from files / pasted text.

Accepted line formats (one per line):
    1.2.3.4:8080
    http://1.2.3.4:8080          socks4://...   socks5://...   socks5h://...
    user:pass@1.2.3.4:8080       socks5://user:pass@1.2.3.4:1080
    1.2.3.4:8080:user:pass
    [2001:db8::1]:1080
Blank lines and lines starting with # or // are ignored. Anything after the first
whitespace on a line is ignored (so "1.2.3.4:80 US 120ms" works).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from .models import SCHEME_TO_PROTO, ProxyEntry

_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-.]*[A-Za-z0-9])?$")


@dataclass
class ParseReport:
    entries: list = field(default_factory=list)
    invalid: int = 0
    duplicates: int = 0
    invalid_samples: list = field(default_factory=list)


def _valid_ipv4(host: str) -> bool:
    parts = host.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not (p.isascii() and p.isdigit()) or len(p) > 3 or (len(p) > 1 and p[0] == "0") or int(p) > 255:
            return False
    return True


def _valid_host(host: str) -> bool:
    if not host:
        return False
    if re.fullmatch(r"[\d.]+", host):
        return _valid_ipv4(host)
    if ":" in host:
        try:
            ipaddress.IPv6Address(host)
            return True
        except ValueError:
            return False
    return bool(_HOST_RE.match(host)) and len(host) <= 253


def _split_hostport(hp: str):
    if hp.startswith("["):
        end = hp.index("]")  # ValueError if missing -> invalid line
        host, rest = hp[1:end], hp[end + 1:]
        if not rest.startswith(":"):
            raise ValueError("missing port")
        return host, rest[1:]
    if hp.count(":") != 1:
        raise ValueError("bad host:port")
    host, port = hp.split(":")
    return host, port


def parse_line(line: str):
    """Return a ProxyEntry, None for blank/comment lines, or raise ValueError."""
    s = line.strip().lstrip("\ufeff")
    if not s or s.startswith("#") or s.startswith("//"):
        return None
    token = s.split()[0]

    scheme = None
    rest = token
    if "://" in token:
        scheme, rest = token.split("://", 1)
        scheme = scheme.lower()
        if scheme not in SCHEME_TO_PROTO:
            raise ValueError("unknown scheme")
    rest = rest.rstrip("/")

    user = password = None
    if "@" in rest:
        creds, hostport = rest.rsplit("@", 1)
        if ":" in creds:
            user, password = creds.split(":", 1)
        else:
            user = creds
        host, port_s = _split_hostport(hostport)
    elif rest.startswith("["):
        host, port_s = _split_hostport(rest)
    else:
        parts = rest.split(":")
        if len(parts) == 2:
            host, port_s = parts
        elif len(parts) == 4:
            host, port_s, user, password = parts
        else:
            raise ValueError("bad format")

    if not port_s.isdigit() or not (1 <= int(port_s) <= 65535):
        raise ValueError("bad port")
    if not _valid_host(host):
        raise ValueError("bad host")
    return ProxyEntry(host=host, port=int(port_s), scheme=scheme,
                      user=user or None, password=password or None)


@lru_cache(maxsize=300_000)
def _parse_cached(line: str):
    """parse_line() with memoisation: re-parsing a big list after a small edit is then instant.
    Returns a ProxyEntry, None (blank / comment) or False (invalid)."""
    try:
        return parse_line(line)
    except ValueError:
        return False


def parse_lines(lines) -> ParseReport:
    rep = ParseReport()
    seen = set()
    for line in lines:
        entry = _parse_cached(line)
        if entry is False:
            rep.invalid += 1
            if len(rep.invalid_samples) < 5:
                rep.invalid_samples.append(line.strip()[:60])
            continue
        if entry is None:
            continue
        ident = (entry.scheme, entry.host.lower(), entry.port, entry.user, entry.password)
        if ident in seen:
            rep.duplicates += 1
            continue
        seen.add(ident)
        rep.entries.append(entry)
    return rep


def read_lines(path) -> list:
    return Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
