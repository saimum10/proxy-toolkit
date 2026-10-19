"""Data models shared by the checker and the GUI."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import quote

# Scheme as written by the user -> base protocol we actually test.
# "https://host:port" is treated as a normal HTTP proxy: every HTTP proxy that
# supports CONNECT carries HTTPS, and the checker verifies that with HTTPS targets.
SCHEME_TO_PROTO = {
    "http": "http",
    "https": "http",
    "socks4": "socks4",
    "socks4a": "socks4",
    "socks5": "socks5",
    "socks5h": "socks5",
}


def fmt_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host


@dataclass(frozen=True)
class ProxyEntry:
    host: str
    port: int
    scheme: Optional[str] = None  # as written by the user, None when omitted
    user: Optional[str] = None
    password: Optional[str] = None

    @property
    def key(self) -> str:
        """Protocol-independent identity used for favourites / blacklist."""
        return f"{self.host.lower()}:{self.port}"

    @property
    def proto(self) -> Optional[str]:
        return SCHEME_TO_PROTO.get(self.scheme) if self.scheme else None

    def url(self, scheme: str) -> str:
        auth = ""
        if self.user:
            auth = quote(self.user, safe="")
            if self.password:
                auth += ":" + quote(self.password, safe="")
            auth += "@"
        return f"{scheme}://{auth}{fmt_host(self.host)}:{self.port}"


@dataclass
class ProxyResult:
    key: str
    host: str
    port: int
    proto: str = "?"
    url: str = ""
    live: bool = False
    error: str = ""
    exit_ip: str = ""
    latency_ms: Optional[float] = None
    rounds: int = 0
    passed: int = 0
    score: int = 0
    anonymity: str = ""          # transparent | anonymous | elite | unknown
    anonymity_note: str = ""
    remote_dns: Optional[bool] = None
    targets: dict = field(default_factory=dict)   # target name -> bool
    country: str = ""
    country_code: str = ""
    city: str = ""
    isp: str = ""
    net_type: str = ""           # Datacenter | Mobile | ISP
    user: Optional[str] = None   # upstream credentials (needed by the proxy server)
    password: Optional[str] = None

    @property
    def stability(self) -> float:
        return self.passed / self.rounds if self.rounds else 0.0

    @property
    def address(self) -> str:
        return f"{fmt_host(self.host)}:{self.port}"
