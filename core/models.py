"""Data models shared by the checker and the GUI."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import quote

# Scheme as written by the user -> base protocol we actually test.
# "http://host:port"  = plain HTTP proxy (CONNECT carries HTTPS targets).
# "https://host:port" = HTTP proxy that is itself reached over TLS ("https" protocol);
#                       the TLS handshake with the proxy is done first, then CONNECT.
SCHEME_TO_PROTO = {
    "http": "http",
    "https": "https",
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
    # V2Ray-style links (ss / vmess / vless / trojan): host / port / user / password above are the
    # LOCAL SOCKS5 inbound of the engine that speaks the real protocol (that is what the proxy
    # server connects to); these fields describe the real link for display and export.
    link: str = ""               # the original share link (also stored in `url`)
    kind: str = ""               # e.g. "vless/ws/tls" - shown instead of `proto` when set
    label: str = ""              # e.g. "31.77.148.89:45021 · my name" - shown instead of host:port

    @property
    def stability(self) -> float:
        return self.passed / self.rounds if self.rounds else 0.0

    @property
    def address(self) -> str:
        return self.label or f"{fmt_host(self.host)}:{self.port}"
