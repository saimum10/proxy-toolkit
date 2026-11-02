"""V2Ray-style share links  (ss:// vmess:// vless:// trojan://)  -> Xray-core outbound config.

These are not plain HTTP/SOCKS proxies: they need an engine (Xray-core, see engine.py) that
speaks the real protocol. This module only PARSES the links and builds the matching Xray
"outbound" JSON; it never touches the network.

Supported: ss (AEAD + 2022 ciphers, no plugins), vmess, vless (incl. XTLS flow, Reality,
VLESS encryption string), trojan.   Transports: tcp (raw, optional HTTP header), ws, grpc,
httpupgrade, xhttp.   Security: none, tls, reality.
Not supported yet (reported per link): hysteria2 / tuic / ssr, kcp / quic / h2 transports, ss plugins.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote

SUPPORTED = ("ss", "vmess", "vless", "trojan")
KNOWN_UNSUPPORTED = ("hysteria2", "hysteria", "hy2", "tuic", "ssr", "wireguard")
PLAIN_PROXY = ("http", "https", "socks", "socks4", "socks4a", "socks5", "socks5h")   # ordinary proxies: tab 1

_SS_METHODS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305",
    "xchacha20-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
    "none", "plain",
}
_NET_ALIASES = {"tcp": "tcp", "raw": "tcp", "ws": "ws", "websocket": "ws", "grpc": "grpc", "gun": "grpc",
                "httpupgrade": "httpupgrade", "xhttp": "xhttp", "splithttp": "xhttp"}
_UNSUPPORTED_NETS = {"kcp", "mkcp", "quic", "h2", "http", "h3"}
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class LinkError(ValueError):
    """A link that cannot be used (the message says why)."""


# ---------------------------------------------------------------- small helpers
def _b64decode(text: str) -> bytes:
    t = text.strip().replace("-", "+").replace("_", "/")
    t += "=" * (-len(t) % 4)
    try:
        return base64.b64decode(t, validate=False)
    except (binascii.Error, ValueError):
        raise LinkError("not valid base64") from None


def _b64text(text: str) -> str:
    try:
        return _b64decode(text).decode("utf-8")
    except UnicodeDecodeError:
        raise LinkError("base64 content is not text") from None


def _split_hostport(hp: str):
    hp = hp.strip()
    if hp.startswith("["):                                   # [IPv6]:port
        end = hp.find("]")
        if end < 0:
            raise LinkError("bad IPv6 address")
        host, rest = hp[1:end], hp[end + 1:]
        if not rest.startswith(":"):
            raise LinkError("missing port")
        port = rest[1:]
    else:
        if hp.count(":") != 1:
            raise LinkError("expected host:port")
        host, port = hp.split(":")
    try:
        p = int(port)
    except ValueError:
        raise LinkError("port is not a number") from None
    if not host or not (0 < p < 65536):
        raise LinkError("bad host or port")
    return host, p


def _truthy(v) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _split_fragment(raw: str):
    body, _, frag = raw.partition("#")
    return body, unquote(frag).strip()


def _query(qs: str) -> dict:
    return {k: v for k, v in parse_qsl(qs, keep_blank_values=True)}


def _sanitize_remark(s: str) -> str:
    return re.sub(r"[\x00-\x1f]", " ", s).strip()[:80]


# ---------------------------------------------------------------- the entry
@dataclass
class LinkEntry:
    proto: str                      # ss | vmess | vless | trojan
    host: str
    port: int
    raw: str
    remark: str = ""
    f: dict = field(default_factory=dict)    # normalised fields (see _common_fields)

    # ---- identity / display
    @property
    def key(self) -> str:
        """Stable id (survives restarts, independent of the engine's local port)."""
        f = self.f
        # EVERY setting that changes how the server is reached counts (two links that differ only in
        # flow / fingerprint / alpn ... are different configurations); the display name and the
        # engine-added certificate pin do not
        basis = json.dumps([self.proto, self.host, self.port, {k: v for k, v in f.items() if k != "pin"}],
                           sort_keys=True, default=str)
        return f"{self.proto}://{self.host}:{self.port}#{hashlib.sha1(basis.encode()).hexdigest()[:8]}"

    @property
    def kind(self) -> str:
        f = self.f
        if self.proto == "ss":
            return "ss"
        parts = [self.proto, f.get("net", "tcp")]
        if f.get("security") not in (None, "", "none"):
            parts.append(f["security"])
        return "/".join(parts)

    @property
    def label(self) -> str:
        hp = f"[{self.host}]:{self.port}" if ":" in self.host else f"{self.host}:{self.port}"
        return f"{hp}  ·  {self.remark}" if self.remark else hp

    # ---- Xray outbound
    def outbound(self, tag: str) -> dict:
        f = self.f
        if self.proto == "vless":
            user = {"id": f["id"], "encryption": f.get("encryption") or "none"}
            if f.get("flow"):
                user["flow"] = f["flow"]
            ob = {"protocol": "vless", "settings": {"vnext": [
                {"address": self.host, "port": self.port, "users": [user]}]}}
        elif self.proto == "vmess":
            ob = {"protocol": "vmess", "settings": {"vnext": [{
                "address": self.host, "port": self.port,
                "users": [{"id": f["id"], "alterId": int(f.get("aid") or 0),
                           "security": f.get("scy") or "auto"}]}]}}
        elif self.proto == "trojan":
            ob = {"protocol": "trojan", "settings": {"servers": [
                {"address": self.host, "port": self.port, "password": f["password"]}]}}
        else:                                                # ss
            ob = {"protocol": "shadowsocks", "settings": {"servers": [
                {"address": self.host, "port": self.port, "method": f["method"], "password": f["password"]}]}}
        stream = self._stream()
        if stream:
            ob["streamSettings"] = stream
        ob["tag"] = tag
        return ob

    def _stream(self) -> dict:
        f = self.f
        if self.proto == "ss":
            return {}
        net = f.get("net", "tcp")
        st: dict = {"network": net}
        path = f.get("path") or "/"
        host = f.get("host") or ""
        if net == "ws":
            ws = {"path": path}
            if host:
                ws["headers"] = {"Host": host}
            st["wsSettings"] = ws
        elif net == "grpc":
            st["grpcSettings"] = {"serviceName": f.get("service") or "", "multiMode": f.get("mode") == "multi"}
        elif net == "httpupgrade":
            hu = {"path": path}
            if host:
                hu["host"] = host
            st["httpupgradeSettings"] = hu
        elif net == "xhttp":
            xh = {"path": path, "mode": f.get("mode") or "auto"}
            if host:
                xh["host"] = host
            st["xhttpSettings"] = xh
        elif f.get("header_type") == "http":
            req = {"path": [p for p in path.split(",") if p] or ["/"]}
            if host:
                req["headers"] = {"Host": [h for h in host.split(",") if h]}
            st["tcpSettings"] = {"header": {"type": "http", "request": req}}

        sec = f.get("security", "none")
        if sec == "tls":
            tls: dict = {}
            sni = f.get("sni") or host
            if sni:
                tls["serverName"] = sni
            if f.get("fp"):
                tls["fingerprint"] = f["fp"]
            if f.get("alpn"):
                tls["alpn"] = [a for a in f["alpn"].split(",") if a]
            if f.get("allow_insecure"):
                if f.get("pin"):
                    # newer Xray removed "allowInsecure": the server certificate is pinned instead
                    # (the engine fetches its SHA-256 first, see engine.pin_certificates)
                    tls["pinnedPeerCertSha256"] = f["pin"]
                else:
                    tls["allowInsecure"] = True
            st["security"] = "tls"
            st["tlsSettings"] = tls
        elif sec == "reality":
            st["security"] = "reality"
            st["realitySettings"] = {
                "serverName": f.get("sni") or "", "fingerprint": f.get("fp") or "chrome",
                "publicKey": f["pbk"], "shortId": f.get("sid") or "", "spiderX": f.get("spx") or ""}
        return st


# ---------------------------------------------------------------- field normalisation
def _net(value: str) -> str:
    v = (value or "tcp").strip().lower()
    if v in _UNSUPPORTED_NETS:
        raise LinkError(f"transport '{v}' is not supported yet")
    if v not in _NET_ALIASES:
        raise LinkError(f"unknown transport '{v}'")
    return _NET_ALIASES[v]


def _security(value: str, default: str = "none") -> str:
    v = (value or "").strip().lower()
    if v == "":
        return default
    if v in ("none", "tls", "reality"):
        return v
    raise LinkError(f"security '{v}' is not supported")


def _common_fields(q: dict, default_sec: str) -> dict:
    net = _net(q.get("type") or q.get("net") or "tcp")
    sec = _security(q.get("security"), default_sec)
    f = {
        "net": net, "security": sec,
        "sni": q.get("sni") or q.get("peer") or "", "host": q.get("host") or "",
        "path": q.get("path") or "", "fp": q.get("fp") or "", "alpn": q.get("alpn") or "",
        "allow_insecure": _truthy(q.get("allowInsecure", "")) or _truthy(q.get("insecure", "")),
        "flow": q.get("flow") or "", "encryption": q.get("encryption") or "",
        "pbk": q.get("pbk") or "", "sid": q.get("sid") or "", "spx": q.get("spx") or "",
        "service": q.get("serviceName") or q.get("service") or "", "mode": q.get("mode") or "",
        "header_type": (q.get("headerType") or "").lower(),
    }
    if net == "grpc" and not f["service"]:
        f["service"] = q.get("path") or ""
    if sec == "reality" and not f["pbk"]:
        raise LinkError("Reality link without a public key (pbk)")
    return f


def _check_uuid(u: str) -> str:
    u = unquote(u).strip()
    if not _UUID.match(u):
        raise LinkError("the id is not a UUID")
    return u


# ---------------------------------------------------------------- per-protocol parsers
def _parse_url_style(raw: str, scheme: str):
    """vless:// trojan:// (and the URL form of vmess://):  scheme://user@host:port?query#name"""
    body, remark = _split_fragment(raw)
    rest = body[len(scheme) + 3:]
    rest, _, qs = rest.partition("?")
    rest = rest.rstrip("/")
    if "@" not in rest:
        raise LinkError("missing 'user@' part")
    user, _, hostport = rest.rpartition("@")
    host, port = _split_hostport(hostport)
    return unquote(user), host, port, _query(qs), remark


def _parse_vless(raw: str) -> LinkEntry:
    user, host, port, q, remark = _parse_url_style(raw, "vless")
    f = _common_fields(q, "none")
    f["id"] = _check_uuid(user)
    return LinkEntry("vless", host, port, raw, _sanitize_remark(remark), f)


def _parse_trojan(raw: str) -> LinkEntry:
    user, host, port, q, remark = _parse_url_style(raw, "trojan")
    if not user:
        raise LinkError("empty trojan password")
    f = _common_fields(q, "tls")                 # trojan is TLS unless the link says otherwise
    f["password"] = user
    return LinkEntry("trojan", host, port, raw, _sanitize_remark(remark), f)


def _parse_vmess(raw: str) -> LinkEntry:
    body, remark = _split_fragment(raw)
    payload = body[len("vmess://"):].strip()
    if "@" in payload:                           # newer URL form: vmess://uuid@host:port?...
        user, host, port, q, rm = _parse_url_style(raw, "vmess")
        f = _common_fields(q, "none")
        f["id"] = _check_uuid(user)
        f["scy"] = q.get("encryption") or "auto"
        f["aid"] = int(q.get("aid") or 0) if str(q.get("aid") or "0").isdigit() else 0
        return LinkEntry("vmess", host, port, raw, _sanitize_remark(rm), f)
    try:
        j = json.loads(_b64text(payload))
    except (json.JSONDecodeError, LinkError):
        raise LinkError("vmess link: the base64 part is not a JSON object") from None
    if not isinstance(j, dict):
        raise LinkError("vmess link: unexpected content")
    host = str(j.get("add") or "").strip()
    try:
        port = int(j.get("port"))
    except (TypeError, ValueError):
        raise LinkError("vmess link: bad port") from None
    if not host or not (0 < port < 65536):
        raise LinkError("vmess link: bad host or port")
    q = {"type": j.get("net") or "tcp", "security": "tls" if str(j.get("tls", "")).lower() == "tls" else "none",
         "sni": j.get("sni") or "", "host": j.get("host") or "", "path": j.get("path") or "",
         "fp": j.get("fp") or "", "alpn": j.get("alpn") or "",
         "allowInsecure": str(j.get("allowInsecure", j.get("insecure", "0"))),
         "headerType": j.get("type") if (j.get("net") or "tcp") in ("tcp", "raw") else "",
         "mode": "multi" if j.get("type") == "multi" else ""}
    f = _common_fields(q, "none")
    f["id"] = _check_uuid(str(j.get("id") or ""))
    f["scy"] = j.get("scy") or "auto"
    try:
        f["aid"] = int(j.get("aid") or 0)
    except (TypeError, ValueError):
        f["aid"] = 0
    remark = remark or str(j.get("ps") or "")
    return LinkEntry("vmess", host, port, raw, _sanitize_remark(remark), f)


def _parse_ss(raw: str) -> LinkEntry:
    body, remark = _split_fragment(raw)
    rest = body[len("ss://"):]
    rest, _, qs = rest.partition("?")
    q = _query(qs)
    if q.get("plugin"):
        raise LinkError(f"Shadowsocks plugin '{q['plugin'].split(';')[0]}' is not supported")
    rest = rest.rstrip("/")
    if "@" in rest:                              # SIP002:  base64(method:password)@host:port
        userinfo, _, hostport = rest.rpartition("@")
        if ":" in userinfo:                      # plain (percent-encoded) method:password
            method, _, password = unquote(userinfo).partition(":")
        else:
            method, _, password = _b64text(unquote(userinfo)).partition(":")
        host, port = _split_hostport(hostport)
    else:                                        # legacy:  base64(method:password@host:port)
        decoded = _b64text(unquote(rest))
        if "@" not in decoded:
            raise LinkError("unrecognised Shadowsocks link")
        userinfo, _, hostport = decoded.rpartition("@")
        method, _, password = userinfo.partition(":")
        host, port = _split_hostport(hostport)
    method = method.strip().lower()
    if method not in _SS_METHODS:
        raise LinkError(f"cipher '{method}' is not supported by Xray")
    if not password and method not in ("none", "plain"):
        raise LinkError("empty Shadowsocks password")
    f = {"method": method, "password": password, "net": "tcp", "security": "none"}
    return LinkEntry("ss", host, port, raw, _sanitize_remark(remark), f)


_PARSERS = {"ss": _parse_ss, "vmess": _parse_vmess, "vless": _parse_vless, "trojan": _parse_trojan}


def parse_link(text: str) -> LinkEntry:
    """Parse ONE share link (raises LinkError with a readable reason)."""
    raw = text.strip()
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://", raw)
    if not m:
        raise LinkError("not a link")
    scheme = m.group(1).lower()
    if scheme not in _PARSERS:
        if scheme in PLAIN_PROXY:
            raise LinkError(f"{scheme}:// is an ordinary proxy - check it on the Proxy Checker tab")
        if scheme in KNOWN_UNSUPPORTED:
            raise LinkError(f"{scheme}:// is not supported yet")
        raise LinkError(f"unknown scheme {scheme}://")
    try:
        return _PARSERS[scheme](raw)
    except LinkError:
        raise
    except Exception as exc:                     # never let one odd link break a whole list
        raise LinkError(f"cannot read this {scheme}:// link ({type(exc).__name__})") from None


# ---------------------------------------------------------------- lists
@dataclass
class LinksReport:
    entries: list = field(default_factory=list)       # unique LinkEntry objects
    errors: list = field(default_factory=list)        # [(line, reason)] - links that cannot be used
    duplicates: int = 0
    other: int = 0                                    # lines that are not links at all (e.g. ip:port)


def looks_like_link(line: str) -> bool:
    return re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", line.strip()) is not None


def expand_subscription(lines: list) -> list:
    """A subscription is often ONE base64 blob that decodes to a list of links: unpack it."""
    text = "\n".join(lines).strip()
    if not text or "://" in text or len(text) < 16 or re.search(r"[^A-Za-z0-9+/=_\-\s]", text):
        return lines
    try:
        decoded = _b64decode("".join(text.split())).decode("utf-8")
    except (LinkError, UnicodeDecodeError):
        return lines
    return decoded.splitlines() if "://" in decoded else lines


def parse_links(lines) -> LinksReport:
    rep = LinksReport()
    seen = set()
    for line in expand_subscription([ln for ln in lines]):
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("//"):
            continue
        if not looks_like_link(s) or s.split("://", 1)[0].lower() in PLAIN_PROXY:
            rep.other += 1                           # ip:port, http://…, socks5://… = ordinary proxies
            continue
        try:
            e = parse_link(s)
        except LinkError as exc:
            rep.errors.append((s, str(exc)))
            continue
        if e.key in seen:
            rep.duplicates += 1
            continue
        seen.add(e.key)
        rep.entries.append(e)
    return rep
