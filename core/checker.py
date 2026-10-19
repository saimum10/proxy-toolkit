"""Async proxy checker.

Per proxy it measures:
  * liveness      - a real HTTPS request through the proxy; exit IP must differ from yours
  * anonymity     - plain-HTTP header-echo test (HTTP proxies): transparent / anonymous / elite
  * reachability  - several target sites (ipify, Cloudflare, Google, optional custom URL)
  * remote DNS    - does the proxy resolve hostnames itself (socks5h / socks4a / HTTP CONNECT)
  * stability     - N rounds, average latency and a 0-100 score
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import aiohttp
from aiohttp_socks import ProxyConnector
from python_socks import ProxyConnectionError, ProxyError, ProxyTimeoutError, ProxyType

from .models import ProxyEntry, ProxyResult, fmt_host


@dataclass(frozen=True)
class Target:
    name: str
    url: str
    kind: str            # "ip": body is an IP | "trace": Cloudflare trace | "status": reachability only
    expect: tuple = ()   # accepted HTTP codes for "status" (empty = anything below 400)


IPIFY = Target("ipify", "https://api.ipify.org", "ip")
CLOUDFLARE = Target("Cloudflare", "https://www.cloudflare.com/cdn-cgi/trace", "trace")
GOOGLE = Target("Google", "https://www.google.com/generate_204", "status", (204,))
ICANHAZIP = Target("icanhazip", "https://icanhazip.com", "ip")

# Used (without any proxy) to discover your real IP.
DIRECT_IP_TARGETS = [IPIFY, CLOUDFLARE, ICANHAZIP]

# Plain-HTTP header-echo pages for the anonymity test (must be http://, not https://,
# otherwise the proxy only sees an opaque tunnel and cannot add headers).
JUDGE_URLS = ["http://httpbin.org/get", "http://postman-echo.com/get"]

LEAK_HEADERS = {
    "via", "x-forwarded-for", "x-forwarded", "forwarded-for", "forwarded",
    "x-real-ip", "client-ip", "x-client-ip", "x-originating-ip", "x-remote-ip",
    "x-remote-addr", "x-proxy-id", "proxy-connection", "x-proxy-connection",
    "x-cluster-client-ip", "true-client-ip", "x-forwarded-host",
}

_PROTO_TYPES = {
    "http": ProxyType.HTTP,
    "socks4": ProxyType.SOCKS4,
    "socks5": ProxyType.SOCKS5,
}
_SOCKS = ("socks4", "socks5")


@dataclass
class CheckConfig:
    timeout: float = 10.0
    concurrency: int = 100
    rounds: int = 3                      # stability rounds (1 = single test)
    targets: list = field(default_factory=lambda: [IPIFY, CLOUDFLARE, GOOGLE])
    anonymity: bool = True
    autodetect: bool = True              # try http, socks5, socks4 when no scheme is given


@dataclass
class Fetched:
    status: int
    text: str
    ms: float


@dataclass
class _Probe:
    target: Target
    ip: str
    loc: Optional[str]
    ms: float
    rdns: bool


# ---------------------------------------------------------------- helpers

async def _read_limited(resp, limit: int = 65536) -> str:
    buf = bytearray()
    async for chunk in resp.content.iter_chunked(8192):
        buf += chunk
        if len(buf) >= limit:
            break
    return bytes(buf).decode("utf-8", "ignore")


def _parse_ip(text: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(text.strip()))
    except ValueError:
        return None


def parse_target(t: Target, f: Fetched):
    """Return (exit_ip, country_code) extracted from a response, or (None, None)."""
    if f.status != 200:
        return None, None
    if t.kind == "ip":
        return _parse_ip(f.text), None
    if t.kind == "trace":
        kv = dict(line.split("=", 1) for line in f.text.splitlines() if "=" in line)
        return _parse_ip(kv.get("ip", "")), kv.get("loc")
    return None, None


def target_ok(t: Target, f: Fetched) -> bool:
    if t.kind == "status":
        return (f.status in t.expect) if t.expect else f.status < 400
    return parse_target(t, f)[0] is not None


def _contains_ip(text: str, ip: str) -> bool:
    return bool(re.search(rf"(?<![\d.]){re.escape(ip)}(?![\d.])", text))


def classify(exc: BaseException) -> str:
    """timeout | connect | proxy | other"""
    chain, seen, cur = [], set(), exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        chain.append(cur)
        os_err = getattr(cur, "os_error", None)
        if isinstance(os_err, BaseException):
            chain.append(os_err)
        cur = cur.__cause__ or cur.__context__
    if any(isinstance(e, (ProxyTimeoutError, asyncio.TimeoutError, TimeoutError)) for e in chain):
        return "timeout"
    if any(isinstance(e, (ProxyConnectionError, aiohttp.ClientProxyConnectionError,
                          ConnectionRefusedError, socket.gaierror)) for e in chain):
        return "connect"
    if any(isinstance(e, (ProxyError, aiohttp.ClientHttpProxyError)) for e in chain):
        return "proxy"
    return "other"


def describe(exc: BaseException, kind: str) -> str:
    if kind == "timeout":
        return "timeout"
    if kind == "connect":
        return "connection to proxy failed"
    msg = " ".join(str(exc).split())
    if len(msg) > 70:
        msg = msg[:67] + "…"
    label = "proxy error" if kind == "proxy" else type(exc).__name__
    return f"{label}: {msg}" if msg else label


def _score(avg_ms: float, stability: float, timeout_s: float) -> int:
    lat = max(0.0, 1.0 - avg_ms / (timeout_s * 1000.0))
    return round(100 * stability * (0.3 + 0.7 * lat))


async def _tcp_connect(host: str, port: int) -> None:
    _, writer = await asyncio.open_connection(host, port)
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass


# ---------------------------------------------------------------- checker

class Checker:
    def __init__(self, cfg: CheckConfig):
        self.cfg = cfg
        self.my_ip: Optional[str] = None
        self.judge_url: Optional[str] = None
        self.baseline: set = set()
        self.notes: list = []
        self._stop = False
        self._workers: list = []

        self.ip_targets = [t for t in cfg.targets if t.kind in ("ip", "trace")] or [IPIFY]
        self.all_targets = self.ip_targets + [t for t in cfg.targets if t.kind == "status"]

    # -- control
    def stop(self) -> None:
        self._stop = True
        for w in self._workers:
            w.cancel()

    def is_stopped(self) -> bool:
        return self._stop

    # -- setup: your real IP + baseline headers of the judge page (no proxy)
    async def prepare(self) -> None:
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as s:
            for t in DIRECT_IP_TARGETS:
                try:
                    async with s.get(t.url) as r:
                        f = Fetched(r.status, await _read_limited(r), 0)
                    ip, _ = parse_target(t, f)
                    if ip:
                        self.my_ip = ip
                        break
                except Exception:
                    continue
            if self.cfg.anonymity:
                for url in JUDGE_URLS:
                    try:
                        async with s.get(url) as r:
                            data = json.loads(await _read_limited(r))
                        headers = data.get("headers")
                        if isinstance(headers, dict):
                            self.baseline = {str(k).lower() for k in headers}
                            self.judge_url = url
                            break
                    except Exception:
                        continue

        if self.my_ip:
            self.notes.append(f"Your real IP: {self.my_ip}")
        else:
            self.notes.append("Warning: could not detect your real IP - 'exit IP differs' check is skipped.")
        if self.cfg.anonymity:
            if self.judge_url:
                self.notes.append(f"Anonymity test page: {self.judge_url}")
            else:
                self.notes.append("Warning: no header-echo page reachable - anonymity will be 'unknown'.")

    # -- one HTTP request through a proxy
    async def _fetch(self, entry: ProxyEntry, proto: str, rdns: bool, url: str,
                     forward: bool = False) -> Fetched:
        timeout = aiohttp.ClientTimeout(total=self.cfg.timeout)
        t0 = time.perf_counter()
        if forward:
            # Real forward-proxy request (absolute-URI GET) so the proxy can see/alter headers.
            auth = aiohttp.BasicAuth(entry.user, entry.password or "") if entry.user else None
            async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as s:
                async with s.get(url, proxy=f"http://{fmt_host(entry.host)}:{entry.port}",
                                 proxy_auth=auth, allow_redirects=False) as r:
                    status, text = r.status, await _read_limited(r)
        else:
            connector = ProxyConnector(
                proxy_type=_PROTO_TYPES[proto], host=entry.host, port=entry.port,
                username=entry.user, password=entry.password,
                rdns=rdns if proto in _SOCKS else None)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as s:
                async with s.get(url, max_redirects=3) as r:
                    status, text = r.status, await _read_limited(r)
        return Fetched(status, text, (time.perf_counter() - t0) * 1000.0)

    # -- primary liveness test for one protocol
    async def _probe(self, entry: ProxyEntry, proto: str):
        rdns_options = (True, False) if proto in _SOCKS else (True,)
        err = "no valid response"
        for rdns in rdns_options:
            for t in self.ip_targets:
                try:
                    f = await self._fetch(entry, proto, rdns, t.url)
                except Exception as e:
                    kind = classify(e)
                    err = describe(e, kind)
                    if kind in ("connect", "timeout"):
                        return None, err
                    if kind == "proxy":
                        break            # proxy rejected the request: maybe remote DNS unsupported
                    continue
                ip, loc = parse_target(t, f)
                if ip is None:
                    err = f"{t.name}: unexpected response (HTTP {f.status})"
                    continue
                if self.my_ip and ip == self.my_ip:
                    err = "exit IP equals your real IP (not proxying)"
                    continue
                return _Probe(t, ip, loc, f.ms, rdns), ""
        return None, err

    async def _anonymity(self, entry: ProxyEntry, proto: str):
        if proto in _SOCKS:
            return "elite", "SOCKS relays raw TCP, so it cannot add or change HTTP headers."
        if not self.judge_url:
            return "unknown", "no header-echo page was reachable from your connection"
        try:
            f = await self._fetch(entry, proto, True, self.judge_url, forward=True)
            headers = json.loads(f.text)["headers"]
            names = {str(k).lower() for k in headers}
        except Exception:
            return "unknown", "proxy blocked or altered the plain-HTTP test request"
        if self.my_ip and _contains_ip(f.text, self.my_ip):
            return "transparent", "your real IP is visible to the website"
        leaked = (names & LEAK_HEADERS) - self.baseline
        if leaked:
            return "anonymous", "proxy adds: " + ", ".join(sorted(leaked))
        return "elite", "no proxy-revealing headers detected"

    def _candidates(self, entry: ProxyEntry) -> list:
        if entry.proto:
            return [entry.proto]
        return ["http", "socks5", "socks4"] if self.cfg.autodetect else ["http"]

    def _dead(self, entry: ProxyEntry, proto: str, error: str) -> ProxyResult:
        scheme = proto if proto in _PROTO_TYPES else "http"
        return ProxyResult(key=entry.key, host=entry.host, port=entry.port,
                           proto=proto, url=entry.url(scheme), live=False, error=error,
                           user=entry.user, password=entry.password)

    async def check_one(self, entry: ProxyEntry) -> ProxyResult:
        candidates = self._candidates(entry)
        label = candidates[0] if len(candidates) == 1 else "?"

        # Cheap pre-check: if the port does not even accept TCP, skip everything else.
        try:
            await asyncio.wait_for(_tcp_connect(entry.host, entry.port), self.cfg.timeout)
        except asyncio.TimeoutError:
            return self._dead(entry, label, "timeout")
        except Exception:
            return self._dead(entry, label, "connection to proxy failed")

        probe, proto, err = None, label, ""
        for p in candidates:
            probe, err = await self._probe(entry, p)
            if probe:
                proto = p
                break
        if not probe:
            return self._dead(entry, label, err)
        return await self._finish_live(entry, proto, probe)

    async def _finish_live(self, entry: ProxyEntry, proto: str, probe: _Probe) -> ProxyResult:
        cfg = self.cfg
        rounds = max(1, cfg.rounds)
        latencies = [probe.ms]
        passed = 1
        loc = [probe.loc]

        async def more_rounds():
            nonlocal passed
            for _ in range(rounds - 1):
                try:
                    f = await self._fetch(entry, proto, probe.rdns, probe.target.url)
                except Exception:
                    continue
                ip, _ = parse_target(probe.target, f)
                if ip and ip != self.my_ip:
                    passed += 1
                    latencies.append(f.ms)

        async def one_target(t: Target):
            if t.name == probe.target.name:
                return t.name, True
            try:
                f = await self._fetch(entry, proto, probe.rdns, t.url)
            except Exception:
                return t.name, False
            if t.kind == "trace":
                loc[0] = loc[0] or parse_target(t, f)[1]
            return t.name, target_ok(t, f)

        async def reach():
            return dict(await asyncio.gather(*(one_target(t) for t in self.all_targets)))

        async def anon():
            if not cfg.anonymity:
                return "", ""
            return await self._anonymity(entry, proto)

        _, targets, (anonymity, note) = await asyncio.gather(more_rounds(), reach(), anon())

        avg = sum(latencies) / len(latencies)
        stability = passed / rounds
        remote_dns = probe.rdns if proto in _SOCKS else True
        scheme = proto
        if remote_dns and proto == "socks5":
            scheme = "socks5h"
        elif remote_dns and proto == "socks4":
            scheme = "socks4a"

        res = ProxyResult(
            key=entry.key, host=entry.host, port=entry.port, proto=proto,
            url=entry.url(scheme), live=True, exit_ip=probe.ip, latency_ms=avg,
            rounds=rounds, passed=passed, score=_score(avg, stability, cfg.timeout),
            anonymity=anonymity, anonymity_note=note, remote_dns=remote_dns,
            targets=targets, user=entry.user, password=entry.password)
        if loc[0] and loc[0].upper() not in ("XX", "T1"):
            res.country_code = loc[0].upper()
        return res

    # -- run many
    async def run(self, entries: list, on_result: Callable, on_progress: Callable) -> None:
        queue: asyncio.Queue = asyncio.Queue()
        for e in entries:
            queue.put_nowait(e)
        total = len(entries)
        done = 0

        async def worker():
            nonlocal done
            while not self._stop:
                try:
                    entry = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    res = await self.check_one(entry)
                except Exception as ex:  # never let one proxy kill a worker
                    res = self._dead(entry, "?", f"internal error: {ex!r}"[:90])
                done += 1
                on_result(res)
                on_progress(done, total)

        n = max(1, min(self.cfg.concurrency, total))
        self._workers = [asyncio.ensure_future(worker()) for _ in range(n)]
        await asyncio.gather(*self._workers, return_exceptions=True)
