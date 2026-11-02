"""Local proxy server (SOCKS5 + SOCKS4/4a + HTTP/HTTPS on ONE port).

Your browser / curl / burp talk to 127.0.0.1:<port>; every connection is forwarded
through the pool of checked proxies, either rotated (round-robin / random / weighted random /
fastest / favourites first / failover groups / sticky per domain / manual hold) or chained
(strict / dynamic / random chain, like proxychains).

Safety properties
  * Kill-switch: the server NEVER connects directly. If no eligible proxy exists the
    connection is refused (SOCKS5 reply 0x02 / HTTP 503) so your real IP is not leaked.
  * DNS: hostnames sent by the client are passed to the proxy (remote DNS). By default only
    proxies that passed the remote-DNS test are used for hostnames ("require_rdns").
  * Health monitor: pool members are re-tested in the background; dead ones leave the active
    pool, recovered ones return. A failed connection also triggers a quick re-test.

The server runs in its own thread with its own asyncio loop, so heavy traffic never
blocks the GUI.
"""
from __future__ import annotations

import asyncio
import collections
import ipaddress
import math
import random
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

from python_socks import ProxyType
from python_socks.async_.asyncio.v2 import Proxy

from .checker import CheckConfig, Checker, IPIFY, classify, describe, proxy_ssl_context
from .models import ProxyEntry, ProxyResult

MODES = [
    ("round_robin", "Round-robin"),
    ("random", "Random"),
    ("weighted", "Weighted random (better proxies more often)"),
    ("fastest", "Fastest first"),
    ("fav_first", "Favourites first"),
    ("failover", "Failover groups (Primary → Backup)"),
    ("sticky", "Sticky per domain"),
    ("manual", "Manual · hold one IP (Change IP)"),
    ("chain_strict", "Chain · strict"),
    ("chain_dynamic", "Chain · dynamic"),
    ("chain_random", "Chain · random"),
]

# Modes that hold one exit IP per site / per client and can therefore be rotated automatically
_ROTATE_MODES = ("manual", "sticky")
FAILOVER_GROUPS = {1: "Primary", 2: "Backup 1", 3: "Backup 2"}

_PTYPE = {"http": ProxyType.HTTP, "https": ProxyType.HTTP,
          "socks4": ProxyType.SOCKS4, "socks5": ProxyType.SOCKS5}
_SOCKS = ("socks4", "socks5")
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go"}
_HOP_BY_HOP = (b"proxy-connection", b"proxy-authorization", b"connection", b"keep-alive")

# Health monitor scheduling (see ProxyServer._monitor_due)
_MONITOR_TICK = 5.0        # how often the scheduler looks for proxies that are due
_IDLE_FACTOR = 3.0         # alive proxies nobody is using are re-tested this many times less often
_MAX_BACKOFF = 16          # a dead proxy is re-tested at most every  interval * 16


# ------------------------------------------------------------------ helpers

def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def site_key(host: str) -> str:
    """Rough 'registrable domain' used for sticky sessions (www.a.com and api.a.com match)."""
    if _is_ip(host):
        return host
    labels = host.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def split_hostport(target: str, default_port: int):
    t = target.strip()
    if t.startswith("["):
        end = t.index("]")
        rest = t[end + 1:]
        port = int(rest[1:]) if rest.startswith(":") and rest[1:] else default_port
        return t[1:end], port
    if t.count(":") == 1:
        host, port = t.split(":")
        return host, int(port)
    return t, default_port


class Blocked(Exception):
    """Raised when the kill-switch refuses a connection (nothing is ever sent directly)."""


# ------------------------------------------------------------------ pool

@dataclass(eq=False)
class Member:
    res: ProxyResult
    alive: bool = True
    fails: int = 0
    cooldown: float = 0.0          # monotonic time until which the proxy is skipped
    uses: int = 0
    latency_ms: Optional[float] = None
    last_check: float = 0.0
    last_used: float = 0.0
    group: int = 1                 # failover mode: 1 = Primary, 2 = Backup 1, 3 = Backup 2

    @property
    def key(self) -> str:
        return self.res.key


class Pool:
    """Thread-safe set of live proxies (shared between the GUI and the server thread)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._m: dict = {}
        self.version = 0

    def add(self, results) -> int:
        """Add live results. Known proxies keep their state but get fresh data; returns #new."""
        new = 0
        with self._lock:
            for r in results:
                if not r.live:
                    continue
                m = self._m.get(r.key)
                if m is None:
                    self._m[r.key] = Member(res=r, latency_ms=r.latency_ms, last_check=time.monotonic())
                    new += 1
                else:
                    m.res = r
                    m.alive, m.fails, m.cooldown = True, 0, 0.0
                    m.last_check = time.monotonic()
                    if r.latency_ms is not None:
                        m.latency_ms = r.latency_ms
            self.version += 1
        return new

    def remove(self, keys) -> None:
        with self._lock:
            for k in keys:
                self._m.pop(k, None)
            self.version += 1

    def clear(self) -> None:
        with self._lock:
            self._m.clear()
            self.version += 1

    def mark_due(self, keys) -> int:
        """Make the health monitor re-test these members at its next pass (skipping any back-off).

        Used when something outside the pool just got fixed (e.g. an engine was restarted)."""
        n = 0
        with self._lock:
            for k in keys:
                m = self._m.get(k)
                if m is not None:
                    m.last_check = -1e12
                    n += 1
        return n

    def set_group(self, keys, group: int) -> int:
        """Assign proxies to a failover group (1 = Primary ... 3 = Backup 2). Returns #changed."""
        group = max(1, min(int(group), max(FAILOVER_GROUPS)))
        n = 0
        with self._lock:
            for k in keys:
                m = self._m.get(k)
                if m is not None and m.group != group:
                    m.group = group
                    n += 1
            self.version += 1
        return n

    def get(self, key: str) -> Optional[Member]:
        with self._lock:
            return self._m.get(key)

    def members(self) -> list:
        with self._lock:
            return list(self._m.values())

    def __len__(self) -> int:
        with self._lock:
            return len(self._m)


# ------------------------------------------------------------------ config / stats

@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 1080
    mode: str = "round_robin"
    chain: list = field(default_factory=list)     # member keys, in order (strict / dynamic)
    chain_len: int = 2                            # random chain length
    countries: set = field(default_factory=set)   # allowed exit countries (empty = any)
    min_score: int = 0
    require_rdns: bool = True
    connect_timeout: float = 15.0
    idle_timeout: float = 600.0
    retries: int = 3
    sticky_ttl: float = 0.0                       # seconds, 0 = until the proxy dies
    cooldown: float = 30.0                        # seconds a failing proxy is skipped
    monitor: bool = True
    monitor_interval: float = 60.0
    max_fails: int = 2
    log_connections: bool = True
    drop_on_change: bool = True                   # manual mode: close open connections on Change IP
    half_close_timeout: float = 60.0              # after the client stops sending: max silence from the upstream
    favourites: frozenset = frozenset()           # keys of favourite proxies (weighted / favourites-first)
    fav_fallback: bool = True                     # favourites-first: use other proxies when no favourite is usable
    rotate_minutes: float = 0.0                   # manual / sticky: new IP every N minutes (0 = off)
    rotate_requests: int = 0                      # manual / sticky: new IP every N connections (0 = off)
    rotate_drop: bool = False                     # auto-rotate also closes open connections (default: new
                                                  # connections use the new IP, open ones finish normally)


class Stats:
    def __init__(self):
        self.total = 0
        self.active = 0
        self.success = 0
        self.errors = 0
        self.blocked = 0
        self.up = 0
        self.down = 0


@dataclass
class ChangeResult:
    ok: bool
    address: str = ""
    exit_ip: str = ""
    country: str = ""
    ms: float = 0.0
    dropped: int = 0
    message: str = ""


# ------------------------------------------------------------------ server

class ProxyServer:
    def __init__(self, cfg: ServerConfig, pool: Pool, probe_cfg: Optional[CheckConfig] = None,
                 my_ip: Optional[str] = None):
        self.cfg = cfg
        self.pool = pool
        self.stats = Stats()
        self.my_ip = my_ip
        self.probe_cfg = probe_cfg or CheckConfig(timeout=8.0, rounds=1, targets=[IPIFY],
                                                   anonymity=False, autodetect=False)
        self.port = cfg.port           # real port (differs from cfg.port when 0 was requested)

        self._thread: Optional[threading.Thread] = None
        self._loop = None
        self._stop_evt = None
        self._server = None
        self._checker: Optional[Checker] = None
        self._ready = threading.Event()
        self._start_error: Optional[BaseException] = None
        self._running = False

        self._tasks: set = set()
        self._bg: set = set()
        self._rr = 0
        self._sticky: dict = {}
        self._current_key: Optional[str] = None     # manual mode: the proxy currently held
        self.current_exit_ip = ""
        self.last_change: Optional[ChangeResult] = None   # newest IP change (manual button or auto-rotate)
        self.change_count = 0
        self._last_rotate = time.monotonic()        # auto-rotate: time of the last change
        self._rot_conns = 0                         # auto-rotate: connections since the last change
        self._rotating = False
        self._routes: dict = {}                     # handler task -> route (to drop on Change IP)
        self._elig_cache: dict = {}
        self._once: dict = {}

        self._ev_lock = threading.Lock()
        self._events = collections.deque(maxlen=1000)
        self._seq = 0

    # ---------------------------------------------------------- public control
    @property
    def running(self) -> bool:
        return self._running

    def start(self, timeout: float = 5.0) -> None:
        self._ready.clear()
        self._start_error = None
        self._thread = threading.Thread(target=self._thread_main, name="proxy-server", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout):
            raise RuntimeError("proxy server did not start in time")
        if self._start_error:
            raise self._start_error

    def request_stop(self) -> None:
        """Ask the server to stop and return immediately (poll `stopped` for completion)."""
        if self._loop and self._stop_evt and self._running:
            try:
                self._loop.call_soon_threadsafe(self._stop_evt.set)
            except RuntimeError:
                pass

    @property
    def stopped(self) -> bool:
        return self._thread is None or not self._thread.is_alive()

    def stop(self, wait: float = 6.0) -> None:
        """Stop the server; blocks up to `wait` seconds (use request_stop() from the GUI thread)."""
        self.request_stop()
        if self._thread and wait > 0:
            self._thread.join(timeout=wait)
        self._running = False

    def update_config(self, cfg: ServerConfig) -> None:
        """Apply new settings to a running server (host/port changes need a restart)."""
        old = self.cfg
        cfg.host, cfg.port = old.host, old.port
        self.cfg = cfg
        self._elig_cache.clear()
        if (cfg.mode, cfg.rotate_minutes, cfg.rotate_requests) != (old.mode, old.rotate_minutes, old.rotate_requests):
            # new auto-rotate settings: the countdown starts NOW (otherwise a server that has been
            # running for hours would rotate the moment auto-rotate is switched on)
            self._last_rotate = time.monotonic()
            self._rot_conns = 0

    def set_my_ip(self, ip: Optional[str]) -> None:
        """Real IP of this machine (lets the health monitor spot proxies that do not proxy)."""
        self.my_ip = ip
        if self._checker:
            self._checker.my_ip = ip

    def current_member(self) -> Optional[Member]:
        """Manual mode: the proxy currently held (None until the first connection / Change IP)."""
        return self.pool.get(self._current_key) if self._current_key else None

    def change_ip(self, target_key: Optional[str] = None):
        """Switch to the next live proxy (verified with a real request first).

        With `target_key` the server holds exactly that pool member instead ("connect through
        this IP"). Returns a concurrent.futures.Future that resolves to a ChangeResult."""
        if not (self._loop and self._running):
            raise RuntimeError("server is not running")
        return asyncio.run_coroutine_threadsafe(self._change_ip(target_key), self._loop)

    def recheck(self, keys):
        """Re-test the given pool members right now. Future -> [(address, alive, latency_ms)]."""
        if not (self._loop and self._running):
            raise RuntimeError("server is not running")
        members = [m for m in (self.pool.get(k) for k in keys) if m is not None]
        return asyncio.run_coroutine_threadsafe(self._recheck_report(members), self._loop)

    def active_group(self) -> Optional[int]:
        """Failover mode: the group that currently serves traffic (None = nothing usable)."""
        return min((m.group for m in self._eligible(True, cached=False)), default=None)

    def rotate_status(self) -> str:
        """Human-readable auto-rotate countdown ('' when auto-rotate is off / not applicable)."""
        cfg = self.cfg
        if cfg.mode not in _ROTATE_MODES or (cfg.rotate_minutes <= 0 and cfg.rotate_requests <= 0):
            return ""
        parts = []
        if cfg.rotate_minutes > 0:
            left = max(0, int(cfg.rotate_minutes * 60 - (time.monotonic() - self._last_rotate)))
            parts.append(f"in {left // 60}:{left % 60:02d}")
        if cfg.rotate_requests > 0:
            parts.append(f"after {max(0, cfg.rotate_requests - self._rot_conns)} more connection(s)")
        return "Auto-rotate: next new IP " + " or ".join(parts)

    def events_since(self, seq: int) -> list:
        with self._ev_lock:
            return [e for e in self._events if e[0] > seq]

    def status(self):
        """(eligible_count, blocked, reason) - callable from the GUI thread."""
        cfg = self.cfg
        if cfg.mode in ("chain_strict", "chain_dynamic"):
            route, reason = self._plan_chain(True)
            return (len(route) if route else 0), route is None, reason
        n = len(self._eligible(True, cached=False))
        return n, n == 0, ("no eligible live proxy in the pool" if n == 0 else "")

    # ---------------------------------------------------------- thread / loop
    def _thread_main(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            loop.run_until_complete(self._main())
        finally:
            self._running = False
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:
                pass
            loop.close()

    async def _main(self) -> None:
        self._stop_evt = asyncio.Event()
        self._checker = Checker(self.probe_cfg)
        self._checker.my_ip = self.my_ip
        try:
            self._server = await asyncio.start_server(
                self._handle, self.cfg.host, self.cfg.port, backlog=1024, reuse_address=True)
        except OSError as e:
            self._start_error = e
            self._ready.set()
            return
        self.port = self._server.sockets[0].getsockname()[1]
        self._running = True
        self._event(f"Listening on {self.cfg.host}:{self.port} - mode {self.cfg.mode}")
        self._ready.set()

        self._last_rotate = time.monotonic()
        monitor = asyncio.ensure_future(self._monitor_loop())
        rotator = asyncio.ensure_future(self._rotate_loop())
        await self._stop_evt.wait()

        self._running = False
        self._server.close()
        monitor.cancel()
        rotator.cancel()
        for t in list(self._tasks) + list(self._bg):
            t.cancel()
        await asyncio.gather(monitor, rotator, *self._tasks, *self._bg, return_exceptions=True)
        try:
            await asyncio.wait_for(self._server.wait_closed(), 2)
        except Exception:
            pass
        self._event("Server stopped")

    # ---------------------------------------------------------- events
    def _event(self, text: str) -> None:
        with self._ev_lock:
            self._seq += 1
            self._events.append((self._seq, time.time(), text))

    def _event_once(self, key: str, text: str, ttl: float = 5.0) -> None:
        now = time.monotonic()
        if now - self._once.get(key, 0.0) >= ttl:
            self._once[key] = now
            self._event(text)

    def _spawn(self, coro) -> None:
        t = asyncio.ensure_future(coro)
        self._bg.add(t)
        t.add_done_callback(self._bg.discard)

    # ---------------------------------------------------------- routing
    def _eligible(self, is_domain: bool, cached: bool = True) -> list:
        now = time.monotonic()
        if cached:
            hit = self._elig_cache.get(is_domain)
            if hit and now - hit[0] < 1.0 and hit[1] == self.pool.version and hit[2] is self.cfg:
                return hit[3]
        cfg = self.cfg
        out = []
        for m in self.pool.members():
            if not m.alive or m.cooldown > now:
                continue
            r = m.res
            if cfg.countries and (r.country_code or "").upper() not in cfg.countries:
                continue
            if r.score < cfg.min_score:
                continue
            if is_domain and cfg.require_rdns and not r.remote_dns:
                continue
            out.append(m)
        if cached:
            self._elig_cache[is_domain] = (now, self.pool.version, cfg, out)
        return out

    def _plan_chain(self, is_domain: bool):
        cfg = self.cfg
        if not cfg.chain:
            return None, "the chain is empty - add proxies to the chain"
        now = time.monotonic()
        members = [self.pool.get(k) for k in cfg.chain]

        def eligible(m):
            if m is None or not m.alive or m.cooldown > now:
                return False
            r = m.res
            if cfg.countries and (r.country_code or "").upper() not in cfg.countries:
                return False
            if r.score < cfg.min_score:
                return False
            return True

        if cfg.mode == "chain_strict":
            if any(not eligible(m) for m in members):
                return None, "a hop of the strict chain is down, cooling, or filtered"
            route = members
        else:
            route = [m for m in members if eligible(m)]
            if not route:
                return None, "every hop of the chain is down, cooling, or filtered"
        if is_domain and cfg.require_rdns and not route[-1].res.remote_dns:
            return None, "last hop cannot resolve hostnames remotely (DNS-leak protection)"
        return route, ""

    def _plan(self, host: str, is_domain: bool):
        """Pick the route (list of Members) for one new connection, or (None, reason)."""
        cfg = self.cfg
        mode = cfg.mode
        if mode in ("chain_strict", "chain_dynamic"):
            return self._plan_chain(is_domain)
        elig = self._eligible(is_domain)
        if not elig:
            return None, "no eligible live proxy in the pool"
        if mode == "chain_random":
            return random.sample(elig, max(1, min(cfg.chain_len, len(elig)))), ""
        if mode == "random":
            return [random.choice(elig)], ""
        if mode == "weighted":
            return [random.choices(elig, weights=[self._weight(m) for m in elig], k=1)[0]], ""
        if mode == "fav_first":
            favs = [m for m in elig if m.key in cfg.favourites]
            usable = favs or (elig if cfg.fav_fallback else [])
            if not usable:
                return None, "no favourite proxy is usable (fallback to other proxies is off)"
            i = self._rr % len(usable)
            self._rr += 1
            return [usable[i]], ""
        if mode == "failover":
            group = min(m.group for m in elig)           # the best (lowest) group that has a usable proxy
            usable = [m for m in elig if m.group == group]
            i = self._rr % len(usable)
            self._rr += 1
            return [usable[i]], ""
        if mode == "fastest":
            return [min(elig, key=lambda m: m.latency_ms if m.latency_ms is not None else 1e12)], ""
        if mode == "sticky":
            pin = self._sticky.get(site_key(host))
            if pin and (cfg.sticky_ttl <= 0 or time.monotonic() - pin[1] < cfg.sticky_ttl):
                for m in elig:
                    if m.key == pin[0]:
                        return [m], ""
        if mode == "manual":
            for m in elig:
                if m.key == self._current_key:
                    return [m], ""
            nxt = self._next_eligible(elig, self._current_key)
            old = self._current_key
            self._current_key = nxt.key
            self.current_exit_ip = nxt.res.exit_ip
            self._event((f"Manual mode: {old} unavailable, " if old else "Manual mode: ")
                        + f"now using {nxt.res.address}")
            return [nxt], ""
        i = self._rr % len(elig)          # round_robin, and first pick for sticky
        self._rr += 1
        return [elig[i]], ""

    def _weight(self, m: Member) -> float:
        """Weighted-random weight: high score and low latency win more often, favourites x3."""
        lat = m.latency_ms if m.latency_ms is not None else 1500.0
        w = (max(1, m.res.score) / 100.0) ** 2 / (1.0 + lat / 1000.0)
        if m.key in self.cfg.favourites:
            w *= 3.0
        return max(w, 1e-6)

    def _why_ineligible(self, m: Member) -> str:
        """Why the server would not route traffic through `m` right now ('' = it can be used)."""
        cfg = self.cfg
        r = m.res
        if not m.alive:
            return "it is marked down by the health monitor"
        if m.cooldown > time.monotonic():
            return "it is cooling down after a failure"
        if cfg.countries and (r.country_code or "").upper() not in cfg.countries:
            return "its country is not in the Countries filter"
        if r.score < cfg.min_score:
            return "its score is below the Min score filter"
        if cfg.require_rdns and not r.remote_dns:
            return "it cannot resolve hostnames remotely (Require remote DNS is on)"
        return ""

    def _next_eligible(self, elig: list, after_key: Optional[str]) -> Member:
        """The next eligible member after `after_key` in pool order (wraps around)."""
        ek = {m.key: m for m in elig}
        order = [m.key for m in self.pool.members()]
        start = order.index(after_key) + 1 if after_key in order else 0
        for k in order[start:] + order[:start]:
            if k in ek and k != after_key:
                return ek[k]
        return ek.get(after_key) or elig[0]

    # ---------------------------------------------------------- upstream connect
    async def _open(self, route: list, host: str, port: int):
        proxy = None
        for m in route:
            r = m.res
            proxy = Proxy(_PTYPE[r.proto], r.host, r.port, r.user or None, r.password or None,
                          rdns=(bool(r.remote_dns) if r.proto in _SOCKS else None),
                          proxy_ssl=proxy_ssl_context(r.proto), forward=proxy)
        return await proxy.connect(dest_host=host, dest_port=port, timeout=self.cfg.connect_timeout)

    async def _connect(self, host: str, port: int):
        cfg = self.cfg
        is_domain = not _is_ip(host)
        if cfg.mode == "chain_strict":
            attempts = 1
        elif cfg.mode == "chain_dynamic":
            attempts = 2
        else:
            attempts = max(1, cfg.retries)
        last: Optional[BaseException] = None
        for _ in range(attempts):
            route, reason = self._plan(host, is_domain)
            if route is None:
                self.stats.blocked += 1
                self._event_once("blocked:" + reason,
                                 f"BLOCKED (kill-switch) {host}:{port} - {reason}")
                raise Blocked(reason)
            t0 = time.monotonic()
            try:
                stream = await self._open(route, host, port)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                last = e
                self._on_failure(route, e, host, port)
                if cfg.mode == "chain_dynamic":
                    await self._recheck(route, urgent=True)
                continue
            self._on_success(route, host, port, (time.monotonic() - t0) * 1000.0)
            task = asyncio.current_task()
            if task is not None:
                self._routes[task] = route
            return stream, route
        self.stats.errors += 1
        raise last if last else Blocked("no route")

    def _on_success(self, route: list, host: str, port: int, ms: float) -> None:
        now = time.monotonic()
        self.stats.success += 1
        for m in route:
            m.uses += 1
            m.last_used = now
        if self.cfg.mode == "sticky" and len(route) == 1:
            key = site_key(host)
            pin = self._sticky.get(key)
            ttl = self.cfg.sticky_ttl
            expired = bool(pin) and ttl > 0 and now - pin[1] >= ttl
            # (re)pin when: nothing pinned, a different proxy was used, or the old pin ran out -
            # without the last case the lifetime of a pin was never renewed when the same proxy
            # happened to be picked again, so the site kept rotating.
            if not pin or pin[0] != route[0].key or expired:
                if len(self._sticky) > 10000:
                    self._sticky.clear()
                self._sticky[key] = (route[0].key, now)
        cfg = self.cfg
        if cfg.mode in _ROTATE_MODES:
            self._rot_conns += 1
            if cfg.rotate_requests > 0 and self._rot_conns >= cfg.rotate_requests and not self._rotating:
                self._spawn(self._auto_rotate(f"{cfg.rotate_requests} connections", exempt=asyncio.current_task()))
        if cfg.log_connections:
            via = " → ".join(m.res.address for m in route)
            cc = route[-1].res.country_code
            self._event(f"{host}:{port} via {via}{f' [{cc}]' if cc else ''} ({ms:.0f} ms)")

    def _on_failure(self, route: list, exc: BaseException, host: str, port: int) -> None:
        cfg = self.cfg
        now = time.monotonic()
        self._elig_cache.clear()
        via = " → ".join(m.res.address for m in route)
        self._event(f"FAILED {host}:{port} via {via}: {describe(exc, classify(exc))}")
        if len(route) == 1 and not cfg.mode.startswith("chain"):
            # Manual mode keeps the IP the user chose: only a proxy that is unreachable or
            # unresponsive is skipped, not one that merely failed to reach a website.
            if cfg.mode != "manual" or classify(exc) in ("connect", "timeout"):
                route[0].cooldown = now + cfg.cooldown
        if cfg.monitor and cfg.mode != "chain_dynamic":
            stale = [m for m in route if now - m.last_check > 15]
            if stale:
                for m in stale:
                    m.last_check = now        # rate-limit repeated re-tests
                self._spawn(self._recheck(stale, urgent=True))

    # ---------------------------------------------------------- health monitor
    async def _probe_full(self, m: Member):
        r = m.res
        entry = ProxyEntry(host=r.host, port=r.port, user=r.user, password=r.password)
        # rdns_only: re-test exactly the way this proxy is used - never fall back to a LOCAL DNS
        # lookup, which would leak a DNS query from this machine on every background test.
        probe, _ = await self._checker._probe(entry, r.proto, rdns_only=bool(r.remote_dns))
        return probe

    async def _probe_member(self, m: Member):
        probe = await self._probe_full(m)
        return (probe is not None), (probe.ms if probe else None)

    def _drop_connections(self, keep_key: str, exempt=None) -> int:
        """Close open client connections that are not using the proxy `keep_key`
        (`exempt` = the one connection that caused the change: it must survive)."""
        n = 0
        for task, route in list(self._routes.items()):
            if task is exempt:
                continue
            if len(route) != 1 or route[0].key != keep_key:
                task.cancel()
                n += 1
        return n

    async def _change_ip(self, target_key: Optional[str] = None, drop: Optional[bool] = None,
                         exempt=None) -> ChangeResult:
        """Move to the next live proxy, or - with `target_key` - hold exactly that proxy.

        drop: close open connections (None = the "Close open connections" setting)."""
        cfg = self.cfg
        cur = self._current_key
        if target_key:
            tm = self.pool.get(target_key)
            if tm is None:
                return ChangeResult(False, message="that proxy is not in the pool any more")
            why = self._why_ineligible(tm)
            if why:
                return ChangeResult(False, message=f"cannot use {tm.res.address}: {why}")
            cands = [tm]
        else:
            elig = self._eligible(True, cached=False)
            if not elig:
                return ChangeResult(False, message="no eligible live proxy in the pool")
            ek = {m.key: m for m in elig}
            order = [m.key for m in self.pool.members()]
            start = order.index(cur) + 1 if cur in order else 0
            ordered = [ek[k] for k in order[start:] + order[:start] if k in ek]
            # the proxy we are leaving comes last: it is only kept when nothing else works
            cands = [m for m in ordered if m.key != cur] + [m for m in ordered if m.key == cur]

        winner = None
        tried = 0
        for i in range(0, min(len(cands), 12), 4):          # at most 3 batches of 4 test requests
            batch = cands[i:i + 4]
            probes = await asyncio.gather(*(self._probe_full(m) for m in batch),
                                          return_exceptions=True)
            for m, p in zip(batch, probes):
                tried += 1
                m.last_check = time.monotonic()
                if p is not None and not isinstance(p, BaseException):
                    m.fails = 0
                    m.latency_ms = p.ms
                    if winner is None:
                        winner = (m, p)
                else:
                    m.fails += 1
                    if m.alive:
                        m.alive = False
                        self._event(f"REMOVED {m.res.address} from the active pool (failed the IP-change test)")
            if winner:
                break
        self._elig_cache.clear()
        if not winner:
            if target_key:
                return ChangeResult(False, message=f"{cands[0].res.address} did not respond (marked down)")
            return ChangeResult(False, message=f"none of the {tried} tested proxies responded")

        m, p = winner
        self._current_key = m.key
        self.current_exit_ip = p.ip
        if m.res.exit_ip != p.ip:
            m.res.exit_ip = p.ip
        dropped = self._drop_connections(m.key, exempt) if (cfg.drop_on_change if drop is None else drop) else 0
        same = m.key == cur
        cc = m.res.country_code
        if target_key:
            head = "Holding (already current): " if same else "IP SET -> "
        else:
            head = "IP unchanged (no other live proxy): " if same else "IP CHANGED -> "
        self._event(head + f"{m.res.address} exit {p.ip}{f' [{cc}]' if cc else ''}"
                    + (f" - {dropped} open connection(s) closed" if dropped else ""))
        note = "" if (target_key or not same) else "no other live proxy responded - staying on the current one"
        res = ChangeResult(True, m.res.address, p.ip, cc, p.ms, dropped, note)
        self.last_change = res
        self.change_count += 1
        self._last_rotate = time.monotonic()                # restart the auto-rotate countdown
        self._rot_conns = 0
        return res

    async def _recheck_report(self, members) -> list:
        await self._recheck(members, urgent=True)
        return [(m.res.address, m.alive, m.latency_ms) for m in members]

    # ---------------------------------------------------------- auto-rotate
    async def _rotate_loop(self) -> None:
        """Time-based auto-rotate (the connection-count trigger lives in _on_success)."""
        while True:
            await asyncio.sleep(1.0)
            cfg = self.cfg
            if cfg.mode not in _ROTATE_MODES or self._rotating or cfg.rotate_minutes <= 0:
                continue
            if time.monotonic() - self._last_rotate >= cfg.rotate_minutes * 60.0:
                await self._auto_rotate(f"{cfg.rotate_minutes:g} min elapsed")

    async def _auto_rotate(self, reason: str, exempt=None) -> None:
        """manual mode: Change IP (verified). sticky mode: forget all site pins -> new IPs."""
        if self._rotating:
            return
        self._rotating = True
        self._last_rotate = time.monotonic()      # also after a failure: no retry storm every second
        self._rot_conns = 0
        try:
            if self.cfg.mode == "manual":
                res = await self._change_ip(drop=self.cfg.rotate_drop, exempt=exempt)
                if not res.ok:
                    self._event(f"Auto-rotate ({reason}): IP not changed - {res.message}")
            else:
                n = len(self._sticky)
                self._sticky.clear()
                self._event(f"Auto-rotate ({reason}): {n} site pin(s) cleared - every site gets a new IP")
        finally:
            self._rotating = False

    async def _recheck(self, members, urgent: bool = False) -> None:
        members = list(members)
        if not members:
            return
        sem = asyncio.Semaphore(30)

        async def one(m: Member):
            async with sem:
                m.last_check = time.monotonic()
                ok, ms = await self._probe_member(m)
            m.last_check = time.monotonic()
            if ok:
                m.fails = 0
                m.latency_ms = ms
                if not m.alive:
                    m.alive, m.cooldown = True, 0.0
                    self._event(f"BACK ONLINE {m.res.address} - re-added to the active pool")
            else:
                m.fails += 1
                limit = 1 if urgent else max(1, self.cfg.max_fails)
                if m.alive and m.fails >= limit:
                    m.alive = False
                    self._event(f"REMOVED {m.res.address} from the active pool (failed {m.fails}x)")

        await asyncio.gather(*(one(m) for m in members), return_exceptions=True)
        self._elig_cache.clear()

    def _monitor_due(self) -> list:
        """Proxies that need a background re-test now, oldest first.

        Instead of re-testing the WHOLE pool every interval (thousands of requests per minute),
        every proxy gets its own due time:
          * in use (recently used / current manual proxy / chain hop) ... every `interval`
          * alive but idle ................................................ every `interval` x 3
          * down (exponential back-off per failed re-test) ............... `interval` x 2, 4, 8 ... 16
        and a single pass is capped, so the load is spread evenly over time.
        """
        cfg = self.cfg
        now = time.monotonic()
        base = max(5.0, float(cfg.monitor_interval))
        chain = set(cfg.chain) if cfg.mode.startswith("chain") else set()
        members = self.pool.members()
        due = []
        for m in members:
            if m.alive:
                hot = (m.key in chain or m.key == self._current_key
                       or (m.last_used and now - m.last_used < base * 2))
                wait = base if hot else base * _IDLE_FACTOR
            else:
                wait = base * min(2 ** max(0, m.fails - 1), _MAX_BACKOFF)
            if now - m.last_check >= wait:
                due.append(m)
        due.sort(key=lambda m: m.last_check)
        # per-pass cap, sized for the (slow) idle cycle: even if the whole pool is due at the same
        # moment the re-tests are spread over many passes instead of one burst
        budget = max(40, math.ceil(len(members) * _MONITOR_TICK / (base * _IDLE_FACTOR)) * 2)
        return due[:budget]

    async def _monitor_loop(self) -> None:
        while True:
            await asyncio.sleep(_MONITOR_TICK)
            if not self.cfg.monitor:
                continue
            due = self._monitor_due()
            if due:
                await self._recheck(due)

    # ---------------------------------------------------------- client side
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        self._tasks.add(task)
        self.stats.total += 1
        self.stats.active += 1
        try:
            first = await asyncio.wait_for(reader.readexactly(1), 15)
            if first == b"\x05":
                await self._socks5(reader, writer)
            elif first == b"\x04":
                await self._socks4(reader, writer)
            else:
                await self._http(first, reader, writer)
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        finally:
            self.stats.active -= 1
            self._tasks.discard(task)
            self._routes.pop(task, None)
            try:
                writer.close()
            except Exception:
                pass

    async def _socks5(self, reader, writer) -> None:
        def reply(code: int) -> None:
            writer.write(b"\x05" + bytes([code]) + b"\x00\x01\x00\x00\x00\x00\x00\x00")

        n = (await reader.readexactly(1))[0]
        methods = await reader.readexactly(n)
        if 0 not in methods:
            writer.write(b"\x05\xff")
            return
        writer.write(b"\x05\x00")
        await writer.drain()
        _, cmd, _, atyp = await reader.readexactly(4)
        if atyp == 1:
            host = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == 3:
            ln = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(ln)).decode("utf-8", "ignore")
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        else:
            reply(0x08)
            return
        port = int.from_bytes(await reader.readexactly(2), "big")
        if cmd != 1:                       # only CONNECT (no BIND / UDP ASSOCIATE)
            reply(0x07)
            return
        try:
            up, _ = await self._connect(host, port)
        except Blocked:
            reply(0x02)
            return
        except Exception:
            reply(0x04)
            return
        reply(0x00)
        await writer.drain()
        await self._relay(reader, writer, up)

    async def _socks4(self, reader, writer) -> None:
        def reply(ok: bool) -> None:
            writer.write(b"\x00" + (b"\x5a" if ok else b"\x5b") + b"\x00" * 6)

        cmd = (await reader.readexactly(1))[0]
        port = int.from_bytes(await reader.readexactly(2), "big")
        ip = await reader.readexactly(4)
        await reader.readuntil(b"\x00")                      # user id
        if ip[:3] == b"\x00\x00\x00" and ip[3] != 0:         # SOCKS4a: hostname follows
            host = (await reader.readuntil(b"\x00"))[:-1].decode("utf-8", "ignore")
        else:
            host = socket.inet_ntoa(ip)
        if cmd != 1:
            reply(False)
            return
        try:
            up, _ = await self._connect(host, port)
        except Exception:
            reply(False)
            return
        reply(True)
        await writer.drain()
        await self._relay(reader, writer, up)

    async def _http(self, first: bytes, reader, writer) -> None:
        def error(code: int, text: str) -> None:
            body = (text + "\n").encode()
            writer.write(f"HTTP/1.1 {code} {text.split(':')[0]}\r\nContent-Type: text/plain\r\n"
                         f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)

        head = first + await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
        lines = head.split(b"\r\n")
        try:
            method, target, version = lines[0].decode("latin-1").split(" ", 2)
            if method.upper() == "CONNECT":
                host, port = split_hostport(target, 443)
            else:
                u = urlsplit(target)
                if u.scheme != "http" or not u.hostname:
                    error(400, "Bad Request: this is a proxy server, use it as an HTTP/SOCKS proxy")
                    return
                host, port = u.hostname, u.port or 80
            if not host or not 1 <= int(port) <= 65535:
                error(400, "Bad Request: invalid destination host or port")
                return
        except (ValueError, IndexError):
            error(400, "Bad Request")
            return

        try:
            up, _ = await self._connect(host, port)
        except Blocked as e:
            error(503, f"Service Unavailable: kill-switch active ({e})")
            return
        except Exception:
            error(502, "Bad Gateway: could not reach the destination through the proxy pool")
            return

        if method.upper() == "CONNECT":
            writer.write(b"HTTP/1.1 200 Connection established\r\nProxy-Agent: proxy-toolkit\r\n\r\n")
            await writer.drain()
        else:
            path = (u.path or "/") + (f"?{u.query}" if u.query else "")
            out = [f"{method} {path} {version}".encode("latin-1")]
            # Connection can nominate additional hop-by-hop headers; strip those too.
            hop_by_hop = set(_HOP_BY_HOP)
            for raw in lines[1:]:
                name, sep, value = raw.partition(b":")
                if sep and name.strip().lower() == b"connection":
                    hop_by_hop.update(token.strip().lower() for token in value.split(b",") if token.strip())
            for raw in lines[1:]:
                name, sep, _ = raw.partition(b":")
                if raw and sep and name.strip().lower() not in hop_by_hop:
                    out.append(raw)
            out.append(b"Connection: close")      # one request per connection: always the right host
            await up.write(b"\r\n".join(out) + b"\r\n\r\n")
        await self._relay(reader, writer, up)

    @staticmethod
    def _half_close(up) -> bool:
        """Send EOF to the upstream but keep reading its reply. False if the stream cannot do it."""
        try:
            w = up.writer
            if w.can_write_eof():
                w.write_eof()
                return True
        except Exception:
            pass
        return False

    async def _relay(self, cr: asyncio.StreamReader, cw: asyncio.StreamWriter, up) -> None:
        """Copy data both ways until one side is really finished.

        When the CLIENT stops sending (EOF) the upstream is only half-closed and its reply keeps
        flowing to the client; before, the whole upstream connection was closed at that point and
        replies of clients that "send request, shutdown(write), wait for answer" were cut off.
        When the UPSTREAM ends, everything is closed.
        """
        idle = self.cfg.idle_timeout
        linger = max(1.0, self.cfg.half_close_timeout)
        state = {"client_done": False}

        async def client_to_upstream():
            try:
                while True:
                    data = await asyncio.wait_for(cr.read(65536), idle)
                    if not data:
                        break
                    await up.write(data)
                    self.stats.up += len(data)
            except Exception:
                pass
            state["client_done"] = True
            self._half_close(up)

        async def upstream_to_client():
            try:
                while True:
                    # after the client is done only wait `linger` for more data: the client may
                    # be gone for good (no way to tell EOF from a closed socket), so don't hold
                    # the upstream connection for the full idle timeout.
                    data = await asyncio.wait_for(up.read(65536),
                                                  linger if state["client_done"] else idle)
                    if not data:
                        break
                    cw.write(data)
                    await cw.drain()
                    self.stats.down += len(data)
            except Exception:
                pass

        t_up = asyncio.ensure_future(client_to_upstream())
        t_down = asyncio.ensure_future(upstream_to_client())
        try:
            await t_down                       # the reply direction decides when we are done
        finally:
            for t in (t_up, t_down):
                if not t.done():
                    t.cancel()
            await asyncio.gather(t_up, t_down, return_exceptions=True)
            try:
                await up.close()
            except Exception:
                pass
            try:
                cw.close()
            except Exception:
                pass
