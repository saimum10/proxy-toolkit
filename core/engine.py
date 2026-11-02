"""Engine manager: runs Xray-core so that V2Ray-style links look like ordinary SOCKS5 proxies.

One Xray process hosts MANY links: every link gets its own SOCKS5 inbound on 127.0.0.1:<port>
(protected with a random user/password so no other program on this computer can use it) that
is routed to exactly one outbound (the real vless / vmess / trojan / ss server). There is NO
"freedom" (direct) outbound, so nothing can ever leave through your real IP.

If a single link makes Xray refuse the whole config, the batch is split in halves until the
broken link is isolated - the others keep working and the broken one gets Xray's error text.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Optional

from .store import config_dir

_IS_WIN = sys.platform == "win32"
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if _IS_WIN else 0
DEFAULT_CHUNK = 200                 # links per Xray process
RELEASE_BASE = "https://github.com/XTLS/Xray-core/releases/latest/download/"
MAX_DOWNLOAD = 80 * 1024 * 1024


class EngineError(Exception):
    pass


class EngineUnavailable(EngineError):
    """The engine binary itself cannot be run (missing, wrong architecture, no permission)."""


# ---------------------------------------------------------------- finding the binary
def engine_dir() -> Path:
    return config_dir() / "engine"


def _binary_name() -> str:
    return "xray.exe" if _IS_WIN else "xray"


def find_binary(custom: str = "") -> Optional[Path]:
    """Xray binary: the path the user set, ~/.config/proxy-toolkit/engine/, next to the app, PATH."""
    cands = []
    if custom.strip():
        cands.append(Path(custom.strip()).expanduser())
    cands.append(engine_dir() / _binary_name())
    here = Path(sys.argv[0]).resolve().parent if sys.argv and sys.argv[0] else Path.cwd()
    for d in (here, here / "engine", Path.cwd(), Path.cwd() / "engine"):
        cands.append(d / _binary_name())
    for p in cands:
        try:
            if p.is_file() and os.access(p, os.X_OK):
                return p
        except OSError:
            continue
    found = shutil.which("xray")
    return Path(found) if found else None


_VERSION_CACHE: dict = {}


def binary_version(path: Path) -> str:
    """e.g. 'Xray 26.10.21' ('' if the binary cannot be run). Runs the binary once per file version
    (it blocks for up to 8 s on a broken binary: call it from a worker thread)."""
    try:
        key = (str(path), path.stat().st_mtime)
    except OSError:
        return ""
    if key in _VERSION_CACHE:
        return _VERSION_CACHE[key]
    try:
        out = subprocess.run([str(path), "version"], capture_output=True, text=True, timeout=8,
                             stdin=subprocess.DEVNULL, creationflags=_NO_WINDOW).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    m = re.search(r"Xray\s+(\d+(?:\.\d+)+)", out)
    ver = f"Xray {m.group(1)}" if m else ""
    if ver:
        _VERSION_CACHE[key] = ver
    return ver


# ---------------------------------------------------------------- config
def free_ports(n: int) -> list:
    socks = []
    try:
        for _ in range(n):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", 0))
            socks.append(s)
        return [s.getsockname()[1] for s in socks]
    finally:
        for s in socks:
            s.close()


def build_config(entries: list, ports: list, user: str, password: str) -> dict:
    inbounds, outbounds, rules = [], [], []
    for i, (e, port) in enumerate(zip(entries, ports)):
        inbounds.append({
            "tag": f"in{i}", "listen": "127.0.0.1", "port": port, "protocol": "socks",
            "settings": {"auth": "password", "accounts": [{"user": user, "pass": password}],
                         "udp": False}})
        outbounds.append(e.outbound(f"out{i}"))
        rules.append({"type": "field", "inboundTag": [f"in{i}"], "outboundTag": f"out{i}"})
    return {"log": {"loglevel": "warning"}, "inbounds": inbounds, "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules}}


def short_error(lines) -> str:
    """Xray prints a long  'a > b > c: reason'  chain - keep only the reason."""
    lines = [ln.strip() for ln in lines if ln and ln.strip()]
    for ln in reversed(lines):
        if "Failed to start" in ln or "failed" in ln.lower() or "error" in ln.lower() or "prohibited" in ln:
            tail = ln.split(" > ")[-1]
            tail = re.sub(r"^(common/errors|infra/conf|main|app/\S+|proxy/\S+|transport/\S+):\s*", "", tail)
            return tail[:240]
    return (lines[-1] if lines else "engine exited without a message")[:240]


def validate_entries(binary: Path, entries: list, workers: int = 8, should_stop: Optional[Callable] = None) -> list:
    """Ask the engine about every link on its own (`xray run -test`, ~20 ms each, in parallel).

    Returns [(entry, reason)] for the links Xray refuses. Much faster than finding them by
    repeatedly starting and halving a whole batch."""
    def one(e):
        if should_stop and should_stop():
            return None
        d = Path(tempfile.mkdtemp(prefix="ptk-engine-"))
        try:
            cfg = d / "c.json"
            fd = os.open(cfg, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(build_config([e], [1], "u", "p"), fh)       # -test never opens the port
            r = subprocess.run([str(binary), "run", "-test", "-c", str(cfg)], capture_output=True, text=True,
                               timeout=20, stdin=subprocess.DEVNULL, creationflags=_NO_WINDOW)
            if r.returncode == 0:
                return None
            return (e, short_error((r.stdout + r.stderr).splitlines()))
        except (OSError, subprocess.SubprocessError):
            return None                                               # cannot judge: the real start decides
        finally:
            shutil.rmtree(d, ignore_errors=True)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return [r for r in pool.map(one, entries) if r]


# ---------------------------------------------------------------- one Xray process
class Engine:
    def __init__(self, binary: Path, entries: list):
        self.binary = Path(binary)
        self.entries = list(entries)
        self.user = secrets.token_hex(8)
        self.password = secrets.token_hex(16)
        self.ports: list = []
        self.proc: Optional[subprocess.Popen] = None
        self.restarts = 0
        self._dir: Optional[Path] = None
        self._tail: deque = deque(maxlen=30)
        self._config: Optional[dict] = None

    @property
    def keys(self) -> list:
        return [e.key for e in self.entries]

    def endpoint(self, key: str):
        """(port, user, password) of the SOCKS5 inbound for this link, or None."""
        for e, port in zip(self.entries, self.ports):
            if e.key == key:
                return port, self.user, self.password
        return None

    @property
    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def error_text(self) -> str:
        """Short reason for a failed start (Xray prints a long  'a > b > c: reason'  chain)."""
        return short_error(self._tail)

    # ---- lifecycle
    def start(self, timeout: float = 12.0) -> None:
        if self.alive:
            return
        if not self.ports:
            self.ports = free_ports(len(self.entries))
            self._config = build_config(self.entries, self.ports, self.user, self.password)
        self._write_config()
        self._tail.clear()
        try:
            self.proc = subprocess.Popen(
                [str(self.binary), "run", "-c", str(self._dir / "config.json")],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, errors="replace", start_new_session=not _IS_WIN, creationflags=_NO_WINDOW)
        except OSError as exc:
            self._cleanup_dir()
            raise EngineUnavailable(f"cannot run {self.binary}: {exc}") from None
        threading.Thread(target=self._pump_stderr, args=(self.proc,), daemon=True).start()
        self._arm_watchdog()

        deadline = time.monotonic() + timeout
        pending = list(self.ports)
        while pending and time.monotonic() < deadline:
            if self.proc.poll() is not None:
                time.sleep(0.15)                          # let the stderr reader catch up
                msg = self.error_text()
                self._disarm_watchdog()
                self._cleanup_dir()
                raise EngineError(msg)
            still = []
            for port in pending:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                        pass
                except OSError:
                    still.append(port)
            pending = still
            if pending:
                time.sleep(0.05)
        if pending:
            self.stop()
            raise EngineError("the engine did not open its local ports in time")
        # the config file holds every secret (uuids, passwords): nobody needs it once Xray has read it
        self._cleanup_dir()

    def _pump_stderr(self, proc) -> None:
        try:
            for line in proc.stdout:
                self._tail.append(line.rstrip())
        except (OSError, ValueError):
            pass

    def _write_config(self) -> None:
        self._cleanup_dir()
        self._dir = Path(tempfile.mkdtemp(prefix="ptk-engine-"))      # mode 0700
        cfg = self._dir / "config.json"
        fd = os.open(cfg, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(self._config, fh)

    def _cleanup_dir(self) -> None:
        if self._dir:
            shutil.rmtree(self._dir, ignore_errors=True)
            self._dir = None

    # ---- watchdog: Xray must not outlive the app
    # A tiny `sh` process waits on a pipe that only this app holds. If the app dies in ANY way
    # (kill -9, crash, power-off of the session) the pipe closes and the watchdog stops Xray, which
    # would otherwise keep running with its local ports open. Before it kills anything it checks
    # that the pid still belongs to one of our engines (a recycled pid must never be hit).
    _WATCHDOG = (
        'if read -r _; then exit 0; fi; '
        'case "$(ps -p "$0" -o args= 2>/dev/null)" in *ptk-engine-*) kill -TERM "$0" 2>/dev/null; sleep 2; '
        'case "$(ps -p "$0" -o args= 2>/dev/null)" in *ptk-engine-*) kill -KILL "$0" 2>/dev/null;; esac;; esac'
    )

    def _arm_watchdog(self) -> None:
        self._watchdog = None
        if _IS_WIN or not shutil.which("sh") or self.proc is None:
            return
        try:
            self._watchdog = subprocess.Popen(
                ["sh", "-c", self._WATCHDOG, str(self.proc.pid)], stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        except OSError:
            self._watchdog = None

    def _disarm_watchdog(self) -> None:
        wd, self._watchdog = getattr(self, "_watchdog", None), None
        if wd is None:
            return
        try:
            wd.stdin.write(b"\n")                     # "all clear": the watchdog exits without killing
            wd.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            wd.wait(timeout=1.5)
        except subprocess.TimeoutExpired:
            wd.kill()

    def stop(self) -> None:
        self._disarm_watchdog()
        proc, self.proc = self.proc, None
        if proc is not None and proc.poll() is None:
            try:
                if _IS_WIN:
                    proc.terminate()
                else:
                    os.killpg(proc.pid, signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        self._cleanup_dir()

    def restart(self) -> None:
        """Start again with the SAME ports / credentials (pool members keep pointing at them)."""
        self.stop()
        self.restarts += 1
        self.start()


_INSECURE_SUPPORT: dict = {}


def supports_allow_insecure(binary: Path) -> bool:
    """False for Xray versions that removed "allowInsecure" (they want a pinned certificate hash)."""
    try:
        key = (str(binary), binary.stat().st_mtime)
    except OSError:
        return True
    if key not in _INSECURE_SUPPORT:
        cfg = {"log": {"loglevel": "none"}, "outbounds": [{
            "protocol": "trojan", "settings": {"servers": [{"address": "127.0.0.1", "port": 1, "password": "x"}]},
            "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"allowInsecure": True}}}]}
        d = Path(tempfile.mkdtemp(prefix="ptk-engine-"))
        try:
            (d / "t.json").write_text(json.dumps(cfg))
            out = subprocess.run([str(binary), "run", "-test", "-c", str(d / "t.json")], capture_output=True,
                                 text=True, timeout=15, stdin=subprocess.DEVNULL, creationflags=_NO_WINDOW)
            _INSECURE_SUPPORT[key] = "has been removed" not in (out.stdout + out.stderr)
        except (OSError, subprocess.SubprocessError):
            _INSECURE_SUPPORT[key] = True
        finally:
            shutil.rmtree(d, ignore_errors=True)
    return _INSECURE_SUPPORT[key]


def fetch_cert_sha256(host: str, port: int, sni: str = "", timeout: float = 6.0) -> str:
    """SHA-256 (hex) of the certificate a TLS server presents - what Xray's pinnedPeerCertSha256 wants."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni or None) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise OSError("the server sent no certificate")
    return hashlib.sha256(der).hexdigest()


def pin_certificates(entries: list, timeout: float = 4.0, should_stop: Optional[Callable] = None,
                     workers: int = 48):
    """For links that ask to skip certificate checks: fetch + pin each server certificate.

    Returns [(entry, reason)] for the links whose server could not be reached."""
    todo = [e for e in entries if e.f.get("allow_insecure") and e.f.get("security") == "tls"]
    failed = []

    def one(e):
        if should_stop and should_stop():
            return (e, "stopped")
        try:
            e.f["pin"] = fetch_cert_sha256(e.host, e.port, e.f.get("sni") or e.f.get("host") or "", timeout)
            return None
        except Exception as exc:
            return (e, f"cannot read the server certificate ({type(exc).__name__}: {exc})"[:200])

    if todo:
        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(todo)))) as pool:
            failed = [r for r in pool.map(one, todo) if r]
    return failed


def launch(binary: Path, entries: list, chunk: int = DEFAULT_CHUNK,
           log: Optional[Callable] = None, should_stop: Optional[Callable] = None):
    """Start engines for `entries` (blocking: run it in a worker thread).

    Returns (engines, failures) where failures = [(LinkEntry, reason)]."""
    engines: list = []
    failures: list = []
    log = log or (lambda msg: None)

    if any(e.f.get("allow_insecure") for e in entries) and not supports_allow_insecure(binary):
        log("this Xray needs server certificates pinned: reading them first…")
        bad = pin_certificates(entries, should_stop=should_stop)       # this Xray needs the certificate pinned
        if bad:
            failures.extend(bad)
            gone = {id(e) for e, _ in bad}
            entries = [e for e in entries if id(e) not in gone]

    def attempt(batch: list) -> None:
        if should_stop and should_stop():
            return
        eng = Engine(binary, batch)
        try:
            eng.start()
            engines.append(eng)
        except EngineUnavailable:
            raise
        except EngineError as exc:
            if len(batch) == 1:
                failures.append((batch[0], str(exc)))
                return
            bad = validate_entries(binary, batch, should_stop=should_stop)
            if bad:
                failures.extend(bad)
                gone = {id(e) for e, _ in bad}
                good = [e for e in batch if id(e) not in gone]
                log(f"engine refused {len(bad)} of {len(batch)} links - starting the other {len(good)}")
                if good:
                    attempt(good)
                return
            log(f"engine refused a batch of {len(batch)} links ({exc}) - isolating the broken one…")
            mid = len(batch) // 2
            attempt(batch[:mid])
            attempt(batch[mid:])

    try:
        for i in range(0, len(entries), max(1, chunk)):
            attempt(entries[i:i + chunk])
        # isolating broken links leaves the good ones spread over many small processes:
        # put them back together (one process per `chunk` links)
        good = [e for eng in engines for e in eng.entries]
        if failures and len(engines) > -(-len(good) // max(1, chunk)):
            for eng in engines:
                eng.stop()
            engines.clear()
            for i in range(0, len(good), max(1, chunk)):
                attempt(good[i:i + chunk])
    except EngineUnavailable:
        for e in engines:
            e.stop()
        raise
    return engines, failures


_EXPLAIN = (
    ("vless without TLS or other encryption is prohibited",
     "Xray refuses VLESS without TLS/Reality to a public IP address (its security policy) - "
     "this link cannot be used with this engine"),
    ("allowInsecure", "this Xray version does not accept the link's certificate setting"),
)


def explain_error(reason: str) -> str:
    """Friendlier text for the engine errors users run into most."""
    for needle, text in _EXPLAIN:
        if needle in reason:
            return text
    return reason


class EngineGroup:
    """All running engines of the application.

    Every link has exactly ONE owner engine: the newest engine that is alive (or, when none is
    alive, the newest dead one - it may still be revived). A newer engine for the same link
    therefore replaces an older one instead of piling up, and a dead engine never hands out its
    (closed) port while a living one exists."""

    def __init__(self):
        self.engines: list = []
        self._lock = threading.Lock()

    def add(self, engines) -> None:
        with self._lock:
            self.engines.extend(engines)

    def _owners(self) -> dict:                       # (lock held)  key -> owner engine
        owner: dict = {}
        for eng in self.engines:                     # old -> new
            for k in eng.keys:
                cur = owner.get(k)
                if cur is None or eng.alive or not cur.alive:
                    owner[k] = eng
        return owner

    def endpoint(self, key: str):
        """(port, user, password) of the running engine that serves `key`, or None."""
        with self._lock:
            eng = self._owners().get(key)
        return eng.endpoint(key) if eng is not None and eng.alive else None

    def _wanted_engines(self, keep_keys: set) -> list:   # (lock held)
        owners = self._owners()
        ids = {id(eng) for k, eng in owners.items() if k in keep_keys}
        return [e for e in self.engines if id(e) in ids]

    def prune(self, keep_keys: set) -> int:
        """Stop engines that own none of the wanted links. Returns how many were stopped."""
        with self._lock:
            keep = self._wanted_engines(keep_keys)
            drop = [e for e in self.engines if e not in keep]
            self.engines = keep
        for e in drop:
            e.stop()
        return len(drop)

    def revive(self, keep_keys: set, max_restarts: int = 3) -> list:
        """Restart dead engines that own wanted links. Returns [(message, restarted link keys)]."""
        out = []
        with self._lock:
            engines = [e for e in self._wanted_engines(keep_keys) if not e.alive]
        for e in engines:
            if e.restarts >= max_restarts:
                continue
            try:
                e.restart()
                out.append((f"engine restarted ({len(e.entries)} links, attempt {e.restarts})", list(e.keys)))
            except EngineError as exc:
                out.append((f"engine could not be restarted: {exc}", []))
        return out

    def stop_all(self) -> None:
        with self._lock:
            engines, self.engines = self.engines, []
        for e in engines:
            e.stop()

    @property
    def process_count(self) -> int:
        with self._lock:
            return sum(1 for e in self.engines if e.alive)

    @property
    def link_count(self) -> int:
        with self._lock:
            return sum(len(e.entries) for e in self.engines if e.alive)


# ---------------------------------------------------------------- download
def release_asset() -> str:
    m = platform.machine().lower()
    arm64 = m in ("aarch64", "arm64", "armv8l")
    if sys.platform == "win32":
        return "Xray-windows-arm64-v8a.zip" if arm64 else "Xray-windows-64.zip"
    if sys.platform == "darwin":
        return "Xray-macos-arm64-v8a.zip" if arm64 else "Xray-macos-64.zip"
    if arm64:
        return "Xray-linux-arm64-v8a.zip"
    if m.startswith("armv7") or m == "armv6l":
        return "Xray-linux-arm32-v7a.zip"
    return "Xray-linux-64.zip"


async def download_xray(progress: Optional[Callable] = None) -> Path:
    """Download the newest Xray-core release into the app's engine folder.

    The zip is checked against the SHA-256 published next to it (this catches damaged downloads;
    it cannot protect against a compromised release page - same trust as downloading by hand)."""
    import aiohttp

    asset = release_asset()
    note = progress or (lambda msg: None)
    tmo = aiohttp.ClientTimeout(total=300)
    async with aiohttp.ClientSession(timeout=tmo, trust_env=False,
                                     headers={"User-Agent": "ProxyToolkit"}) as s:
        note(f"Downloading {asset}.dgst …")
        async with s.get(RELEASE_BASE + asset + ".dgst") as r:
            if r.status != 200:
                raise EngineError(f"checksum file not available (HTTP {r.status})")
            dgst = await r.text()
        m = re.search(r"SHA2?-?256\s*=\s*([0-9a-fA-F]{64})", dgst)
        if not m:
            raise EngineError("checksum file has an unexpected format")
        want = m.group(1).lower()

        note(f"Downloading {asset} …")
        data = bytearray()
        async with s.get(RELEASE_BASE + asset) as r:
            if r.status != 200:
                raise EngineError(f"download failed (HTTP {r.status})")
            total = r.content_length or 0
            async for chunk in r.content.iter_chunked(65536):
                data += chunk
                if len(data) > MAX_DOWNLOAD:
                    raise EngineError("download is larger than expected")
                if total:
                    note(f"Downloading {asset} … {100 * len(data) // total}%")
    if hashlib.sha256(bytes(data)).hexdigest() != want:
        raise EngineError("checksum mismatch - the download was damaged, nothing was installed")

    dest_dir = engine_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = _binary_name()
    tmp_zip = dest_dir / "download.zip"
    tmp_zip.write_bytes(bytes(data))
    try:
        with zipfile.ZipFile(tmp_zip) as zf:
            member = next((n for n in zf.namelist() if n == name), None)
            if member is None:
                raise EngineError(f"{name} not found inside the downloaded archive")
            target = dest_dir / name
            tmp_bin = dest_dir / (name + ".new")
            tmp_bin.write_bytes(zf.read(member))           # only this one file is ever extracted
    finally:
        tmp_zip.unlink(missing_ok=True)
    if not _IS_WIN:
        tmp_bin.chmod(0o755)
    tmp_bin.replace(target)
    if not binary_version(target):
        raise EngineError("the downloaded engine cannot run on this computer")
    return target
