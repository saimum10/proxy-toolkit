"""Launch a browser that can only reach the internet through the local proxy server.

The browser gets a throw-away profile with the usual leak paths switched off:
WebRTC (STUN/UDP), local DNS, QUIC (HTTP/3), IPv6 DNS, DNS-over-HTTPS, captive-portal
checks and "fall back to a direct connection if the proxy fails".

This protects ONLY the browser window started from here. It is not an OS-level guarantee.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

LEAK_TEST_URL = "https://browserleaks.com/webrtc"
_IS_WIN = os.name == "nt"

# (label, executable, kind)
_CANDIDATES = [
    ("Firefox", "firefox", "firefox"),
    ("Firefox ESR", "firefox-esr", "firefox"),
    ("Chromium", "chromium", "chromium"),
    ("Chromium", "chromium-browser", "chromium"),
    ("Google Chrome", "google-chrome-stable", "chromium"),
    ("Google Chrome", "google-chrome", "chromium"),
    ("Brave", "brave-browser", "chromium"),
    ("Brave", "brave-browser-stable", "chromium"),
]


# Windows: browsers are not on PATH, so look in the usual install folders.
_WIN_APPS = [
    ("Firefox", ("Mozilla Firefox", "firefox.exe"), "firefox"),
    ("Google Chrome", ("Google", "Chrome", "Application", "chrome.exe"), "chromium"),
    ("Microsoft Edge", ("Microsoft", "Edge", "Application", "msedge.exe"), "chromium"),
    ("Brave", ("BraveSoftware", "Brave-Browser", "Application", "brave.exe"), "chromium"),
    ("Chromium", ("Chromium", "Application", "chrome.exe"), "chromium"),
]


@dataclass
class BrowserInfo:
    label: str
    path: str
    kind: str          # "firefox" | "chromium"
    snap: bool = False

    @property
    def title(self) -> str:
        return self.label + (" (snap)" if self.snap else "")


def _is_snap(path: str) -> bool:
    if _IS_WIN:
        return False
    real = os.path.realpath(path)
    if real.startswith("/snap/") or os.path.basename(real) == "snap":
        return True
    try:
        with open(path, "rb") as f:                     # Ubuntu's /usr/bin/firefox is a wrapper script
            head = f.read(4096)
        return b"/snap/" in head or b"snap run" in head
    except OSError:
        return False


def _find_windows(env) -> list[BrowserInfo]:
    roots = [env.get(k) for k in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)", "LOCALAPPDATA")]
    found: list[BrowserInfo] = []
    seen: set[str] = set()
    for label, parts, kind in _WIN_APPS:
        for root in roots:
            if not root:
                continue
            path = os.path.join(root, *parts)
            key = os.path.normcase(os.path.realpath(path))
            if key in seen or not os.path.isfile(path):
                continue
            seen.add(key)
            found.append(BrowserInfo(label, path, kind, False))
    return found


def find_browsers(env=None, windows: bool | None = None) -> list[BrowserInfo]:
    if (_IS_WIN if windows is None else windows):
        return _find_windows(os.environ if env is None else env)
    found: list[BrowserInfo] = []
    seen: set[str] = set()
    for label, exe, kind in _CANDIDATES:
        path = shutil.which(exe)
        if not path:
            continue
        real = os.path.realpath(path)
        if real in seen:
            continue
        seen.add(real)
        found.append(BrowserInfo(label, path, kind, _is_snap(path)))
    return found


def profiles_root() -> Path:
    # Not a hidden folder: snap browsers are not allowed to read dot-folders in $HOME.
    return Path.home() / "proxy-toolkit-profiles"


# ------------------------------------------------------------------ settings
def firefox_prefs(host: str, port: int) -> dict:
    return {
        # proxy: SOCKS5 with remote DNS, never fall back to a direct connection
        "network.proxy.type": 1,
        "network.proxy.socks": host,
        "network.proxy.socks_port": port,
        "network.proxy.socks_version": 5,
        "network.proxy.socks_remote_dns": True,
        "network.proxy.http": "",
        "network.proxy.ssl": "",
        "network.proxy.ftp": "",
        "network.proxy.failover_direct": False,
        "network.proxy.allow_bypass": False,
        # WebRTC: off completely (+ belt and braces if it is ever re-enabled)
        "media.peerconnection.enabled": False,
        "media.peerconnection.ice.default_address_only": True,
        "media.peerconnection.ice.no_host": True,
        "media.peerconnection.ice.proxy_only": True,
        # UDP-based or side-channel network paths
        "network.http.http3.enable": False,
        "network.dns.disableIPv6": True,
        "network.trr.mode": 5,                    # DNS-over-HTTPS off
        "network.dns.disablePrefetch": True,
        "network.prefetch-next": False,
        "network.predictor.enabled": False,
        "network.http.speculative-parallel-limit": 0,
        "network.captive-portal-service.enabled": False,
        "network.connectivity-service.enabled": False,
        "geo.enabled": False,
        # no first-run pages / telemetry
        "browser.shell.checkDefaultBrowser": False,
        "browser.startup.homepage_override.mstone": "ignore",
        "startup.homepage_welcome_url": "",
        "startup.homepage_welcome_url.additional": "",
        "browser.aboutwelcome.enabled": False,
        "datareporting.policy.dataSubmissionEnabled": False,
        "datareporting.healthreport.uploadEnabled": False,
        "toolkit.telemetry.enabled": False,
        "app.normandy.enabled": False,
    }


def _js(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    return json.dumps(v)


def write_firefox_profile(profile: Path, host: str, port: int) -> None:
    lines = [f'user_pref({json.dumps(k)}, {_js(v)});' for k, v in firefox_prefs(host, port).items()]
    (profile / "user.js").write_text("\n".join(lines) + "\n", encoding="utf-8")


def chromium_args(host: str, port: int, profile: Path) -> list[str]:
    return [
        f"--user-data-dir={profile}",
        f"--proxy-server=socks5://{host}:{port}",
        # any name that would be resolved locally simply fails instead of leaking
        "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--disable-quic",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-sync",
        "--disable-domain-reliability",
        "--disable-client-side-phishing-detection",
        "--no-pings",
        "--no-first-run",
        "--no-default-browser-check",
    ]


def _child_env() -> dict:
    """Environment for the browser process.

    A PyInstaller one-file binary points the dynamic loader (LD_LIBRARY_PATH) at its own bundled
    libraries. The system Firefox / Chromium must not inherit that, or they can load the wrong
    libraries and crash. Restore the original value (or drop it) when running frozen.
    """
    env = dict(os.environ)
    if getattr(sys, "frozen", False):
        orig = env.pop("LD_LIBRARY_PATH_ORIG", None)
        if orig is not None:
            env["LD_LIBRARY_PATH"] = orig
        else:
            env.pop("LD_LIBRARY_PATH", None)
        for k in ("QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH"):
            env.pop(k, None)
    return env


# ------------------------------------------------------------------ session
@dataclass
class Session:
    info: BrowserInfo
    profile: Path
    proc: subprocess.Popen
    keep: bool
    started: float

    def finished(self) -> int | None:
        return self.proc.poll()

    def cleanup(self) -> None:
        if not self.keep:
            shutil.rmtree(self.profile, ignore_errors=True)


def _lock_pid(profile: Path) -> int | None:
    for name in ("lock", "SingletonLock"):           # Firefox / Chromium lock symlinks
        p = profile / name
        if os.path.lexists(p):
            try:
                m = re.search(r"(\d+)$", os.readlink(p))
            except OSError:
                return -1
            return int(m.group(1)) if m else -1
    return None


def _in_use(profile: Path) -> bool:
    if time.time() - profile.stat().st_mtime < 60:    # just created
        return True
    if _IS_WIN:
        # a running browser keeps its lock file open, so it cannot be deleted
        for name in ("parent.lock", "lockfile"):
            f = profile / name
            if f.exists():
                try:
                    os.remove(f)
                except OSError:
                    return True
        return False
    pid = _lock_pid(profile)
    if pid is None:
        return False
    if pid <= 0:
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def prune_stale() -> None:
    """Delete leftover temporary profiles of browsers that are no longer running."""
    root = profiles_root()
    if not root.is_dir():
        return
    for d in root.glob("session-*"):
        try:
            if d.is_dir() and not _in_use(d):
                shutil.rmtree(d, ignore_errors=True)
        except OSError:
            pass


def launch(info: BrowserInfo, host: str, port: int, url: str | None = None,
           keep: bool = False) -> Session:
    root = profiles_root()
    root.mkdir(parents=True, exist_ok=True)
    prune_stale()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    profile = root / f"{'kept' if keep else 'session'}-{stamp}-{os.getpid()}"
    profile.mkdir(parents=True, exist_ok=True)

    if info.kind == "firefox":
        write_firefox_profile(profile, host, port)
        cmd = [info.path, "--no-remote", "--new-instance", "--profile", str(profile)]
        if url:
            cmd.append(url)
    else:
        cmd = [info.path, *chromium_args(host, port, profile)]
        if url:
            cmd.append(url)

    kw = {} if _IS_WIN else {"start_new_session": True}
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, env=_child_env(), **kw)
    return Session(info, profile, proc, keep, time.monotonic())
