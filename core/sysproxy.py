"""Point the operating system's proxy setting at the local Proxy Toolkit server (and undo it).

Backends
  * "gsettings"  GNOME / Cinnamon / Budgie / Unity (org.gnome.system.proxy). Most GNOME
                 apps and browsers that follow the system setting then use the server.
  * "windows"    WinINET settings in the registry (Edge, Chrome, IE, many apps).
  * ""           nothing available (XFCE, KDE, macOS, ...): use shell_env() for terminals or
                 set the proxy by hand / with the PAC export.

Safety: the previous values are written to a backup file BEFORE anything is changed, so they
can always be restored - also after a crash (restore_stale() at the next start). While the
system proxy points at the server and the server is stopped, programs would have no
connection at all, so callers restore it when the server stops.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from .models import fmt_host
from .store import config_dir

_GS_SCHEMA = "org.gnome.system.proxy"
_GS_KEYS = [(_GS_SCHEMA, "mode")] + [
    (f"{_GS_SCHEMA}.{p}", k) for p in ("http", "https", "socks") for k in ("host", "port")
]

_WIN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_WIN_VALUES = ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL")


class SysProxyError(Exception):
    pass


def shell_env(host: str, port: int) -> str:
    """Commands for a terminal: curl, git, pip, apt ... then use the local server."""
    if host in ("", "0.0.0.0", "::"):
        host = "127.0.0.1"
    hp = f"{fmt_host(host)}:{port}"
    return "\n".join([
        f'export ALL_PROXY="socks5h://{hp}"',
        f'export all_proxy="socks5h://{hp}"',
        f'export http_proxy="http://{hp}"',
        f'export https_proxy="http://{hp}"',
        f'export HTTP_PROXY="http://{hp}"',
        f'export HTTPS_PROXY="http://{hp}"',
        'export no_proxy="localhost,127.0.0.1,::1"',
        "",
        "# undo:",
        "unset ALL_PROXY all_proxy http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy",
    ])


def _gs(*args):
    try:
        return subprocess.run(["gsettings", *args], capture_output=True, text=True, timeout=5,
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None


class SystemProxy:
    def __init__(self, backup_path: Path | None = None, detect: bool = True):
        self.backup_path = Path(backup_path) if backup_path else config_dir() / "system-proxy-backup.json"
        # detect=False: the caller finds the backend later in a worker thread (running gsettings can block)
        self.backend = self._detect() if detect else ""

    # ------------------------------------------------------------ info
    @staticmethod
    def _detect() -> str:
        if sys.platform == "win32":
            return "windows"
        if shutil.which("gsettings"):
            r = _gs("get", _GS_SCHEMA, "mode")
            if r is not None and r.returncode == 0:
                return "gsettings"
        return ""

    @property
    def available(self) -> bool:
        return bool(self.backend)

    @property
    def label(self) -> str:
        return {"gsettings": "GNOME / Cinnamon system proxy", "windows": "Windows system proxy"
                }.get(self.backend, "")

    def active(self) -> bool:
        """True while a backup exists = we changed the setting and have not restored it yet."""
        return self.backup_path.exists()

    # ------------------------------------------------------------ backup file
    def _read_backup(self):
        try:
            return json.loads(self.backup_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def _write_backup(self, data: dict) -> None:
        try:
            self.backup_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.backup_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(self.backup_path)
        except OSError as e:
            raise SysProxyError(f"cannot write the backup file {self.backup_path}: {e}") from None

    def _drop_backup(self) -> None:
        try:
            self.backup_path.unlink()
        except OSError:
            pass

    # ------------------------------------------------------------ public
    def enable(self, host: str, port: int) -> str:
        if not self.backend:
            raise SysProxyError("no supported system-proxy backend on this computer")
        if host in ("", "0.0.0.0", "::"):
            host = "127.0.0.1"
        if self.backend == "gsettings":
            return self._enable_gs(host, port)
        return self._enable_win(host, port)

    def disable(self) -> str:
        """Restore the settings saved by enable(). Safe to call at any time."""
        data = self._read_backup()
        if data is None:
            if self.backup_path.exists():
                self._drop_backup()                 # unreadable leftover
            return "system proxy: nothing to restore"
        backend = data.get("backend")
        if backend == "gsettings":
            return self._restore_gs(data.get("values", {}))
        if backend == "windows":
            return self._restore_win(data.get("values", {}))
        self._drop_backup()
        return "system proxy: unknown backup ignored"

    def restore_stale(self) -> str:
        """At start-up: undo a change that a crashed session never restored ('' if none)."""
        if not self.active():
            return ""
        try:
            return "previous session did not restore the system proxy - " + self.disable()
        except SysProxyError as e:
            return f"could not restore the system proxy of the previous session: {e}"

    # ------------------------------------------------------------ gsettings
    def _gs_set(self, schema: str, key: str, value: str) -> None:
        r = _gs("set", schema, key, value)
        if r is None or r.returncode != 0:
            err = (r.stderr.strip() if r is not None else "gsettings could not be run")
            raise SysProxyError(f"gsettings set {schema} {key} failed: {err}")

    def _enable_gs(self, host: str, port: int) -> str:
        data = self._read_backup() if self.active() else None
        if data and data.get("backend") == "gsettings":
            old = data["values"]                    # keep the ORIGINAL values, not ours
        else:
            old = {}
            for schema, key in _GS_KEYS:
                r = _gs("get", schema, key)
                if r is None or r.returncode != 0:
                    raise SysProxyError(f"cannot read {schema} {key}: "
                                        f"{r.stderr.strip() if r is not None else 'gsettings failed'}")
                old[f"{schema} {key}"] = r.stdout.strip()
            self._write_backup({"backend": "gsettings", "values": old})
        try:
            for p in ("http", "https", "socks"):
                self._gs_set(f"{_GS_SCHEMA}.{p}", "host", f"'{host}'")
                self._gs_set(f"{_GS_SCHEMA}.{p}", "port", str(int(port)))
            self._gs_set(_GS_SCHEMA, "mode", "'manual'")
        except SysProxyError:
            try:
                self._restore_gs(old)
            except SysProxyError:
                pass
            raise
        return f"system proxy set to {fmt_host(host)}:{port} (GNOME)"

    def _restore_gs(self, old: dict) -> str:
        errors = []
        # mode last: no moment where "manual" points at half-restored hosts
        items = [(k, v) for k, v in old.items() if not k.endswith(" mode")]
        items += [(k, v) for k, v in old.items() if k.endswith(" mode")]
        for name, value in items:
            schema, key = name.rsplit(" ", 1)
            r = _gs("set", schema, key, value)
            if r is None or r.returncode != 0:
                errors.append(f"{name}: {r.stderr.strip() if r is not None else 'gsettings failed'}")
        if errors:
            raise SysProxyError("could not restore: " + "; ".join(errors)
                                + f" (backup kept in {self.backup_path})")
        self._drop_backup()
        return "system proxy restored (GNOME)"

    # ------------------------------------------------------------ windows
    @staticmethod
    def _win_notify() -> None:
        try:
            import ctypes
            wininet = ctypes.windll.wininet            # type: ignore[attr-defined]
            wininet.InternetSetOptionW(None, 39, None, 0)   # INTERNET_OPTION_SETTINGS_CHANGED
            wininet.InternetSetOptionW(None, 37, None, 0)   # INTERNET_OPTION_REFRESH
        except Exception:
            pass

    def _enable_win(self, host: str, port: int) -> str:
        import winreg
        hp = f"{fmt_host(host)}:{int(port)}"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WIN_KEY, 0,
                                winreg.KEY_READ | winreg.KEY_WRITE) as k:
                data = self._read_backup() if self.active() else None
                if data and data.get("backend") == "windows":
                    old = data["values"]
                else:
                    old = {}
                    for name in _WIN_VALUES:
                        try:
                            val, typ = winreg.QueryValueEx(k, name)
                            old[name] = [val, typ]
                        except FileNotFoundError:
                            old[name] = None
                    self._write_backup({"backend": "windows", "values": old})
                winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, f"http={hp};https={hp};socks={hp}")
                winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, "localhost;127.*;<local>")
                try:
                    winreg.DeleteValue(k, "AutoConfigURL")     # a PAC script would win over our setting
                except FileNotFoundError:
                    pass
                winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        except OSError as e:
            raise SysProxyError(f"cannot change the Windows proxy settings: {e}") from None
        self._win_notify()
        return f"system proxy set to {hp} (Windows)"

    def _restore_win(self, old: dict) -> str:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WIN_KEY, 0,
                                winreg.KEY_READ | winreg.KEY_WRITE) as k:
                for name in [n for n in _WIN_VALUES if n != "ProxyEnable"] + ["ProxyEnable"]:
                    saved = old.get(name)
                    if saved is None:
                        try:
                            winreg.DeleteValue(k, name)
                        except FileNotFoundError:
                            pass
                    else:
                        winreg.SetValueEx(k, name, 0, saved[1], saved[0])
        except OSError as e:
            raise SysProxyError(f"cannot restore the Windows proxy settings: {e} "
                                f"(backup kept in {self.backup_path})") from None
        self._drop_backup()
        self._win_notify()
        return "system proxy restored (Windows)"
