"""Proxy-list sources: URLs that are downloaded (once or on a schedule) and fed to the checker.

A source is just a URL that returns text with one proxy per line (GitHub raw files, plain
text lists, ...). Sources are kept in  ~/.config/proxy-toolkit/sources.json.

Privacy note: lists are downloaded directly from this machine (not through the local proxy
server), so the list's host sees your real IP - like the Checker's own test requests.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .store import config_dir

MAX_BYTES = 25 * 1024 * 1024        # refuse anything larger (a proxy list is never that big)
MIN_INTERVAL_MIN = 5                # auto-refresh is never more frequent than this
FETCH_TIMEOUT = 30.0
_UA = "Mozilla/5.0 (X11; Linux x86_64) ProxyToolkit"


class FetchError(Exception):
    pass


def normalize_url(url: str) -> str:
    """Validate a list URL and turn GitHub "blob" page links into raw-file links."""
    url = (url or "").strip()
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("enter a full http:// or https:// address")
    m = re.fullmatch(r"https?://(?:www\.)?github\.com/([^/]+)/([^/]+)/blob/(.+)", url)
    if m:                                           # the HTML page of a file -> the file itself
        url = f"https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}/{m.group(3)}"
    return url


@dataclass
class Source:
    url: str
    interval_min: int = 0          # auto-refresh every N minutes, 0 = only when asked
    enabled: bool = True           # unchecked sources are skipped by auto-refresh and "Fetch all"
    last_fetch: float = 0.0        # unix time of the last attempt
    last_status: str = ""

    def due(self, now: float) -> bool:
        return (self.enabled and self.interval_min > 0
                and now - self.last_fetch >= self.interval_min * 60.0)


class SourceStore:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else config_dir() / "sources.json"
        self.sources: list[Source] = []
        self.load()

    def load(self) -> None:
        self.sources = []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            for d in data.get("sources", []):
                self.sources.append(Source(
                    url=str(d["url"]), interval_min=int(d.get("interval_min", 0)),
                    enabled=bool(d.get("enabled", True)), last_fetch=float(d.get("last_fetch", 0.0)),
                    last_status=str(d.get("last_status", ""))))
        except (OSError, ValueError, KeyError, TypeError):
            pass

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"sources": [asdict(s) for s in self.sources]}, indent=2),
                           encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            pass

    def find(self, url: str) -> Source | None:
        return next((s for s in self.sources if s.url == url), None)

    def add(self, url: str, interval_min: int = 0) -> Source:
        """Add a source (raises ValueError for a bad / duplicate URL)."""
        url = normalize_url(url)
        if self.find(url):
            raise ValueError("this URL is already in the list")
        if interval_min:
            interval_min = max(MIN_INTERVAL_MIN, int(interval_min))
        src = Source(url=url, interval_min=int(interval_min))
        self.sources.append(src)
        self.save()
        return src

    def remove(self, url: str) -> None:
        self.sources = [s for s in self.sources if s.url != url]
        self.save()

    def due(self, now: float | None = None) -> list[Source]:
        now = time.time() if now is None else now
        return [s for s in self.sources if s.due(now)]


async def fetch_lines(url: str, timeout: float = FETCH_TIMEOUT) -> list[str]:
    """Download a proxy list and return its lines."""
    import aiohttp

    url = normalize_url(url)
    tmo = aiohttp.ClientTimeout(total=timeout)
    try:
        async with aiohttp.ClientSession(timeout=tmo, trust_env=False,
                                         headers={"User-Agent": _UA}) as session:
            async with session.get(url, allow_redirects=True, max_redirects=5) as resp:
                if resp.status != 200:
                    raise FetchError(f"HTTP {resp.status}")
                data = bytearray()
                async for chunk in resp.content.iter_chunked(65536):
                    data += chunk
                    if len(data) > MAX_BYTES:
                        raise FetchError(f"the list is larger than {MAX_BYTES // (1024 * 1024)} MB")
    except FetchError:
        raise
    except aiohttp.ClientError as e:
        raise FetchError(f"{type(e).__name__}: {e}") from None
    except asyncio.TimeoutError:
        raise FetchError(f"no answer within {timeout:.0f} s") from None
    return bytes(data).decode("utf-8", "replace").splitlines()
