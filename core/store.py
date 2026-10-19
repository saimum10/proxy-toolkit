"""Persistent favourites / blacklist (host:port keys) in ~/.config/proxy-toolkit/lists.json"""
from __future__ import annotations

import json
import os
from pathlib import Path


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "proxy-toolkit"


class ListStore:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else config_dir() / "lists.json"
        self.favourites: set = set()
        self.blacklist: set = set()
        self.load()

    def load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.favourites = set(data.get("favourites", []))
            self.blacklist = set(data.get("blacklist", []))
        except (OSError, ValueError):
            pass

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"favourites": sorted(self.favourites),
                                       "blacklist": sorted(self.blacklist)}, indent=2),
                           encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            pass

    def is_fav(self, key: str) -> bool:
        return key in self.favourites

    def is_black(self, key: str) -> bool:
        return key in self.blacklist

    def set_fav(self, keys, on: bool) -> None:
        (self.favourites.update if on else self.favourites.difference_update)(keys)
        self.save()

    def set_black(self, keys, on: bool) -> None:
        (self.blacklist.update if on else self.blacklist.difference_update)(keys)
        self.save()

    def clear_favourites(self) -> None:
        self.favourites.clear()
        self.save()

    def clear_blacklist(self) -> None:
        self.blacklist.clear()
        self.save()
