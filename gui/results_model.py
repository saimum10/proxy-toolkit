"""Table model for check results + a sort/filter proxy."""
from __future__ import annotations

import ipaddress

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PyQt6.QtGui import QBrush, QColor

SORT_ROLE = Qt.ItemDataRole.UserRole

# (title, default width)
COLUMNS = [
    ("", 28), ("Status", 62), ("Proxy", 170), ("Type", 62), ("Exit IP", 125),
    ("Country", 130), ("City", 110), ("Anonymity", 95), ("Latency", 80),
    ("Stability", 72), ("Score", 56), ("Remote DNS", 86), ("Targets", 210),
    ("Network", 200), ("Note", 230),
]
NUMERIC = {8, 9, 10}
ANON_RANK = {"": -2, "unknown": -1, "transparent": 0, "anonymous": 1, "elite": 2}

GREEN = QColor("#2e9e4f")
RED = QColor("#c0392b")
AMBER = QColor("#c27c0e")
GREY = QColor("#808080")


def _ip_key(s: str) -> str:
    try:
        return f"{int(ipaddress.ip_address(s)):040d}"
    except ValueError:
        return (s or "").lower()


class ResultsModel(QAbstractTableModel):
    def __init__(self, store, parent=None):
        super().__init__(parent)
        self.store = store
        self.results: list = []

    # -- structure
    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.results)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return COLUMNS[section][0]
        return None

    # -- mutation
    def add_results(self, batch) -> None:
        if not batch:
            return
        first = len(self.results)
        self.beginInsertRows(QModelIndex(), first, first + len(batch) - 1)
        self.results.extend(batch)
        self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self.results = []
        self.endResetModel()

    def refresh(self) -> None:
        if self.results:
            self.dataChanged.emit(self.index(0, 0),
                                  self.index(len(self.results) - 1, len(COLUMNS) - 1))

    # -- data
    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        r = self.results[index.row()]
        c = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            return self._text(r, c)
        if role == SORT_ROLE:
            return self._sort_key(r, c)
        if role == Qt.ItemDataRole.ForegroundRole:
            if c == 1:
                return QBrush(GREEN if r.live else RED)
            if c == 7:
                return {"elite": QBrush(GREEN), "anonymous": QBrush(AMBER),
                        "transparent": QBrush(RED)}.get(r.anonymity)
            if c == 14:
                return QBrush(GREY)
            return None
        if role == Qt.ItemDataRole.ToolTipRole:
            return self._tip(r, c)
        if role == Qt.ItemDataRole.TextAlignmentRole and c in NUMERIC:
            return (Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter).value
        return None

    def _text(self, r, c):
        if c == 0:
            return "⛔" if self.store.is_black(r.key) else ("★" if self.store.is_fav(r.key) else "")
        if c == 1:
            return "LIVE" if r.live else "DEAD"
        if c == 2:
            return r.address
        if c == 3:
            return r.proto
        if c == 4:
            return r.exit_ip
        if c == 5:
            if r.country and r.country_code:
                return f"{r.country} ({r.country_code})"
            return r.country or r.country_code
        if c == 6:
            return r.city
        if c == 7:
            return r.anonymity.capitalize()
        if c == 8:
            return f"{r.latency_ms:.0f} ms" if r.latency_ms is not None else ""
        if c == 9:
            return f"{r.passed}/{r.rounds}" if r.rounds else ""
        if c == 10:
            return str(r.score) if r.live else ""
        if c == 11:
            return ("yes" if r.remote_dns else "no") if r.live else ""
        if c == 12:
            return "  ".join(f"{k} {'✓' if v else '✗'}" for k, v in r.targets.items())
        if c == 13:
            return " · ".join(x for x in (r.net_type, r.isp) if x)
        if c == 14:
            return r.error
        return ""

    def _sort_key(self, r, c):
        if c == 0:
            return 2 if self.store.is_black(r.key) else (1 if self.store.is_fav(r.key) else 0)
        if c == 1:
            return 1 if r.live else 0
        if c == 2:
            return f"{_ip_key(r.host)}:{r.port:05d}"
        if c == 4:
            return _ip_key(r.exit_ip)
        if c == 7:
            return ANON_RANK.get(r.anonymity, -2)
        if c == 8:
            return float(r.latency_ms) if r.latency_ms is not None else 1e12
        if c == 9:
            return float(r.stability) if r.rounds else -1.0
        if c == 10:
            return int(r.score) if r.live else -1
        if c == 11:
            return (1 if r.remote_dns else 0) if r.live else -1
        return self._text(r, c).lower()

    def _tip(self, r, c):
        if c == 0:
            if self.store.is_black(r.key):
                return "Blacklisted - skipped in future checks"
            return "Favourite" if self.store.is_fav(r.key) else None
        if c == 2:
            return r.url
        if c == 7:
            return r.anonymity_note or None
        if c == 11 and r.live:
            if r.remote_dns:
                return ("Hostnames are resolved by the proxy (socks5h / socks4a / HTTP CONNECT): "
                        "no local DNS leak.")
            return ("This proxy only works with local DNS resolution: your machine would "
                    "send DNS lookups itself (DNS leak).")
        if c == 14:
            return r.error or None
        return None


class ResultsFilter(QSortFilterProxyModel):
    def __init__(self, model: ResultsModel):
        super().__init__()
        self._m = model
        self.mode = "all"
        self.tokens: list = []
        self.setSourceModel(model)
        self.setSortRole(SORT_ROLE)

    def set_mode(self, mode: str) -> None:
        self.mode = mode
        self.invalidateFilter()

    def set_text(self, text: str) -> None:
        self.tokens = text.lower().split()
        self.invalidateFilter()

    def filterAcceptsRow(self, row, parent):
        r = self._m.results[row]
        mode = self.mode
        if mode == "live" and not r.live:
            return False
        if mode == "dead" and r.live:
            return False
        if mode == "fav" and not self._m.store.is_fav(r.key):
            return False
        if mode == "black" and not self._m.store.is_black(r.key):
            return False
        if self.tokens:
            blob = (f"{r.address} {r.proto} {r.exit_ip} {r.country} {r.country_code} {r.city} "
                    f"{r.anonymity} {r.isp} {r.net_type} {r.error}").lower()
            return all(t in blob for t in self.tokens)
        return True
