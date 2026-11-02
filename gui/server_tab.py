"""'Proxy Server' tab: start the local proxy, choose rotation / chain mode, manage the pool."""
from __future__ import annotations

import asyncio
import re
import time

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QBrush, QGuiApplication
from PyQt6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QFormLayout, QFrame, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMenu, QMessageBox, QPlainTextEdit,
    QPushButton, QScrollArea, QSpinBox, QSplitter, QStyle, QTableView, QToolButton, QVBoxLayout, QWidget,
)

from core import browser, geo
from core.server import FAILOVER_GROUPS, MODES, Pool, ProxyServer, ServerConfig
from core.checker import Checker
from core.parser import parse_lines, read_lines
from core.sources import SourceStore, fetch_lines
from core.sysproxy import SystemProxy, SysProxyError, shell_env

from . import export_dialogs
from .results_model import AMBER, GREEN, RED, SORT_ROLE, _ip_key
from .sources_panel import SourcesPanel

MODE_HELP = {
    "round_robin": "Every new connection uses the next live proxy in turn.",
    "random": "Every new connection uses a random live proxy.",
    "weighted": "Random, but proxies with a high score and low latency are picked more often; "
                "favourites (★) count 3x.",
    "fastest": "Always uses the live proxy with the lowest latency; if it fails, the next fastest.",
    "fav_first": "Uses your ★ favourite proxies (in turn). If none of them is usable it can fall "
                 "back to the rest of the pool.",
    "failover": "Traffic uses the Primary group. Only when no Primary proxy is usable does it move to "
                "Backup 1, then Backup 2 - and returns to Primary as soon as one recovers. "
                "Set a proxy's group with right-click ▸ Failover group.",
    "sticky": "A website (domain) keeps the same exit IP; different domains rotate. "
              "Good for logins and sessions.",
    "manual": "One exit IP is held until you press Change IP (or until Auto-rotate fires).",
    "chain_strict": "Traffic goes through EVERY proxy of the chain list, in order (A → B → C). "
                    "If any hop is down the connection is blocked.",
    "chain_dynamic": "Like strict, but hops that are down are skipped automatically.",
    "chain_random": "Builds a new random chain of N live proxies for every connection.",
}

POOL_COLS = [("State", 70), ("Proxy", 170), ("Type", 60), ("Country", 120), ("Latency", 80),
             ("Score", 55), ("Uses", 55), ("Fails", 50), ("Chain", 50), ("Group", 90)]
NUMERIC = {4, 5, 6, 7, 8}


def _dropped_local_paths(mime) -> list[str]:
    return [url.toLocalFile() for url in mime.urls() if url.isLocalFile()]


class ProxyListEdit(QPlainTextEdit):
    """Paste area that also accepts proxy-list files dropped from the file manager."""
    filesDropped = pyqtSignal(list)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            paths = _dropped_local_paths(event.mimeData())
            if paths:
                self.filesDropped.emit(paths)
                event.acceptProposedAction()
                return
        super().dropEvent(event)


def _fmt_bytes(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if f < 1024 or unit == "GB":
            return f"{f:.0f} {unit}" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024
    return f"{n} B"


class PoolModel(QAbstractTableModel):
    def __init__(self, store=None):
        super().__init__()
        self.store = store                 # favourites (★ in front of the address)
        self.members: list = []
        self.chain_keys: list = []
        self.current_key = None
        self._keys: list = []

    def set_members(self, members: list, chain_keys: list, current_key=None) -> None:
        self.chain_keys = list(chain_keys)
        self.current_key = current_key
        keys = [m.key for m in members]
        if keys != self._keys:
            self.beginResetModel()
            self.members, self._keys = members, keys
            self.endResetModel()
        else:
            self.members = members
            if members:
                self.dataChanged.emit(self.index(0, 0),
                                      self.index(len(members) - 1, len(POOL_COLS) - 1))

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.members)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(POOL_COLS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return POOL_COLS[section][0]
        return None

    @staticmethod
    def _state(m) -> str:
        if not m.alive:
            return "down"
        return "cooling" if m.cooldown > time.monotonic() else "alive"

    def _chain_pos(self, m):
        try:
            return self.chain_keys.index(m.key) + 1
        except ValueError:
            return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        m = self.members[index.row()]
        r = m.res
        c = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if c == 0:
                st = self._state(m)
                return "▶ current" if (st == "alive" and m.key == self.current_key) else st
            if c == 1:
                return ("★ " if self.store and self.store.is_fav(m.key) else "") + r.address
            if c == 2:
                return r.kind or r.proto
            if c == 3:
                return r.country_code if not r.country else f"{r.country} ({r.country_code})"
            if c == 4:
                return f"{m.latency_ms:.0f} ms" if m.latency_ms is not None else ""
            if c == 5:
                return str(r.score)
            if c == 6:
                return str(m.uses)
            if c == 7:
                return str(m.fails)
            if c == 8:
                pos = self._chain_pos(m)
                return str(pos) if pos else ""
            if c == 9:
                return f"{m.group} · {FAILOVER_GROUPS.get(m.group, '?')}"
        if role == SORT_ROLE:
            if c == 0:
                return {"alive": 2, "cooling": 1, "down": 0}[self._state(m)]
            if c == 1:
                return f"{_ip_key(r.host)}:{r.port:05d}"
            if c == 4:
                return float(m.latency_ms) if m.latency_ms is not None else 1e12
            if c == 5:
                return int(r.score)
            if c == 6:
                return int(m.uses)
            if c == 7:
                return int(m.fails)
            if c == 8:
                return self._chain_pos(m) or 9999
            if c == 9:
                return int(m.group)
            return str(self.data(index)).lower()
        if role == Qt.ItemDataRole.ForegroundRole and c == 0:
            return QBrush({"alive": GREEN, "cooling": AMBER, "down": RED}[self._state(m)])
        if role == Qt.ItemDataRole.ToolTipRole and c == 1:
            return f"{r.url}\nRemote DNS: {'yes' if r.remote_dns else 'no'}"
        if role == Qt.ItemDataRole.TextAlignmentRole and c in NUMERIC:
            return (Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter).value
        return None


class ServerTab(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        self.pool = Pool()
        self.server: ProxyServer | None = None
        self._seq = 0
        self._import_task = None
        self._import_checker: Checker | None = None
        self._import_my_ip = None
        self._ip_future = None
        self._ip_started = 0.0
        self._browsers: list = []                     # running safe-browser sessions
        self._stopping = False                        # server stop requested, not finished yet
        self._stop_started = 0.0
        self._seen_changes = 0                        # server.change_count already shown in the label
        self._import_stopped = False
        self._last_import = None                      # (checked, live, added) of the newest import run
        self._last_src_check = time.monotonic() - 25  # first auto-refresh look ~5 s after start
        self._sys_confirmed = False
        self._sys_set = False                         # WE changed the system proxy in this session
        self.source_store = SourceStore()
        self.sysproxy = SystemProxy(detect=False)     # the backend is detected in the background

        self.pool_model = PoolModel(self.main.store)
        self.pool_proxy = QSortFilterProxyModel()
        self.pool_proxy.setSourceModel(self.pool_model)
        self.pool_proxy.setSortRole(SORT_ROLE)

        self._build()
        self._mode_changed()
        QTimer.singleShot(0, lambda: self.main.loop.create_task(self._detect_sysproxy()))
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self._tick)
        self.timer.start()
        self._tick()

    # ------------------------------------------------------------ UI
    def _build(self):
        root = QHBoxLayout(self)
        left = QWidget()
        llay = QVBoxLayout(left)
        llay.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()                      # the settings scroll on small screens ...
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)   # never silently cut
        inner = self._build_left()
        scroll.setWidget(inner)
        llay.addWidget(scroll, 1)
        # as wide as the content needs at the current font / display scaling (min 414 px)
        extent = scroll.style().pixelMetric(QStyle.PixelMetric.PM_ScrollBarExtent)
        left.setFixedWidth(max(414, inner.minimumSizeHint().width() + extent + 12))

        row = QHBoxLayout()                         # ... Start / Stop never do
        self.btn_start = QPushButton("▶  Start server")
        self.btn_start.setMinimumHeight(38)
        self.btn_start.clicked.connect(self.start_server)
        self.btn_stop = QPushButton("■  Stop")
        self.btn_stop.setMinimumHeight(38)
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_server)
        row.addWidget(self.btn_start, 2)
        row.addWidget(self.btn_stop, 1)
        llay.addLayout(row)

        root.addWidget(left)
        root.addWidget(self._build_right(), 1)

    def _build_left(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 6, 0)

        # proxy list import for rotation pool
        gb = QGroupBox("Add proxies  ·  paste / browse / drop")
        import_lay = QVBoxLayout(gb)
        self.cb_auto = QCheckBox("Add live proxies from the Checker tab automatically")
        self.cb_auto.setChecked(True)
        self.cb_auto.setToolTip("ON: after every check in the Checker tab, its live proxies go straight "
                                "into the rotation pool.\nOFF: nothing is added until you press "
                                "“Add live proxies from Checker” above the pool table.")
        import_lay.addWidget(self.cb_auto)
        self.ed_proxy_list = ProxyListEdit()
        self.ed_proxy_list.setPlaceholderText(
            "Paste proxies here, one per line, or drop a .txt file:\n"
            "1.2.3.4:8080\nsocks5://1.2.3.4:1080\nuser:pass@1.2.3.4:3128\n\n"
            "Imported proxies are checked before entering the rotation pool.")
        self.ed_proxy_list.setMinimumHeight(90)
        self.ed_proxy_list.setMaximumHeight(135)
        self.ed_proxy_list.filesDropped.connect(self._load_proxy_files)
        import_lay.addWidget(self.ed_proxy_list)
        import_row = QHBoxLayout()
        self.btn_proxy_browse = QPushButton("Browse…")
        self.btn_proxy_browse.clicked.connect(self._browse_proxy_files)
        self.btn_proxy_clear = QPushButton("Clear list")
        self.btn_proxy_clear.clicked.connect(self.ed_proxy_list.clear)
        self.btn_proxy_import = QPushButton("Check && add")   # && = a literal "&" (a single & would be a mnemonic)
        self.btn_proxy_import.setToolTip("Check the proxies, then add the live ones to the rotation pool")
        self.btn_proxy_import.clicked.connect(self._check_and_add_proxy_list)
        import_row.addWidget(self.btn_proxy_browse)
        import_row.addWidget(self.btn_proxy_clear)
        import_row.addWidget(self.btn_proxy_import, 1)
        self.btn_proxy_stop = QPushButton("Stop")
        self.btn_proxy_stop.setEnabled(False)
        self.btn_proxy_stop.clicked.connect(self._stop_import)
        import_row.addWidget(self.btn_proxy_stop)
        import_lay.addLayout(import_row)
        self.lbl_proxy_import = QLabel("Only verified live proxies are added to rotation.")
        self.lbl_proxy_import.setWordWrap(True)
        import_lay.addWidget(self.lbl_proxy_import)
        lay.addWidget(gb)

        self.sources_panel = SourcesPanel(self.source_store)
        self.sources_panel.fetchRequested.connect(lambda srcs: self._start_sources(srcs, manual=True))
        lay.addWidget(self.sources_panel)

        # listen
        gb = QGroupBox("Listen address")
        f = QFormLayout(gb)
        self.ed_host = QLineEdit("127.0.0.1")
        self.ed_host.setToolTip("127.0.0.1 = only this computer. 0.0.0.0 would open the proxy "
                                "to your whole network - not recommended.")
        self.sp_port = QSpinBox()
        self.sp_port.setRange(1, 65535)
        self.sp_port.setValue(1080)
        f.addRow("Host", self.ed_host)
        f.addRow("Port", self.sp_port)
        hint = QLabel("Point your browser / curl / burp to this address.\n"
                      "Works as SOCKS5, SOCKS4/4a and HTTP(S) proxy on the same port.\n"
                      "Tip: use socks5h:// in curl and tick “Proxy DNS” in Firefox.")
        hint.setWordWrap(True)
        f.addRow(hint)
        lay.addWidget(gb)

        # mode
        gb = QGroupBox("Mode")
        f = QFormLayout(gb)
        self.cmb_mode = QComboBox()
        for key, label in MODES:
            self.cmb_mode.addItem(label, key)
        self.cmb_mode.currentIndexChanged.connect(self._mode_changed)
        self.lbl_help = QLabel()
        self.lbl_help.setWordWrap(True)
        self.sp_len = QSpinBox()
        self.sp_len.setRange(1, 10)
        self.sp_len.setValue(2)
        self.sp_len.valueChanged.connect(self._apply)
        self.sp_ttl = QSpinBox()
        self.sp_ttl.setRange(0, 1440)
        self.sp_ttl.setSuffix(" min")
        self.sp_ttl.setToolTip("0 = keep the same exit until that proxy dies")
        self.sp_ttl.valueChanged.connect(self._apply)
        self.cb_favfb = QCheckBox("Use other proxies when no favourite is usable")
        self.cb_favfb.setChecked(True)
        self.cb_favfb.setToolTip("Favourites-first mode: OFF = block traffic instead of using non-favourites.")
        self.cb_favfb.toggled.connect(self._apply)
        self.sp_rot_min = QSpinBox()
        self.sp_rot_min.setRange(0, 1440)
        self.sp_rot_min.setSpecialValueText("off")
        self.sp_rot_min.setSuffix(" min")
        self.sp_rot_min.setToolTip("Manual mode: switch to a new verified proxy every N minutes.\n"
                                   "Sticky mode: forget all site pins every N minutes (new IPs).")
        self.sp_rot_min.valueChanged.connect(self._apply)
        self.sp_rot_req = QSpinBox()
        self.sp_rot_req.setRange(0, 100000)
        self.sp_rot_req.setSpecialValueText("off")
        self.sp_rot_req.setSuffix(" connections")
        self.sp_rot_req.setToolTip("Manual / Sticky: new IP after N successful connections (requests).\n"
                                   "A web page usually opens several connections.\n"
                                   "Whichever limit (minutes / connections) is reached first wins.")
        self.sp_rot_req.valueChanged.connect(self._apply)
        self.cb_rotdrop = QCheckBox("Auto-rotate also closes open connections")
        self.cb_rotdrop.setToolTip("OFF (recommended): after an automatic change new connections use the new IP\n"
                                   "while pages / downloads that are already open finish undisturbed.\n"
                                   "ON: open connections are cut at every automatic change.")
        self.cb_rotdrop.toggled.connect(self._apply)
        self.cb_drop = QCheckBox("Close open connections when the IP changes")
        self.cb_drop.setChecked(True)
        self.cb_drop.setToolTip("Manual mode: browsers keep old connections open, so the website would still see\n"
                                "the previous IP. Closing them makes the browser reconnect through the new proxy.")
        self.cb_drop.toggled.connect(self._apply)
        f.addRow(self.cmb_mode)
        f.addRow(self.lbl_help)
        f.addRow("Random chain length", self.sp_len)
        f.addRow("Sticky lifetime", self.sp_ttl)
        f.addRow(self.cb_favfb)
        f.addRow("Auto-rotate every", self.sp_rot_min)
        f.addRow("… or every", self.sp_rot_req)
        f.addRow(self.cb_rotdrop)
        f.addRow(self.cb_drop)
        lay.addWidget(gb)

        # filters
        gb = QGroupBox("Pool filters")
        f = QFormLayout(gb)
        self.ed_countries = QLineEdit()
        self.ed_countries.setPlaceholderText("e.g. US, DE   (empty = any country)")
        self.ed_countries.setToolTip("Needs the Country lookup enabled in the Checker settings.")
        self.ed_countries.textChanged.connect(self._apply)
        self.sp_score = QSpinBox()
        self.sp_score.setRange(0, 100)
        self.sp_score.valueChanged.connect(self._apply)
        self.cb_rdns = QCheckBox("Require remote DNS (prevents DNS leaks)")
        self.cb_rdns.setChecked(True)
        self.cb_rdns.setToolTip("Hostnames are only sent through proxies that resolve them remotely.")
        self.cb_rdns.toggled.connect(self._apply)
        self.cb_log = QCheckBox("Log every connection")
        self.cb_log.setChecked(True)
        self.cb_log.toggled.connect(self._apply)
        f.addRow("Countries", self.ed_countries)
        f.addRow("Min score", self.sp_score)
        f.addRow(self.cb_rdns)
        f.addRow(self.cb_log)
        lay.addWidget(gb)

        # monitor
        gb = QGroupBox("Health monitor")
        f = QFormLayout(gb)
        self.cb_monitor = QCheckBox("Re-test pool in the background")
        self.cb_monitor.setChecked(True)
        self.cb_monitor.toggled.connect(self._apply)
        self.sp_interval = QSpinBox()
        self.sp_interval.setRange(5, 3600)
        self.sp_interval.setValue(60)
        self.sp_interval.setSuffix(" s")
        self.sp_interval.setToolTip("How often a proxy that is in use is re-tested.\n"
                                    "Idle proxies are re-tested 3x less often, dead ones with\n"
                                    "growing pauses (up to 16x) - so big pools stay cheap.")
        self.sp_interval.valueChanged.connect(self._apply)
        self.sp_fails = QSpinBox()
        self.sp_fails.setRange(1, 10)
        self.sp_fails.setValue(2)
        self.sp_fails.setToolTip("Consecutive failed re-tests before a proxy leaves the active pool.")
        self.sp_fails.valueChanged.connect(self._apply)
        f.addRow(self.cb_monitor)
        f.addRow("Interval", self.sp_interval)
        f.addRow("Remove after failures", self.sp_fails)
        lay.addWidget(gb)

        lay.addStretch(1)
        return w

    def _build_right(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)

        self.lbl_banner = QLabel()
        self.lbl_banner.setWordWrap(True)
        self.lbl_banner.setMinimumHeight(44)
        lay.addWidget(self.lbl_banner)
        self.lbl_stats = QLabel()
        lay.addWidget(self.lbl_stats)

        ip_row = QHBoxLayout()
        self.btn_change = QPushButton("🔄  Change IP")
        self.btn_change.setMinimumHeight(38)
        self.btn_change.setStyleSheet("QPushButton { font-weight: 600; padding: 4px 20px; }")
        self.btn_change.setToolTip("Switch to the next live proxy now.\n"
                                   "Manual mode keeps that IP until you press the button again.")
        self.btn_change.setEnabled(False)
        self.btn_change.clicked.connect(self.change_ip)
        self.lbl_exit = QLabel("Start the server, then press “Change IP” to move to the next live proxy.")
        self.lbl_exit.setWordWrap(True)
        ip_row.addWidget(self.btn_change)
        ip_row.addWidget(self.lbl_exit, 1)
        lay.addLayout(ip_row)

        br_row = QHBoxLayout()
        self.btn_browser = QPushButton("🛡  Launch safe browser")
        self.btn_browser.setMinimumHeight(34)
        self.btn_browser.setToolTip(
            "Opens a separate browser window with a temporary profile that can ONLY use this\n"
            "proxy server: WebRTC, local DNS, QUIC (HTTP/3), IPv6 DNS and direct fallback are off.\n"
            "Only that window is protected - your normal browser and other apps are not.")
        self.btn_browser.setEnabled(False)
        self.btn_browser.clicked.connect(self.launch_browser)
        self.cmb_browser = QComboBox()
        self._browser_infos = browser.find_browsers()
        for info in self._browser_infos:
            self.cmb_browser.addItem(info.title, info)
        if not self._browser_infos:
            self.cmb_browser.addItem("No supported browser found")
            self.cmb_browser.setEnabled(False)
        self.cb_leaktest = QCheckBox("Open WebRTC test page")
        self.cb_leaktest.setChecked(True)
        self.cb_keep = QCheckBox("Keep profile")
        self.cb_keep.setToolTip("Keep cookies / history after closing the browser (default: deleted).")
        br_row.addWidget(self.btn_browser)
        br_row.addWidget(self.cmb_browser)
        br_row.addWidget(self.cb_leaktest)
        br_row.addWidget(self.cb_keep)
        br_row.addStretch(1)
        lay.addLayout(br_row)

        sys_row = QHBoxLayout()
        self.cb_sysproxy = QCheckBox("Use as system proxy")
        self.cb_sysproxy.setToolTip("Looking for a system-proxy backend …")
        self.cb_sysproxy.setEnabled(False)
        self.cb_sysproxy.toggled.connect(self._toggle_sysproxy)
        self.btn_env = QPushButton("Copy terminal commands")
        self.btn_env.setToolTip("Copies  export ALL_PROXY=…  lines so curl, git, pip, apt … use this server.")
        self.btn_env.clicked.connect(self._copy_env)
        sys_row.addWidget(self.cb_sysproxy)
        sys_row.addWidget(self.btn_env)
        sys_row.addStretch(1)
        lay.addLayout(sys_row)

        split = QSplitter(Qt.Orientation.Horizontal)

        # pool
        pw = QWidget()
        pl = QVBoxLayout(pw)
        pl.setContentsMargins(0, 0, 0, 0)
        bar = QHBoxLayout()
        b_add = QPushButton("Add live proxies from Checker")
        b_add.clicked.connect(self.add_from_checker)
        b_rm = QPushButton("Remove selected")
        b_rm.clicked.connect(self._remove_selected)
        b_clr = QPushButton("Clear pool")
        b_clr.clicked.connect(self._clear_pool)
        for b in (b_add, b_rm, b_clr):
            bar.addWidget(b)
        exp = QToolButton()
        exp.setText("Export ▾")
        exp.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        em = QMenu(exp)
        em.addAction("proxychains.conf  (alive pool proxies)…", self._export_pool_proxychains)
        em.addAction("PAC file  (best alive pool proxies)…", self._export_pool_pac)
        em.addSeparator()
        em.addAction("proxychains.conf for this local server…", self._export_local_proxychains)
        em.addAction("PAC file for this local server…", self._export_local_pac)
        exp.setMenu(em)
        bar.addWidget(exp)
        bar.addStretch(1)
        pl.addLayout(bar)
        self.table = QTableView()
        self.table.setModel(self.pool_proxy)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(24)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        self.table.horizontalHeader().setStretchLastSection(True)
        for i, (_, width) in enumerate(POOL_COLS):
            self.table.setColumnWidth(i, width)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._pool_context_menu)
        pl.addWidget(self.table, 1)
        self.lbl_pool = QLabel()
        pl.addWidget(self.lbl_pool)
        split.addWidget(pw)

        # chain builder
        gb = QGroupBox("Chain builder  (for the Chain modes)")
        cl = QVBoxLayout(gb)
        info = QLabel("you  →  hop 1  →  hop 2  →  …  →  website\n"
                      "Drag items to reorder, or use the arrows.")
        info.setWordWrap(True)
        cl.addWidget(info)
        self.chain_list = QListWidget()
        self.chain_list.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.chain_list.setDefaultDropAction(Qt.DropAction.MoveAction)
        self.chain_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.chain_list.model().rowsMoved.connect(self._chain_changed)
        cl.addWidget(self.chain_list, 1)
        r1 = QHBoxLayout()
        b = QPushButton("◀ Add selected from pool")
        b.clicked.connect(self._add_selected_to_chain)
        r1.addWidget(b)
        cl.addLayout(r1)
        r2 = QHBoxLayout()
        for text, fn in (("↑", lambda: self._move(-1)), ("↓", lambda: self._move(1)),
                         ("Remove", self._chain_remove), ("Clear", self._chain_clear)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            r2.addWidget(b)
        cl.addLayout(r2)
        split.addWidget(gb)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        lay.addWidget(split, 1)
        return w

    # ------------------------------------------------------------ config
    def _mode_key(self) -> str:
        return self.cmb_mode.currentData()

    def _mode_changed(self, *_):
        key = self._mode_key()
        self.lbl_help.setText(MODE_HELP.get(key, ""))
        self.sp_len.setEnabled(key == "chain_random")
        self.sp_ttl.setEnabled(key == "sticky")
        self.cb_favfb.setEnabled(key == "fav_first")
        rot = key in ("manual", "sticky")
        self.sp_rot_min.setEnabled(rot)
        self.sp_rot_req.setEnabled(rot)
        self.cb_rotdrop.setEnabled(rot)
        self._apply()

    def _chain_keys(self) -> list:
        return [self.chain_list.item(i).data(Qt.ItemDataRole.UserRole)
                for i in range(self.chain_list.count())]

    def _build_cfg(self) -> ServerConfig:
        countries = {c.upper() for c in re.split(r"[,\s;]+", self.ed_countries.text()) if c}
        return ServerConfig(
            host=self.ed_host.text().strip() or "127.0.0.1", port=self.sp_port.value(),
            mode=self._mode_key(), chain=self._chain_keys(), chain_len=self.sp_len.value(),
            countries=countries, min_score=self.sp_score.value(),
            require_rdns=self.cb_rdns.isChecked(), sticky_ttl=self.sp_ttl.value() * 60.0,
            monitor=self.cb_monitor.isChecked(), monitor_interval=float(self.sp_interval.value()),
            max_fails=self.sp_fails.value(), log_connections=self.cb_log.isChecked(),
            drop_on_change=self.cb_drop.isChecked(),
            favourites=frozenset(self.main.store.favourites), fav_fallback=self.cb_favfb.isChecked(),
            rotate_minutes=float(self.sp_rot_min.value()), rotate_requests=self.sp_rot_req.value(),
            rotate_drop=self.cb_rotdrop.isChecked())

    def _apply(self, *_):
        if hasattr(self, "server") and self.server and self.server.running:
            self.server.update_config(self._build_cfg())

    # ------------------------------------------------------------ start / stop
    def start_server(self):
        if self._stopping or (self.server and self.server.running):
            return
        cfg = self._build_cfg()
        probe_cfg, my_ip = self.main.probe_settings()
        my_ip = my_ip or self._import_my_ip
        srv = ProxyServer(cfg, self.pool, probe_cfg, my_ip)
        try:
            srv.start()
        except OSError as e:
            QMessageBox.warning(self, "Cannot start the server",
                                f"Could not listen on {cfg.host}:{cfg.port}\n\n{e}")
            return
        except Exception as e:
            QMessageBox.warning(self, "Cannot start the server", str(e))
            return
        self.server = srv
        self._seq = 0
        self._seen_changes = 0
        self._set_running(True)
        self.main.log(f"Proxy server listening on {cfg.host}:{srv.port}")
        self._tick()

    def stop_server(self):
        """Stop without blocking the window: ask the server thread to stop, then poll."""
        if self._stopping:
            return
        if self._ip_future is not None:
            self._ip_future.cancel()
            self._finish_change(None, "server stopped", quiet=True)
        self._restore_sysproxy()               # never leave the OS pointing at a stopped server
        if not self.server or self.server.stopped:
            self._set_running(False)
            self._tick()
            return
        self._stopping = True
        self._stop_started = time.monotonic()
        for b in (self.btn_stop, self.btn_change, self.btn_browser):
            b.setEnabled(False)
        self.server.request_stop()
        QTimer.singleShot(100, self._poll_stop)

    def _poll_stop(self):
        srv = self.server
        if srv and not srv.stopped and time.monotonic() - self._stop_started < 8.0:
            QTimer.singleShot(100, self._poll_stop)
            return
        self._stopping = False
        self._drain_events()
        self.main.log("Proxy server stopped")
        self._set_running(False)
        self._tick()

    def shutdown(self):
        self.timer.stop()
        self._restore_sysproxy(quiet=True)
        if self._import_checker:
            self._import_checker.stop()
        if self._import_task and not self._import_task.done():
            self._import_task.cancel()
        if self.server:
            self.server.stop()
        # the proxy is gone, so the safe-browser windows are useless: close them and delete
        # their temporary profiles instead of leaving both behind
        if self._browsers:
            try:
                browser.terminate_all(self._browsers)
            except Exception:
                pass
            self._browsers.clear()

    def _set_running(self, on: bool):
        self.btn_start.setEnabled(not on)
        self.btn_stop.setEnabled(on)
        self.ed_host.setEnabled(not on)
        self.sp_port.setEnabled(not on)
        self.btn_change.setEnabled(on and self._ip_future is None)
        self.btn_browser.setEnabled(on and bool(self._browser_infos))
        self.cb_sysproxy.setEnabled(on and self.sysproxy.available)

    # ------------------------------------------------------------ safe browser
    def launch_browser(self):
        srv = self.server
        if not (srv and srv.running):
            QMessageBox.information(self, "Safe browser", "Start the server first.")
            return
        info = self.cmb_browser.currentData()
        if not info:
            return
        host = srv.cfg.host
        if host in ("", "0.0.0.0", "::"):
            host = "127.0.0.1"
        try:
            sess = browser.launch(info, host, srv.port,
                                  browser.LEAK_TEST_URL if self.cb_leaktest.isChecked() else None,
                                  keep=self.cb_keep.isChecked())
        except Exception as e:
            QMessageBox.warning(self, "Safe browser", f"Could not start {info.title}:\n\n{e}")
            return
        self._browsers.append(sess)
        self.main.log(f"Safe browser started: {info.title} → socks5://{host}:{srv.port} "
                      f"(profile {sess.profile})")
        if info.snap:
            self.main.log("Note: snap browsers can refuse a custom profile folder; "
                          "if the window does not open, install the .deb / apt version instead.")

    def _reap_browsers(self):
        for sess in list(self._browsers):
            code = sess.finished()
            if code is None:
                continue
            self._browsers.remove(sess)
            sess.cleanup()
            quick = (time.monotonic() - sess.started) < 5
            if quick and code != 0:
                self.main.log(f"Safe browser {sess.info.title} exited immediately (code {code}); "
                              "it may not support a custom profile (snap/flatpak?).")
            else:
                self.main.log(f"Safe browser {sess.info.title} closed"
                              + ("" if sess.keep else " - temporary profile deleted"))

    # ------------------------------------------------------------ change IP
    def change_ip(self):
        srv = self.server
        if not (srv and srv.running):
            QMessageBox.information(self, "Change IP", "Start the server first.")
            return
        if self._ip_future is not None:
            return                                           # a change is already running
        mode = self._mode_key()
        if mode.startswith("chain"):
            QMessageBox.information(
                self, "Change IP",
                "Chain modes use the chain list (or a new random chain for every connection).\n"
                "Switch to a single-proxy mode to use Change IP.")
            return
        if mode != "manual":
            self.cmb_mode.setCurrentIndex(self.cmb_mode.findData("manual"))
            self.main.log("Mode switched to Manual: the exit IP now stays fixed until you press Change IP again")
        try:
            self._ip_future = srv.change_ip()
        except RuntimeError as exc:
            self.lbl_exit.setText(f"⚠ {exc}")
            return
        self._ip_started = time.monotonic()
        self.btn_change.setEnabled(False)
        self.btn_change.setText("Testing next proxy…")
        QTimer.singleShot(150, self._poll_change)

    def use_proxy(self, key: str):
        """Right-click ▸ Connect through this IP: hold exactly this pool member (manual mode)."""
        srv = self.server
        if not (srv and srv.running):
            QMessageBox.information(self, "Connect through this IP", "Start the server first.")
            return
        if self._ip_future is not None:
            return                                           # another change is still running
        if self._mode_key() != "manual":
            self.cmb_mode.setCurrentIndex(self.cmb_mode.findData("manual"))
            self.main.log("Mode switched to Manual: the exit IP now stays fixed on the proxy you chose")
        try:
            self._ip_future = srv.change_ip(key)
        except RuntimeError as exc:
            self.lbl_exit.setText(f"⚠ {exc}")
            return
        self._ip_started = time.monotonic()
        self.btn_change.setEnabled(False)
        self.btn_change.setText("Testing that proxy…")
        QTimer.singleShot(150, self._poll_change)

    def _poll_change(self):
        fut = self._ip_future
        if fut is None:
            return
        if not fut.done():
            if time.monotonic() - self._ip_started > 45:
                fut.cancel()
                self._finish_change(None, "timed out")
            else:
                QTimer.singleShot(150, self._poll_change)
            return
        try:
            self._finish_change(fut.result(), "")
        except Exception as exc:
            self._finish_change(None, f"{type(exc).__name__}: {exc}")

    def _finish_change(self, res, error: str, quiet: bool = False):
        self._ip_future = None
        self.btn_change.setText("🔄  Change IP")
        self.btn_change.setEnabled(bool(self.server and self.server.running))
        if quiet:
            return
        if res is None or not res.ok:
            msg = error if res is None else res.message
            self.lbl_exit.setText(f"⚠ IP not changed: {msg}")
            self.lbl_exit.setStyleSheet("color: #c0392b;")
            self.main.log(f"Change IP failed: {msg}")
        else:
            if self.server:
                self._seen_changes = self.server.change_count
            self._show_change_ok(res)
        self._tick()

    def _show_change_ok(self, res, prefix: str = ""):
        cc = f" [{res.country}]" if res.country else ""
        closed = f" · {res.dropped} open connection(s) closed" if res.dropped else ""
        note = f" — {res.message}" if res.message else ""
        self.lbl_exit.setText(
            f"{prefix}✓ Exit IP: {res.exit_ip}{cc}  via {res.address}  ({res.ms:.0f} ms){closed}{note}")
        self.lbl_exit.setStyleSheet("color: #1e6f3a;")

    # ------------------------------------------------------------ proxy list import
    def _browse_proxy_files(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Choose proxy list files", "",
            "Proxy lists (*.txt *.list *.csv *.conf);;Text files (*.txt);;All files (*)")
        if paths:
            self._load_proxy_files(paths)

    def _load_proxy_files(self, paths: list[str]):
        chunks = []
        errors = []
        for path in paths:
            try:
                chunks.append("\n".join(read_lines(path)))
            except (OSError, UnicodeError) as exc:
                errors.append(f"{path}: {exc}")
        if chunks:
            current = self.ed_proxy_list.toPlainText().rstrip()
            combined = "\n".join(part for part in [current, *chunks] if part)
            self.ed_proxy_list.setPlainText(combined)
            self.lbl_proxy_import.setText(f"Loaded {len(chunks)} file(s). Click ‘Check & add’ to verify them.")
        if errors:
            QMessageBox.warning(self, "Could not read file(s)", "\n".join(errors[:8]))

    def _check_and_add_proxy_list(self):
        if self._import_task and not self._import_task.done():
            return
        self._import_stopped = False
        lines = self.ed_proxy_list.toPlainText().splitlines()
        cfg = self.main._build_config()
        # Import checks are isolated from the main Checker run and do not clear its results.
        self._import_task = self.main.loop.create_task(self._import_flow(lines, cfg))

    async def _import_flow(self, lines, cfg):
        if len(lines) > self.main.SYNC_PARSE_LIMIT:         # big list: parse in a worker thread
            self.lbl_proxy_import.setText(f"Parsing {len(lines):,} lines…")
            report = await self.main.loop.run_in_executor(self.main._parse_exec, parse_lines, lines)
        else:
            report = parse_lines(lines)
        if not report.entries:
            detail = f"\nInvalid lines: {report.invalid}." if report.invalid else ""
            self.lbl_proxy_import.setText("No valid proxies found.")
            QMessageBox.information(self, "No valid proxies", "Paste, browse, or drop a proxy list first." + detail)
            return
        entries = [e for e in report.entries if not self.main.store.is_black(e.key)]
        if not entries:
            self.lbl_proxy_import.setText("Every proxy in this list is blacklisted.")
            QMessageBox.information(self, "Nothing to check", "Every proxy in this list is blacklisted.")
            return
        await self._run_proxy_list_check(entries, cfg)

    async def _run_proxy_list_check(self, entries, cfg):
        live_results = []
        self._last_import = None
        self.btn_proxy_import.setEnabled(False)
        self.btn_proxy_browse.setEnabled(False)
        self.btn_proxy_stop.setEnabled(True)
        self.lbl_proxy_import.setText(f"Checking {len(entries):,} proxy entries…")
        checker = Checker(cfg)
        self._import_checker = checker
        try:
            await checker.prepare()
            for note in checker.notes:
                self.main.log(f"[rotation import] {note}")
            if checker.my_ip:
                self._import_my_ip = checker.my_ip
                if self.server and self.server.running and not self.server.my_ip:
                    self.server.set_my_ip(checker.my_ip)

            def on_result(result):
                if result.live:
                    live_results.append(result)

            progress = {"done": 0}

            def on_progress(done, total):
                progress["done"] = done
                self.lbl_proxy_import.setText(
                    f"Checking rotation list… {done:,}/{total:,} · {len(live_results):,} live so far")

            await checker.run(entries, on_result, on_progress)
            if self.main.cb_geo.isChecked() and live_results and not checker.is_stopped():
                ips = sorted({r.exit_ip for r in live_results if r.exit_ip})
                self.lbl_proxy_import.setText(f"Looking up the location of {len(ips):,} exit IPs…")
                geo.apply(live_results, await geo.lookup(ips, checker.is_stopped, self.main.log))
            store = self.main.store
            live_results = [r for r in live_results if not store.is_black(r.key)]   # may have changed meanwhile
            added = self.pool.add(live_results)
            invalid_note = ""
            if not live_results:
                invalid_note = " No live proxies were found; the pool was not changed."
            checked = progress["done"] if checker.is_stopped() else len(entries)
            self.lbl_proxy_import.setText(
                ("Stopped. " if checker.is_stopped() else "") +
                f"Checked {checked:,}: {len(live_results):,} live, "
                f"{checked - len(live_results):,} not live; {added:,} new added to pool." + invalid_note)
            self.main.log(
                f"[rotation import] checked {checked} entries; {len(live_results)} live, "
                f"{added} new proxies added to pool")
            self._last_import = (checked, len(live_results), added)
            self._tick()
        except asyncio.CancelledError:
            self.lbl_proxy_import.setText("Proxy-list check cancelled.")
            raise
        except Exception as exc:
            self.lbl_proxy_import.setText(f"Import check failed: {type(exc).__name__}: {exc}")
            self.main.log(f"[rotation import] failed: {type(exc).__name__}: {exc}")
        finally:
            self._import_checker = None
            self.btn_proxy_import.setEnabled(True)
            self.btn_proxy_browse.setEnabled(True)
            self.btn_proxy_stop.setEnabled(False)

    def _stop_import(self):
        self._import_stopped = True
        if self._import_checker:
            self._import_checker.stop()
            self.lbl_proxy_import.setText("Stopping…")
        elif self._import_task and not self._import_task.done():
            self._import_task.cancel()                       # still downloading / parsing

    # ------------------------------------------------------------ URL sources (auto-fetch)
    def _start_sources(self, sources, manual: bool = False) -> bool:
        if self._import_task and not self._import_task.done():
            if manual:
                self.sources_panel.lbl.setText("Another import is still running - try again when it finishes.")
            return False
        cfg = self.main._build_config()
        self._import_stopped = False
        self._import_task = self.main.loop.create_task(self._sources_flow(list(sources), cfg))
        return True

    async def _sources_flow(self, sources, cfg):
        """Download each list, check it with the Checker settings, add the live proxies to the pool."""
        store, panel = self.source_store, self.sources_panel
        panel.set_busy(True)
        try:
            for src in sources:
                if self._import_stopped:
                    break
                self.btn_proxy_stop.setEnabled(True)
                src.last_fetch = time.time()
                self.lbl_proxy_import.setText(f"Downloading {src.url} …")
                panel.lbl.setText(f"Downloading {src.url} …")
                try:
                    lines = await fetch_lines(src.url)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    src.last_status = f"download failed: {exc}"
                    self.main.log(f"[source] {src.url}: {exc}")
                    store.save()
                    panel.refresh()
                    continue
                if len(lines) > self.main.SYNC_PARSE_LIMIT:
                    report = await self.main.loop.run_in_executor(self.main._parse_exec, parse_lines, lines)
                else:
                    report = parse_lines(lines)
                entries = [e for e in report.entries if not self.main.store.is_black(e.key)]
                if not entries:
                    src.last_status = (f"no valid proxies in {len(lines):,} lines"
                                       if lines else "the download was empty")
                    self.main.log(f"[source] {src.url}: {src.last_status}")
                    store.save()
                    panel.refresh()
                    continue
                self.main.log(f"[source] {src.url}: {len(lines):,} lines → {len(entries):,} proxies, checking…")
                await self._run_proxy_list_check(entries, cfg)
                if self._last_import:
                    checked, live, added = self._last_import
                    src.last_status = (("stopped · " if self._import_stopped else "")
                                       + f"{len(entries):,} proxies · {live:,} live · {added:,} new")
                else:
                    src.last_status = "check failed"
                store.save()
                panel.refresh()
        finally:
            panel.set_busy(False)
            panel.refresh()
            self.btn_proxy_stop.setEnabled(False)

    def _auto_fetch_due(self):
        """Every ~30 s: download the lists whose refresh interval has passed."""
        now = time.monotonic()
        if now - self._last_src_check < 30:
            return
        self._last_src_check = now
        if self._import_task and not self._import_task.done():
            return
        due = self.source_store.due()
        if due:
            self.main.log(f"[source] auto-refresh: {len(due)} list(s) due")
            self._start_sources(due)

    # ------------------------------------------------------------ pool actions
    def add_from_checker(self):
        store = self.main.store
        live = [r for r in self.main.model.results if r.live and not store.is_black(r.key)]
        n = self.pool.add(live)
        self.main.log(f"Pool: {n} new proxies added ({len(self.pool)} total)")
        self._tick()

    def on_check_finished(self):
        if self.cb_auto.isChecked():
            self.add_from_checker()

    def _selected_keys(self) -> list:
        rows = self.table.selectionModel().selectedRows()
        return [self.pool_model.members[self.pool_proxy.mapToSource(i).row()].key for i in rows]

    def _remove_selected(self):
        keys = self._selected_keys()
        if keys:
            self.pool.remove(keys)
            self._tick()

    def _clear_pool(self):
        self.pool.clear()
        self._tick()

    def add_links_results(self, results) -> int:
        """Live V2Ray-link results (tab 3) -> rotation pool. Returns how many were new."""
        store = self.main.store
        live = [r for r in results if r.live and not store.is_black(r.key)]
        n = self.pool.add(live) if live else 0
        self._tick()
        return n

    # ---- right-click menu of the pool table
    def _pool_context_menu(self, pos):
        idx = self.table.indexAt(pos)
        if idx.isValid() and not self.table.selectionModel().isSelected(idx):
            self.table.selectRow(idx.row())                  # right-click on an unselected row selects it
        keys = self._selected_keys()
        if not keys:
            return
        store = self.main.store
        running = bool(self.server and self.server.running)
        m = QMenu(self)
        a = m.addAction("▶  Connect through this IP" if len(keys) == 1
                        else "▶  Connect through the first selected IP", lambda: self.use_proxy(keys[0]))
        a.setEnabled(running)
        a.setToolTip("Holds exactly this proxy as the exit IP (switches to Manual mode)")
        a = m.addAction("↻  Re-test now", lambda: self._retest(keys))
        a.setEnabled(running)
        m.addSeparator()
        all_fav = all(store.is_fav(k) for k in keys)
        m.addAction("☆  Remove from favourites" if all_fav else "★  Add to favourites",
                    lambda: self._set_fav(keys, not all_fav))
        gm = m.addMenu("Failover group")
        for g, name in FAILOVER_GROUPS.items():
            gm.addAction(f"{g} · {name}", lambda _=False, g=g: self._set_group(keys, g))
        m.addAction("⛓  Add to chain", self._add_selected_to_chain)
        m.addSeparator()
        members = [self.pool.get(k) for k in keys]
        members = [x for x in members if x]
        cm = m.addMenu("Copy")
        cm.addAction("Proxy URL(s)", lambda: self._copy_text("\n".join(x.res.url for x in members)))
        cm.addAction("host:port", lambda: self._copy_text("\n".join(x.res.address for x in members)))
        cm.addAction("Exit IP(s)", lambda: self._copy_text("\n".join(x.res.exit_ip for x in members if x.res.exit_ip)))
        m.addSeparator()
        m.addAction("⛔  Blacklist (remove and never use again)", lambda: self.main.set_blacklist(keys, True))
        m.addAction("✕  Remove from pool", self._remove_selected)
        m.exec(self.table.viewport().mapToGlobal(pos))

    @staticmethod
    def _copy_text(text: str):
        QGuiApplication.clipboard().setText(text)

    def _set_fav(self, keys, on: bool):
        self.main.store.set_fav(keys, on)
        self.main.favourites_changed()

    def on_favourites_changed(self):
        self._apply()                                        # the server needs the new favourite set
        self._tick()

    def _set_group(self, keys, group: int):
        n = self.pool.set_group(keys, group)
        self.main.log(f"{n} proxy(ies) moved to failover group {group} · {FAILOVER_GROUPS.get(group, '?')}"
                      + ("" if self._mode_key() == "failover" else "  (used when mode is “Failover groups”)"))
        self._tick()

    def _retest(self, keys):
        srv = self.server
        if not (srv and srv.running):
            return
        try:
            fut = srv.recheck(keys)
        except RuntimeError:
            return
        self.main.log(f"Re-testing {len(keys)} proxy(ies)…")
        self._poll_retest(fut, time.monotonic())

    def _poll_retest(self, fut, t0: float):
        if not fut.done():
            if time.monotonic() - t0 > 60:
                fut.cancel()
                self.main.log("Re-test timed out")
            else:
                QTimer.singleShot(200, lambda: self._poll_retest(fut, t0))
            return
        try:
            res = fut.result()
        except Exception as exc:
            self.main.log(f"Re-test failed: {type(exc).__name__}: {exc}")
            return
        for addr, alive, ms in res[:12]:
            self.main.log(f"Re-test {addr}: " + (f"alive ({ms:.0f} ms)" if alive and ms is not None else
                                                  "alive" if alive else "DOWN"))
        if len(res) > 12:
            alive_n = sum(1 for _, a, _ in res if a)
            self.main.log(f"Re-test: … {len(res)} proxies, {alive_n} alive")
        self._tick()

    # ---- export from the pool
    def _pool_results(self) -> list:
        return [m.res for m in self.pool.members() if m.alive]

    def _local_addr(self):
        srv = self.server
        if srv and srv.running:
            return srv.cfg.host, srv.port
        return self.ed_host.text().strip() or "127.0.0.1", self.sp_port.value()

    def _export_pool_proxychains(self):
        export_dialogs.save_proxychains(self, self._pool_results(), self.main.log)

    def _export_pool_pac(self):
        export_dialogs.save_pac(self, self._pool_results(), self.main.log)

    def _export_local_proxychains(self):
        export_dialogs.save_local_proxychains(self, *self._local_addr(), self.main.log)

    def _export_local_pac(self):
        export_dialogs.save_local_pac(self, *self._local_addr(), self.main.log)

    # ---- system proxy / terminal
    @staticmethod
    def _set_check(cb: QCheckBox, state: bool):
        cb.blockSignals(True)
        cb.setChecked(state)
        cb.blockSignals(False)

    async def _detect_sysproxy(self):
        """Find the system-proxy backend without freezing the window (gsettings can block for seconds),
        then undo whatever a crashed session left behind."""
        self.sysproxy.backend = await self.main.loop.run_in_executor(None, SystemProxy._detect)
        if self.sysproxy.available:
            self.cb_sysproxy.setToolTip(
                f"Sets the {self.sysproxy.label} to this server while it runs; the previous\n"
                "setting is restored when you untick this, stop the server or close the app.")
        else:
            self.cb_sysproxy.setToolTip(
                "No system-proxy backend here (supported: GNOME / Cinnamon, Windows).\n"
                "Use “Copy terminal commands” for shells, or the PAC export for browsers.")
        self.cb_sysproxy.setEnabled(bool(self.server and self.server.running) and self.sysproxy.available)
        self._startup_restore()

    def _startup_restore(self):
        """A crashed session may have left the OS pointing at a dead port: undo that."""
        if self.sysproxy.available:
            msg = self.sysproxy.restore_stale()
            if msg:
                self.main.log(msg)

    def _toggle_sysproxy(self, on: bool):
        if not on:
            self._restore_sysproxy()
            return
        srv = self.server
        if not (srv and srv.running):
            self._set_check(self.cb_sysproxy, False)
            return
        if not self._sys_confirmed:
            ans = QMessageBox.question(
                self, "Use as system proxy",
                f"Programs that follow the {self.sysproxy.label} will send ALL their traffic through "
                f"this server ({srv.cfg.host}:{srv.port}).\n\n"
                "Your previous setting is saved and restored when you untick this, stop the server "
                "or close the app. If no proxy is usable, those programs get no connection at all "
                "(kill-switch).\n\nContinue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if ans != QMessageBox.StandardButton.Yes:
                self._set_check(self.cb_sysproxy, False)
                return
            self._sys_confirmed = True
        try:
            msg = self.sysproxy.enable(srv.cfg.host, srv.port)
        except SysProxyError as exc:
            self._set_check(self.cb_sysproxy, False)
            self.main.log(f"System proxy: {exc}")
            QMessageBox.warning(self, "System proxy", str(exc))
            return
        self._sys_set = True
        self.main.log(msg)

    def _restore_sysproxy(self, quiet: bool = False):
        if self._sys_set or self.sysproxy.active():
            try:
                msg = self.sysproxy.disable()
                if not quiet:
                    self.main.log(msg)
            except SysProxyError as exc:
                if not quiet:
                    self.main.log(f"System proxy: {exc}")
                    QMessageBox.warning(self, "System proxy", str(exc))
            self._sys_set = False
        self._set_check(self.cb_sysproxy, False)

    def _copy_env(self):
        host, port = self._local_addr()
        QGuiApplication.clipboard().setText(shell_env(host, port))
        self.main.log(f"Terminal commands for {host}:{port} copied - paste them into a shell "
                      "(the last line undoes them)."
                      + ("" if (self.server and self.server.running) else "  Start the server first."))

    def drop_keys(self, keys) -> int:
        """Remove proxies from the rotation pool AND the chain builder (e.g. after blacklisting).

        Returns how many of them were in the pool."""
        keys = set(keys)
        in_pool = sum(1 for k in keys if self.pool.get(k) is not None)
        self.pool.remove(keys)
        for i in reversed(range(self.chain_list.count())):
            if self.chain_list.item(i).data(Qt.ItemDataRole.UserRole) in keys:
                self.chain_list.takeItem(i)
        self._chain_changed()
        self._tick()
        return in_pool

    # ------------------------------------------------------------ chain builder
    def add_to_chain(self, results) -> None:
        live = [r for r in results if r.live and not self.main.store.is_black(r.key)]
        if not live:
            return
        self.pool.add(live)
        have = set(self._chain_keys())
        for r in live:
            if r.key not in have:
                item = QListWidgetItem(r.key)
                item.setData(Qt.ItemDataRole.UserRole, r.key)
                self.chain_list.addItem(item)
                have.add(r.key)
        self._chain_changed()
        self._tick()

    def _add_selected_to_chain(self):
        keys = self._selected_keys()
        have = set(self._chain_keys())
        for k in keys:
            if k not in have:
                item = QListWidgetItem(k)
                item.setData(Qt.ItemDataRole.UserRole, k)
                self.chain_list.addItem(item)
        self._chain_changed()

    def _move(self, delta: int):
        rows = sorted({self.chain_list.row(i) for i in self.chain_list.selectedItems()})
        if len(rows) != 1:
            return
        row = rows[0]
        new = row + delta
        if not 0 <= new < self.chain_list.count():
            return
        item = self.chain_list.takeItem(row)
        self.chain_list.insertItem(new, item)
        self.chain_list.setCurrentRow(new)
        self._chain_changed()

    def _chain_remove(self):
        for item in self.chain_list.selectedItems():
            self.chain_list.takeItem(self.chain_list.row(item))
        self._chain_changed()

    def _chain_clear(self):
        self.chain_list.clear()
        self._chain_changed()

    def _chain_changed(self, *_):
        for i in range(self.chain_list.count()):
            item = self.chain_list.item(i)
            key = item.data(Qt.ItemDataRole.UserRole)
            m = self.pool.get(key)
            if m:
                cc = f"  [{m.res.country_code}]" if m.res.country_code else ""
                label = f"{m.res.kind or m.res.proto}  {m.res.address}{cc}"
            else:
                label = f"{key}  (not in pool)"
            item.setText(f"{i + 1}.  {label}")
        self._apply()

    # ------------------------------------------------------------ periodic refresh
    def _drain_events(self):
        if not self.server:
            return
        events = self.server.events_since(self._seq)
        if not events:
            return
        self._seq = events[-1][0]
        show = events[-25:]
        if len(events) > len(show):
            self.main.log(f"[server] … {len(events) - len(show)} more events")
        for _, _, text in show:
            self.main.log(f"[server] {text}")

    def _tick(self):
        self._reap_browsers()
        self._auto_fetch_due()
        members = self.pool.members()
        srv = self.server
        held = srv.current_member() if (srv and srv.running and srv.cfg.mode == "manual") else None
        self.pool_model.set_members(members, self._chain_keys(), held.key if held else None)
        now = time.monotonic()
        alive = sum(1 for m in members if m.alive and m.cooldown <= now)
        cooling = sum(1 for m in members if m.alive and m.cooldown > now)
        self.lbl_pool.setText(f"Pool: {len(members):,} · alive {alive:,} · cooling {cooling:,} · "
                              f"down {len(members) - alive - cooling:,}")
        if srv and srv.running:
            st = srv.stats
            n, blocked, reason = srv.status()
            addr = f"{srv.cfg.host}:{srv.port}"
            if blocked:
                self.lbl_banner.setText(
                    f"⛔ KILL-SWITCH ACTIVE - {reason}.\n"
                    f"All traffic sent to {addr} is blocked; nothing goes out directly.")
                self.lbl_banner.setStyleSheet(
                    "background:#8e2a20;color:white;padding:6px;border-radius:4px;")
            else:
                held_txt = ""
                if srv.cfg.mode == "manual":
                    if held:
                        cc = f" [{held.res.country_code}]" if held.res.country_code else ""
                        held_txt = (f"\nHolding: {held.res.address} → exit IP "
                                    f"{srv.current_exit_ip or held.res.exit_ip}{cc}")
                    else:
                        held_txt = "\nHolding: (chosen at the first connection or on Change IP)"
                extra_txt = ""
                if srv.cfg.mode == "failover":
                    g = srv.active_group()
                    extra_txt += (f"\nActive group: {g} · {FAILOVER_GROUPS.get(g, '?')}" if g else "")
                rot = srv.rotate_status()
                if rot:
                    extra_txt += "\n" + rot
                self.lbl_banner.setText(
                    f"● RUNNING on {addr} · mode: {self.cmb_mode.currentText()} · "
                    f"{n} eligible {'hops' if self._mode_key() in ('chain_strict', 'chain_dynamic') else 'proxies'}"
                    + held_txt + extra_txt)
                self.lbl_banner.setStyleSheet(
                    "background:#1e6f3a;color:white;padding:6px;border-radius:4px;")
            self.lbl_stats.setText(
                f"Connections: {st.active} active · {st.total:,} total · {st.success:,} ok · "
                f"{st.errors:,} failed · {st.blocked:,} blocked    "
                f"↑ {_fmt_bytes(st.up)}  ↓ {_fmt_bytes(st.down)}")
            if srv.change_count != self._seen_changes:           # auto-rotate (or another surface) changed the IP
                self._seen_changes = srv.change_count
                if self._ip_future is None and srv.last_change and srv.last_change.ok:
                    self._show_change_ok(srv.last_change, "auto · ")
            self._drain_events()
        else:
            if self._sys_set and not self._stopping:
                self._restore_sysproxy()                        # server died: do not leave the OS pointing at it
            self.lbl_banner.setText("■ Server stopped. Add proxies to the pool, pick a mode, "
                                    "then press Start.")
            self.lbl_banner.setStyleSheet(
                "background:#555;color:white;padding:6px;border-radius:4px;")
            self.lbl_stats.setText("")
            if self.server and not self.server.running and self.btn_stop.isEnabled():
                self._set_running(False)
