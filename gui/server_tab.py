"""'Proxy Server' tab: start the local proxy, choose rotation / chain mode, manage the pool."""
from __future__ import annotations

import asyncio
import re
import time

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QBrush
from PyQt6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QFormLayout, QFrame, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMessageBox, QPlainTextEdit,
    QPushButton, QScrollArea, QSpinBox, QSplitter, QStyle, QTableView, QVBoxLayout, QWidget,
)

from core import browser, geo
from core.server import MODES, Pool, ProxyServer, ServerConfig
from core.checker import Checker
from core.parser import parse_lines, read_lines

from .results_model import AMBER, GREEN, GREY, RED, SORT_ROLE, _ip_key

MODE_HELP = {
    "round_robin": "Every new connection uses the next live proxy in turn.",
    "random": "Every new connection uses a random live proxy.",
    "fastest": "Always uses the live proxy with the lowest latency; if it fails, the next fastest.",
    "sticky": "A website (domain) keeps the same exit IP; different domains rotate. "
              "Good for logins and sessions.",
    "chain_strict": "Traffic goes through EVERY proxy of the chain list, in order (A → B → C). "
                    "If any hop is down the connection is blocked.",
    "chain_dynamic": "Like strict, but hops that are down are skipped automatically.",
    "chain_random": "Builds a new random chain of N live proxies for every connection.",
}

POOL_COLS = [("State", 70), ("Proxy", 170), ("Type", 60), ("Country", 120), ("Latency", 80),
             ("Score", 55), ("Uses", 55), ("Fails", 50), ("Chain", 50)]
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
    def __init__(self):
        super().__init__()
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
                return r.address
            if c == 2:
                return r.proto
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

        self.pool_model = PoolModel()
        self.pool_proxy = QSortFilterProxyModel()
        self.pool_proxy.setSourceModel(self.pool_model)
        self.pool_proxy.setSortRole(SORT_ROLE)

        self._build()
        self._mode_changed()
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
        self.cb_drop = QCheckBox("Close open connections when the IP changes")
        self.cb_drop.setChecked(True)
        self.cb_drop.setToolTip("Manual mode: browsers keep old connections open, so the website would still see\n"
                                "the previous IP. Closing them makes the browser reconnect through the new proxy.")
        self.cb_drop.toggled.connect(self._apply)
        f.addRow(self.cmb_mode)
        f.addRow(self.lbl_help)
        f.addRow("Random chain length", self.sp_len)
        f.addRow("Sticky lifetime", self.sp_ttl)
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
            drop_on_change=self.cb_drop.isChecked())

    def _apply(self, *_):
        if hasattr(self, "server") and self.server and self.server.running:
            self.server.update_config(self._build_cfg())

    # ------------------------------------------------------------ start / stop
    def start_server(self):
        if self.server and self.server.running:
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
        self._set_running(True)
        self.main.log(f"Proxy server listening on {cfg.host}:{srv.port}")
        self._tick()

    def stop_server(self):
        if self._ip_future is not None:
            self._ip_future.cancel()
            self._finish_change(None, "server stopped", quiet=True)
        if self.server:
            self.server.stop()
            self._drain_events()
            self.main.log("Proxy server stopped")
        self._set_running(False)
        self._tick()

    def shutdown(self):
        self.timer.stop()
        if self._import_checker:
            self._import_checker.stop()
        if self._import_task and not self._import_task.done():
            self._import_task.cancel()
        if self.server:
            self.server.stop()

    def _set_running(self, on: bool):
        self.btn_start.setEnabled(not on)
        self.btn_stop.setEnabled(on)
        self.ed_host.setEnabled(not on)
        self.sp_port.setEnabled(not on)
        self.btn_change.setEnabled(on and self._ip_future is None)
        self.btn_browser.setEnabled(on and bool(self._browser_infos))

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
            cc = f" [{res.country}]" if res.country else ""
            closed = f" · {res.dropped} open connection(s) closed" if res.dropped else ""
            note = f" — {res.message}" if res.message else ""
            self.lbl_exit.setText(
                f"✓ Exit IP: {res.exit_ip}{cc}  via {res.address}  ({res.ms:.0f} ms){closed}{note}")
            self.lbl_exit.setStyleSheet("color: #1e6f3a;")
        self._tick()

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
        report = parse_lines(self.ed_proxy_list.toPlainText().splitlines())
        if not report.entries:
            detail = f"\nInvalid lines: {report.invalid}." if report.invalid else ""
            QMessageBox.information(self, "No valid proxies", "Paste, browse, or drop a proxy list first." + detail)
            return
        entries = [e for e in report.entries if not self.main.store.is_black(e.key)]
        if not entries:
            QMessageBox.information(self, "Nothing to check", "Every proxy in this list is blacklisted.")
            return
        report.entries = entries
        cfg = self.main._build_config()
        # Import checks are isolated from the main Checker run and do not clear its results.
        self._import_task = self.main.loop.create_task(self._run_proxy_list_check(report.entries, cfg))

    async def _run_proxy_list_check(self, entries, cfg):
        live_results = []
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
        if self._import_checker:
            self._import_checker.stop()
            self.lbl_proxy_import.setText("Stopping…")

    # ------------------------------------------------------------ pool actions
    def add_from_checker(self):
        live = [r for r in self.main.model.results if r.live]
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

    # ------------------------------------------------------------ chain builder
    def add_to_chain(self, results) -> None:
        live = [r for r in results if r.live]
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
                label = f"{m.res.proto}  {m.res.address}{cc}"
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
                self.lbl_banner.setText(
                    f"● RUNNING on {addr} · mode: {self.cmb_mode.currentText()} · "
                    f"{n} eligible {'hops' if self._mode_key() in ('chain_strict', 'chain_dynamic') else 'proxies'}"
                    + held_txt)
                self.lbl_banner.setStyleSheet(
                    "background:#1e6f3a;color:white;padding:6px;border-radius:4px;")
            self.lbl_stats.setText(
                f"Connections: {st.active} active · {st.total:,} total · {st.success:,} ok · "
                f"{st.errors:,} failed · {st.blocked:,} blocked    "
                f"↑ {_fmt_bytes(st.up)}  ↓ {_fmt_bytes(st.down)}")
            self._drain_events()
        else:
            self.lbl_banner.setText("■ Server stopped. Add proxies to the pool, pick a mode, "
                                    "then press Start.")
            self.lbl_banner.setStyleSheet(
                "background:#555;color:white;padding:6px;border-radius:4px;")
            self.lbl_stats.setText("")
            if self.server and not self.server.running and self.btn_stop.isEnabled():
                self._set_running(False)
