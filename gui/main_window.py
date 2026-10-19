"""Main window: input (drag & drop / browse / paste), settings, live results table."""
from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import QAction, QDesktopServices, QFontDatabase, QGuiApplication
from PyQt6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDoubleSpinBox, QFileDialog, QFormLayout,
    QFrame, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow,
    QMenu, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QScrollArea, QSpinBox, QSplitter, QStyle,
    QTableView, QTabWidget, QToolButton, QVBoxLayout, QWidget,
)

from core import export, geo
from core.checker import CLOUDFLARE, GOOGLE, IPIFY, CheckConfig, Checker, Target
from core.parser import parse_lines, read_lines
from core.store import ListStore, config_dir
from core.version import __version__

from .results_model import COLUMNS, ResultsFilter, ResultsModel
from .server_tab import ServerTab

SHOW_MODES = [("All", "all"), ("Live only", "live"), ("Dead only", "dead"),
              ("★ Favourites", "fav"), ("⛔ Blacklisted", "black")]


def _local_paths(mime) -> list:
    return [u.toLocalFile() for u in mime.urls() if u.isLocalFile()]


class DropPlainTextEdit(QPlainTextEdit):
    """Text box that accepts pasted proxies AND dropped files."""
    filesDropped = pyqtSignal(list)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
        else:
            super().dragEnterEvent(e)

    def dragMoveEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
        else:
            super().dragMoveEvent(e)

    def dropEvent(self, e):
        if e.mimeData().hasUrls():
            paths = _local_paths(e.mimeData())
            if paths:
                self.filesDropped.emit(paths)
                e.acceptProposedAction()
                return
        super().dropEvent(e)


class MainWindow(QMainWindow):
    def __init__(self, loop):
        super().__init__()
        self.loop = loop
        self.store = ListStore()
        self.file_lines: dict = {}
        self.entries: list = []
        self.checker: Checker | None = None
        self.task = None
        self.running = False
        self._phase = ""
        self._pending: list = []
        self._done = self._total = self._live = self._dead = 0
        self._t0 = time.monotonic()

        self.model = ResultsModel(self.store)
        self.proxy = ResultsFilter(self.model)

        self.setWindowTitle(f"Proxy Toolkit {__version__}")
        self.resize(1440, 840)
        self.setAcceptDrops(True)
        self._build_ui()

        self._flush_timer = QTimer(self)
        self._flush_timer.setInterval(200)
        self._flush_timer.timeout.connect(self._flush)
        self._summary_timer = QTimer(self)
        self._summary_timer.setSingleShot(True)
        self._summary_timer.setInterval(400)
        self._summary_timer.timeout.connect(self._update_summary)
        self._update_summary()

    # ------------------------------------------------------------ UI build
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self._build_left())
        split.addWidget(self._build_right())
        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 1)
        split.setSizes([self._left_width, 1040])
        self.server_tab = ServerTab(self)
        # one switch, two places: keep both checkboxes in sync
        self.cb_pool_auto.setChecked(self.server_tab.cb_auto.isChecked())
        self.cb_pool_auto.toggled.connect(self.server_tab.cb_auto.setChecked)
        self.server_tab.cb_auto.toggled.connect(self.cb_pool_auto.setChecked)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        # Tabs look like buttons; the active one is filled with the accent colour (palette-based,
        # so it follows the light / dark system theme).
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border-top: 2px solid palette(highlight); }
            QTabBar::tab {
                min-width: 190px; padding: 10px 22px; margin: 4px 8px 6px 0px;
                border: 1px solid palette(mid); border-radius: 7px;
                background: palette(button); color: palette(button-text);
            }
            QTabBar::tab:hover:!selected {
                background: palette(midlight); border: 1px solid palette(highlight);
            }
            QTabBar::tab:selected {
                background: palette(highlight); color: palette(highlighted-text);
                border: 1px solid palette(highlight); font-weight: bold;
            }
        """)
        self.tabs.addTab(split, "1 · Proxy Checker")
        self.tabs.addTab(self.server_tab, "2 · Proxy Rotation / Chain")
        self.tabs.setTabToolTip(0, "Check proxies: live / dead, speed, anonymity, country")
        self.tabs.setTabToolTip(1, "Use the live proxies: local proxy server, rotation, chains, Change IP")
        self.tabs.tabBar().setCursor(Qt.CursorShape.PointingHandCursor)
        self.tabs.currentChanged.connect(self._tab_changed)
        self._tab_changed(self.tabs.currentIndex())
        root.addWidget(self.tabs, 1)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumHeight(110)
        self.log_view.setMaximumBlockCount(2000)
        root.addWidget(self.log_view)

        menu = self.menuBar().addMenu("&Lists")
        for text, fn in (("Clear favourites", self._clear_favs),
                         ("Clear blacklist", self._clear_black),
                         ("Open config folder", self._open_config)):
            act = QAction(text, self)
            act.triggered.connect(fn)
            menu.addAction(act)

    def _build_left(self) -> QWidget:
        w = QWidget()
        w.setMinimumWidth(380)
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)

        # Input + settings live in a scroll area so the window can shrink on small screens;
        # Start / Stop / progress stay pinned at the bottom.
        inner = QWidget()
        ilay = QVBoxLayout(inner)
        ilay.setContentsMargins(0, 0, 6, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)   # never silently cut
        scroll.setWidget(inner)
        lay.addWidget(scroll, 1)

        # --- input
        gb = QGroupBox("1 · Proxies  (drop files anywhere · Browse · or paste)")
        g = QVBoxLayout(gb)
        self.text = DropPlainTextEdit()
        self.text.setPlaceholderText(
            "Paste proxies here, one per line:\n"
            "  1.2.3.4:8080\n  socks5://1.2.3.4:1080\n  user:pass@1.2.3.4:3128\n\n"
            "…or drop .txt files onto this box / window.\n"
            "No scheme = protocol is auto-detected (http / socks5 / socks4).")
        self.text.setMinimumHeight(130)
        self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)   # one proxy = one line
        self.text.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.text.filesDropped.connect(self.add_files)
        self.text.textChanged.connect(self._schedule_summary)
        g.addWidget(self.text, 1)

        row = QHBoxLayout()
        b_browse = QPushButton("Browse files…")
        b_browse.clicked.connect(self.browse)
        b_clear_text = QPushButton("Clear text")
        b_clear_text.clicked.connect(self.text.clear)
        b_paste = QPushButton("Paste")
        b_paste.setToolTip("Append the clipboard contents (one proxy per line)")
        b_paste.clicked.connect(self.paste_clipboard)
        row.addWidget(b_browse)
        row.addWidget(b_paste)
        row.addWidget(b_clear_text)
        g.addLayout(row)

        # The loaded-files list only takes space once a file has been added.
        self.file_panel = QWidget()
        fl = QVBoxLayout(self.file_panel)
        fl.setContentsMargins(0, 0, 0, 0)
        self.file_list = QListWidget()
        self.file_list.setMaximumHeight(70)
        self.file_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        fl.addWidget(self.file_list)
        row2 = QHBoxLayout()
        b_rm = QPushButton("Remove selected file")
        b_rm.clicked.connect(self.remove_files)
        b_clr = QPushButton("Clear files")
        b_clr.clicked.connect(self.clear_files)
        row2.addWidget(b_rm)
        row2.addWidget(b_clr)
        fl.addLayout(row2)
        self.file_panel.setVisible(False)
        g.addWidget(self.file_panel)

        self.lbl_summary = QLabel()
        self.lbl_summary.setWordWrap(True)
        g.addWidget(self.lbl_summary)
        ilay.addWidget(gb, 1)

        # --- settings
        self.gb_settings = QGroupBox("2 · Settings")
        form = QFormLayout(self.gb_settings)
        self.sp_timeout = QDoubleSpinBox()
        self.sp_timeout.setRange(2, 60)
        self.sp_timeout.setValue(10)
        self.sp_timeout.setSuffix(" s")
        self.sp_conc = QSpinBox()
        self.sp_conc.setRange(1, 1000)
        self.sp_conc.setValue(100)
        self.sp_rounds = QSpinBox()
        self.sp_rounds.setRange(1, 10)
        self.sp_rounds.setValue(3)
        self.sp_rounds.setToolTip("How many times a live proxy is tested (stability score).")
        form.addRow("Timeout", self.sp_timeout)
        form.addRow("Parallel checks", self.sp_conc)
        form.addRow("Stability rounds", self.sp_rounds)

        self.cb_ipify = QCheckBox("ipify")
        self.cb_cf = QCheckBox("Cloudflare")
        self.cb_google = QCheckBox("Google")
        for cb in (self.cb_ipify, self.cb_cf, self.cb_google):
            cb.setChecked(True)
        trow = QHBoxLayout()
        for cb in (self.cb_ipify, self.cb_cf, self.cb_google):
            trow.addWidget(cb)
        trow.addStretch(1)
        form.addRow("Test targets", trow)
        self.ed_custom = QLineEdit()
        self.ed_custom.setPlaceholderText("optional extra URL, e.g. https://example.com")
        form.addRow("Custom target", self.ed_custom)

        self.cb_anon = QCheckBox("Anonymity level (transparent / anonymous / elite)")
        self.cb_auto = QCheckBox("Auto-detect protocol when no scheme is given")
        self.cb_geo = QCheckBox("Country / city / ISP lookup (ip-api.com)")
        for cb in (self.cb_anon, self.cb_auto, self.cb_geo):
            cb.setChecked(True)
            form.addRow(cb)
        self.cb_pool_auto = QCheckBox("Add live proxies to the rotation pool automatically")
        self.cb_pool_auto.setChecked(True)
        self.cb_pool_auto.setToolTip("Same switch as on the Proxy Rotation tab.\n"
                                     "ON: live proxies of a finished check go straight into the rotation pool.")
        form.addRow(self.cb_pool_auto)
        ilay.addWidget(self.gb_settings)

        # --- run controls
        row3 = QHBoxLayout()
        self.btn_start = QPushButton("▶  Start check")
        self.btn_start.setMinimumHeight(36)
        self.btn_start.clicked.connect(self.start_check)
        self.btn_stop = QPushButton("■  Stop")
        self.btn_stop.setMinimumHeight(36)
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_check)
        row3.addWidget(self.btn_start, 2)
        row3.addWidget(self.btn_stop, 1)
        lay.addLayout(row3)

        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        lay.addWidget(self.progress)
        self.lbl_stats = QLabel("Idle")
        self.lbl_stats.setWordWrap(True)
        lay.addWidget(self.lbl_stats)

        # The pane is always as wide as its content needs (depends on the font / display scaling),
        # so nothing is hidden behind the results panel.
        extent = scroll.style().pixelMetric(QStyle.PixelMetric.PM_ScrollBarExtent)
        need = inner.minimumSizeHint().width() + extent + 12
        w.setMinimumWidth(max(380, need))
        self._left_width = max(400, need)
        return w

    def _build_right(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)

        bar = QHBoxLayout()
        self.cmb_show = QComboBox()
        for label, _ in SHOW_MODES:
            self.cmb_show.addItem(label)
        self.cmb_show.currentIndexChanged.connect(self._filter_changed)
        self.ed_search = QLineEdit()
        self.ed_search.setPlaceholderText("Filter: country, IP, ISP, type, anonymity …")
        self.ed_search.setClearButtonEnabled(True)
        self.ed_search.textChanged.connect(self._filter_changed)
        b_fav = QPushButton("★ Favourite")
        b_fav.setToolTip("Toggle favourite for the selected rows")
        b_fav.clicked.connect(self._toggle_fav)
        b_black = QPushButton("⛔ Blacklist")
        b_black.setToolTip("Toggle blacklist for the selected rows (skipped in future checks)")
        b_black.clicked.connect(self._toggle_black)

        exp = QToolButton()
        exp.setText("Export ▾")
        exp.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        menu = QMenu(exp)
        for text, kind in (("JSON  (visible rows)…", "json"), ("CSV  (visible rows)…", "csv"),
                           ("TXT  (live proxy URLs)…", "txt"),
                           ("Per-country lists → folder…", "country")):
            act = menu.addAction(text)
            act.triggered.connect(lambda _=False, k=kind: self._export(k))
        exp.setMenu(menu)

        bar.addWidget(QLabel("Show:"))
        bar.addWidget(self.cmb_show)
        bar.addWidget(self.ed_search, 1)
        bar.addWidget(b_fav)
        bar.addWidget(b_black)
        bar.addWidget(exp)
        lay.addLayout(bar)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(24)
        self.table.setSortingEnabled(True)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        for i, (_, width) in enumerate(COLUMNS):
            self.table.setColumnWidth(i, width)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        lay.addWidget(self.table, 1)

        self.lbl_shown = QLabel("0 rows")
        lay.addWidget(self.lbl_shown)
        return w

    def _tab_changed(self, index: int):
        """Show which page is open in the window title as well."""
        name = self.tabs.tabText(index).split("· ", 1)[-1]
        self.setWindowTitle(f"Proxy Toolkit {__version__} — {name}")

    def probe_settings(self):
        """Settings the proxy server's health monitor uses (same target / real IP as the last check)."""
        ck = self.checker
        targets = [ck.ip_targets[0]] if ck else [IPIFY]
        cfg = CheckConfig(timeout=8.0, rounds=1, targets=targets, anonymity=False, autodetect=False)
        return cfg, (ck.my_ip if ck else None)

    # ------------------------------------------------------------ logging
    def log(self, msg: str) -> None:
        self.log_view.appendPlainText(f"[{datetime.now():%H:%M:%S}] {msg}")

    # ------------------------------------------------------------ input handling
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        paths = _local_paths(e.mimeData())
        if paths:
            self.add_files(paths)
            e.acceptProposedAction()

    def browse(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Select proxy list file(s)", str(Path.home()),
            "Text files (*.txt *.lst *.list *.csv);;All files (*)")
        if paths:
            self.add_files(paths)

    def add_files(self, paths):
        for p in paths:
            if not os.path.isfile(p) or p in self.file_lines:
                continue
            try:
                lines = read_lines(p)
            except OSError as e:
                self.log(f"Cannot read {p}: {e}")
                continue
            self.file_lines[p] = lines
            item = QListWidgetItem(f"{Path(p).name}   ({len(lines):,} lines)")
            item.setData(Qt.ItemDataRole.UserRole, p)
            item.setToolTip(p)
            self.file_list.addItem(item)
            self.log(f"Loaded {Path(p).name}: {len(lines):,} lines")
        self._update_summary()

    def paste_clipboard(self):
        clip = QGuiApplication.clipboard().text()
        if not clip.strip():
            self.log("Clipboard is empty")
            return
        if self.text.toPlainText().strip():
            self.text.appendPlainText(clip.rstrip("\n"))
        else:
            self.text.setPlainText(clip.rstrip("\n"))

    def remove_files(self):
        for item in self.file_list.selectedItems():
            self.file_lines.pop(item.data(Qt.ItemDataRole.UserRole), None)
            self.file_list.takeItem(self.file_list.row(item))
        self._update_summary()

    def clear_files(self):
        self.file_lines.clear()
        self.file_list.clear()
        self._update_summary()

    def _schedule_summary(self):
        self._summary_timer.start()

    def _update_summary(self):
        self.file_panel.setVisible(bool(self.file_lines))
        lines = [ln for ls in self.file_lines.values() for ln in ls]
        lines.extend(self.text.toPlainText().splitlines())
        rep = parse_lines(lines)
        self.entries = [e for e in rep.entries if not self.store.is_black(e.key)]
        blocked = len(rep.entries) - len(self.entries)
        parts = [f"<b>{len(self.entries):,}</b> to check"]
        if rep.duplicates:
            parts.append(f"{rep.duplicates:,} duplicates removed")
        if blocked:
            parts.append(f"{blocked:,} blacklisted skipped")
        if rep.invalid:
            sample = ", ".join(rep.invalid_samples[:2])
            parts.append(f"{rep.invalid:,} invalid lines (e.g. {sample})")
        self.lbl_summary.setText(" · ".join(parts))

    # ------------------------------------------------------------ run / stop
    def _build_config(self) -> CheckConfig:
        targets = []
        if self.cb_ipify.isChecked():
            targets.append(IPIFY)
        if self.cb_cf.isChecked():
            targets.append(CLOUDFLARE)
        if self.cb_google.isChecked():
            targets.append(GOOGLE)
        custom = self.ed_custom.text().strip()
        if custom:
            if not custom.startswith(("http://", "https://")):
                custom = "https://" + custom
            targets.append(Target("Custom", custom, "status"))
        return CheckConfig(timeout=self.sp_timeout.value(), concurrency=self.sp_conc.value(),
                           rounds=self.sp_rounds.value(), targets=targets,
                           anonymity=self.cb_anon.isChecked(),
                           autodetect=self.cb_auto.isChecked())

    def start_check(self):
        if self.running:
            return
        self._update_summary()
        if not self.entries:
            QMessageBox.information(
                self, "Nothing to check",
                "Add proxies first: drop a file, use Browse, or paste them into the text box.")
            return
        self.task = self.loop.create_task(self._run())

    def stop_check(self):
        if not self.running:
            return
        self.log("Stopping…")
        self.btn_stop.setEnabled(False)
        if self.checker:
            self.checker.stop()
        if self._phase == "prepare" and self.task:
            self.task.cancel()

    async def _run(self):
        entries = list(self.entries)
        cfg = self._build_config()
        self.model.clear()
        self._pending.clear()
        self._done, self._total, self._live, self._dead = 0, len(entries), 0, 0
        self._t0 = time.monotonic()
        self.checker = Checker(cfg)
        self._set_running(True)
        self._flush_timer.start()
        try:
            self.log(f"Starting: {len(entries):,} proxies · timeout {cfg.timeout:g}s · "
                     f"{cfg.concurrency} parallel · {cfg.rounds} round(s)")
            self._phase = "prepare"
            self.lbl_stats.setText("Detecting your real IP…")
            await self.checker.prepare()
            for note in self.checker.notes:
                self.log(note)

            self._phase = "check"
            await self.checker.run(entries, self._on_result, self._on_progress)
            self._flush()

            if self.cb_geo.isChecked() and not self.checker.is_stopped():
                self._phase = "geo"
                await self._geo()
            elapsed = time.monotonic() - self._t0
            state = "Stopped" if self.checker.is_stopped() else "Done"
            self.log(f"{state}: {self._live:,} live / {self._done:,} checked in {elapsed:.0f}s")
            self.server_tab.on_check_finished()
        except asyncio.CancelledError:
            self.log("Stopped.")
        except Exception as e:  # keep the UI usable whatever happens
            self.log(f"Error: {type(e).__name__}: {e}")
        finally:
            self._phase = ""
            self._flush_timer.stop()
            self._flush()
            self._set_running(False)

    async def _geo(self):
        ips = sorted({r.exit_ip for r in self.model.results if r.live and r.exit_ip})
        if not ips:
            return
        self.lbl_stats.setText(f"Looking up location of {len(ips):,} exit IPs…")
        self.log(f"Looking up {len(ips):,} exit IPs (ip-api.com)…")
        info = await geo.lookup(ips, self.checker.is_stopped, self.log)
        for r in self.model.results:
            i = info.get(r.exit_ip) if r.live else None
            if not i:
                continue
            r.country = i.get("country", "") or ""
            r.country_code = i.get("countryCode", "") or r.country_code
            r.city = i.get("city", "") or ""
            r.isp = i.get("isp", "") or ""
            r.net_type = "Datacenter" if i.get("hosting") else ("Mobile" if i.get("mobile") else "ISP")
        self.model.refresh()
        self.log(f"Location found for {len(info):,}/{len(ips):,} exit IPs")

    def _on_result(self, res):
        self._pending.append(res)
        if res.live:
            self._live += 1
        else:
            self._dead += 1

    def _on_progress(self, done, total):
        self._done, self._total = done, total

    def _flush(self):
        if self._pending:
            batch, self._pending = self._pending, []
            self.model.add_results(batch)
        if self._phase in ("check", ""):
            self.progress.setMaximum(max(self._total, 1))
            self.progress.setValue(self._done)
            if self._total:
                elapsed = max(time.monotonic() - self._t0, 0.001)
                self.lbl_stats.setText(
                    f"{self._done:,}/{self._total:,} checked · live {self._live:,} · "
                    f"dead {self._dead:,} · {self._done / elapsed:.1f}/s · {elapsed:.0f}s")
        self._update_shown()

    def _set_running(self, on: bool):
        self.running = on
        self.btn_start.setEnabled(not on)
        self.btn_stop.setEnabled(on)
        self.gb_settings.setEnabled(not on)

    # ------------------------------------------------------------ table actions
    def _filter_changed(self):
        self.proxy.set_mode(SHOW_MODES[self.cmb_show.currentIndex()][1])
        self.proxy.set_text(self.ed_search.text())
        self._update_shown()

    def _update_shown(self):
        self.lbl_shown.setText(f"{self.proxy.rowCount():,} shown / {self.model.rowCount():,} total")

    def _selected_rows(self) -> list:
        sel = self.table.selectionModel().selectedRows()
        return sorted({self.proxy.mapToSource(i).row() for i in sel})

    def _selected_results(self) -> list:
        return [self.model.results[r] for r in self._selected_rows()]

    def _toggle_fav(self):
        res = self._selected_results()
        if not res:
            return
        keys = {r.key for r in res}
        on = not all(self.store.is_fav(k) for k in keys)
        self.store.set_fav(keys, on)
        self.model.refresh()
        self._filter_changed()

    def _toggle_black(self):
        res = self._selected_results()
        if not res:
            return
        keys = {r.key for r in res}
        on = not all(self.store.is_black(k) for k in keys)
        self.store.set_black(keys, on)
        self.model.refresh()
        self._filter_changed()
        self._update_summary()
        self.log(f"{len(keys)} proxy(ies) {'blacklisted' if on else 'removed from blacklist'}")

    def _context_menu(self, pos):
        res = self._selected_results()
        if not res:
            return
        m = QMenu(self)
        m.addAction("★ Toggle favourite", self._toggle_fav)
        m.addAction("⛔ Toggle blacklist", self._toggle_black)
        m.addSeparator()
        m.addAction("⛓ Add to chain (Proxy Server tab)", lambda: self.server_tab.add_to_chain(res))
        m.addSeparator()
        m.addAction("Copy proxy URL(s)", lambda: QGuiApplication.clipboard().setText(
            "\n".join(r.url for r in res)))
        m.addAction("Copy host:port", lambda: QGuiApplication.clipboard().setText(
            "\n".join(r.address for r in res)))
        m.exec(self.table.viewport().mapToGlobal(pos))

    def _visible_results(self) -> list:
        out = []
        for row in range(self.proxy.rowCount()):
            src = self.proxy.mapToSource(self.proxy.index(row, 0)).row()
            out.append(self.model.results[src])
        return out

    def _export(self, kind: str):
        rows = self._visible_results()
        if not rows:
            QMessageBox.information(self, "Nothing to export", "No rows are visible in the table.")
            return
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        try:
            if kind == "country":
                folder = QFileDialog.getExistingDirectory(
                    self, "Folder for per-country lists", str(Path.home()))
                if not folder:
                    return
                n = export.export_by_country(rows, folder)
                self.log(f"Wrote {n} files to {folder}")
                return
            ext, flt, fn = {
                "json": ("json", "JSON (*.json)", export.export_json),
                "csv": ("csv", "CSV (*.csv)", export.export_csv),
                "txt": ("txt", "Text (*.txt)", export.export_txt),
            }[kind]
            path, _ = QFileDialog.getSaveFileName(
                self, "Export", str(Path.home() / f"proxies-{stamp}.{ext}"), flt)
            if not path:
                return
            n = fn(rows, path)
            self.log(f"Exported {n:,} rows → {path}")
        except OSError as e:
            QMessageBox.warning(self, "Export failed", str(e))

    # ------------------------------------------------------------ menu actions
    def _clear_favs(self):
        self.store.clear_favourites()
        self.model.refresh()
        self._filter_changed()

    def _clear_black(self):
        self.store.clear_blacklist()
        self.model.refresh()
        self._filter_changed()
        self._update_summary()

    def _open_config(self):
        d = config_dir()
        d.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(d)))

    def closeEvent(self, e):
        self.server_tab.shutdown()
        if self.checker:
            self.checker.stop()
        if self.task and not self.task.done():
            self.task.cancel()
        super().closeEvent(e)
