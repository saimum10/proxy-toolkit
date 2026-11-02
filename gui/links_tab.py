"""Tab 3 - V2Ray Links: ss:// vmess:// vless:// trojan:// links -> check -> rotation pool.

The links are run by an engine (Xray-core, see core/engine.py) that exposes each of them as a
local SOCKS5 proxy. From there on they are ordinary proxies: the normal Checker measures them
(latency, exit IP, country, score) and the live ones can be added to the rotation pool, where
every mode, chain, Change IP, auto-rotate ... works unchanged.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFontDatabase, QGuiApplication
from PyQt6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QFrame, QGroupBox, QHBoxLayout, QLabel,
    QLineEdit, QMenu, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QScrollArea, QSplitter,
    QStyle, QTableView, QVBoxLayout, QWidget,
)

from core import engine, geo
from core.checker import Checker
from core.links import LinksReport, expand_subscription, parse_links
from core.models import ProxyEntry, ProxyResult
from core.sources import fetch_lines
from core.store import config_dir

from .results_model import COLUMNS, ResultsFilter, ResultsModel

SHOW_MODES = [("All", "all"), ("Live only", "live"), ("Dead only", "dead"), ("★ Favourites", "fav")]
WARNING = ("⚠ Free public configs: the operator of such a server can see - and for links without "
           "encryption also change - your traffic. Do not log in to accounts you care about.")


class LinksTab(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        self.loop = main.loop
        self.model = ResultsModel(main.store)
        self.proxy = ResultsFilter(self.model)
        self.group = engine.EngineGroup()
        self._exec = ThreadPoolExecutor(max_workers=1, thread_name_prefix="engine")
        self.report = LinksReport()
        self.running = False
        self._starting = False
        self._stop = False
        self.task = None
        self.checker = None
        self._phase = ""
        self._pending: list = []
        self._done = self._total = self._live = self._dead = 0
        self._base = 0                    # rows that were already "done" before the checker started
        self._t0 = time.monotonic()
        self._engine_task = None
        self._detect_task = None
        self._settings_path = config_dir() / "links.json"
        self._settings = self._load_settings()

        self._build()
        self._flush_timer = QTimer(self)
        self._flush_timer.setInterval(200)
        self._flush_timer.timeout.connect(self._flush)
        self._summary_timer = QTimer(self)
        self._summary_timer.setSingleShot(True)
        self._summary_timer.setInterval(400)
        self._summary_timer.timeout.connect(self._update_summary)
        self._tick_timer = QTimer(self)
        self._tick_timer.setInterval(3000)
        self._tick_timer.timeout.connect(self._tick)
        self._tick_timer.start()
        QTimer.singleShot(0, self._detect_engine)

    # ------------------------------------------------------------ settings
    def _load_settings(self) -> dict:
        try:
            return json.loads(self._settings_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save_settings(self) -> None:
        self._settings = {"engine_path": self.ed_engine.text().strip(), "auto_add": self.cb_auto.isChecked()}
        try:
            self._settings_path.parent.mkdir(parents=True, exist_ok=True)
            self._settings_path.write_text(json.dumps(self._settings, indent=2), encoding="utf-8")
        except OSError:
            pass

    # ------------------------------------------------------------ UI
    def _build(self) -> None:
        root = QVBoxLayout(self)
        split = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(split)
        split.addWidget(self._build_left())
        split.addWidget(self._build_right())
        split.setStretchFactor(1, 1)
        split.setSizes([self._left_width, 1000])

    def _build_left(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        inner = QWidget()
        ilay = QVBoxLayout(inner)
        ilay.setContentsMargins(0, 0, 6, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(inner)
        lay.addWidget(scroll, 1)

        # --- engine
        gb = QGroupBox("1 · Engine  (Xray-core)")
        g = QVBoxLayout(gb)
        self.lbl_engine = QLabel("Looking for Xray-core…")
        self.lbl_engine.setWordWrap(True)
        g.addWidget(self.lbl_engine)
        self.ed_engine = QLineEdit(self._settings.get("engine_path", ""))
        self.ed_engine.setPlaceholderText("auto-detect, or the path of the xray binary")
        self.ed_engine.editingFinished.connect(self._engine_path_changed)
        g.addWidget(self.ed_engine)
        row = QHBoxLayout()
        b_browse = QPushButton("Browse…")
        b_browse.clicked.connect(self._browse_engine)
        self.btn_download = QPushButton("Download Xray")
        self.btn_download.setToolTip("Downloads the newest Xray-core from github.com/XTLS/Xray-core into the app's\n"
                                     "config folder (the zip is verified against its published SHA-256).")
        self.btn_download.clicked.connect(self._download_engine)
        b_detect = QPushButton("Re-detect")
        b_detect.clicked.connect(self._detect_engine)
        for b in (b_browse, self.btn_download, b_detect):
            row.addWidget(b)
        g.addLayout(row)
        ilay.addWidget(gb)

        # --- links
        gb = QGroupBox("2 · Links  (paste · Browse · subscription URL)")
        g = QVBoxLayout(gb)
        self.text = QPlainTextEdit()
        self.text.setPlaceholderText(
            "Paste links, one per line:\n  vless://…   vmess://…\n  trojan://…  ss://…\n\n"
            "A base64 subscription text works too.\nPlain  ip:port  lines belong on the Proxy Checker tab.")
        self.text.setMinimumHeight(130)
        self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.text.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.text.textChanged.connect(lambda: self._summary_timer.start())
        g.addWidget(self.text, 1)
        row = QHBoxLayout()
        for label, fn in (("Paste", self._paste), ("Browse file…", self._browse_links), ("Clear", self.text.clear)):
            b = QPushButton(label)
            b.clicked.connect(fn)
            row.addWidget(b)
        g.addLayout(row)
        row = QHBoxLayout()
        self.ed_url = QLineEdit()
        self.ed_url.setPlaceholderText("subscription URL (optional)")
        self.ed_url.returnPressed.connect(self._fetch_url)
        self.btn_fetch = QPushButton("Fetch")
        self.btn_fetch.setToolTip("Download the list now (directly from this computer, not through a proxy)")
        self.btn_fetch.clicked.connect(self._fetch_url)
        row.addWidget(self.ed_url, 1)
        row.addWidget(self.btn_fetch)
        g.addLayout(row)
        self.lbl_summary = QLabel()
        self.lbl_summary.setWordWrap(True)
        g.addWidget(self.lbl_summary)
        ilay.addWidget(gb, 1)

        # --- options
        gb = QGroupBox("3 · Check")
        g = QVBoxLayout(gb)
        note = QLabel("Uses the settings of the Proxy Checker tab (timeout, parallel checks, rounds, "
                      "test targets, country lookup).")
        note.setWordWrap(True)
        g.addWidget(note)
        self.cb_auto = QCheckBox("Add live links to the rotation pool automatically")
        self.cb_auto.setChecked(bool(self._settings.get("auto_add", True)))
        self.cb_auto.toggled.connect(lambda _=False: self._save_settings())
        g.addWidget(self.cb_auto)
        warn = QLabel(WARNING)
        warn.setWordWrap(True)
        warn.setStyleSheet("color: #c27c0e;")
        g.addWidget(warn)
        ilay.addWidget(gb)

        row = QHBoxLayout()
        self.btn_start = QPushButton("▶  Check links")
        self.btn_start.setMinimumHeight(36)
        self.btn_start.clicked.connect(self.start_check)
        self.btn_stop = QPushButton("■  Stop")
        self.btn_stop.setMinimumHeight(36)
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_check)
        row.addWidget(self.btn_start, 2)
        row.addWidget(self.btn_stop, 1)
        lay.addLayout(row)
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        lay.addWidget(self.progress)
        self.lbl_stats = QLabel("Idle")
        self.lbl_stats.setWordWrap(True)
        lay.addWidget(self.lbl_stats)

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
        self.ed_search.setPlaceholderText("Filter: name, server, type, country …")
        self.ed_search.setClearButtonEnabled(True)
        self.ed_search.textChanged.connect(self._filter_changed)
        b_pool = QPushButton("＋ Add live to pool")
        b_pool.setToolTip("Add every live link in the table to the rotation pool")
        b_pool.clicked.connect(lambda: self._add_to_pool(self._all_live()))
        b_sel = QPushButton("＋ Add selected")
        b_sel.clicked.connect(lambda: self._add_to_pool(self._selected_results()))
        b_exp = QPushButton("Export links…")
        b_exp.setToolTip("Save the live links (the original share links) to a text file")
        b_exp.clicked.connect(self._export_links)
        bar.addWidget(QLabel("Show:"))
        bar.addWidget(self.cmb_show)
        bar.addWidget(self.ed_search, 1)
        bar.addWidget(b_pool)
        bar.addWidget(b_sel)
        bar.addWidget(b_exp)
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
        self.table.setColumnWidth(2, 300)            # "Proxy": server + the link's name
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        lay.addWidget(self.table, 1)

        row = QHBoxLayout()
        self.lbl_shown = QLabel("0 rows")
        self.lbl_engines = QLabel("")
        row.addWidget(self.lbl_shown)
        row.addStretch(1)
        row.addWidget(self.lbl_engines)
        lay.addLayout(row)
        return w

    # ------------------------------------------------------------ engine
    def _engine_path_changed(self) -> None:
        self._save_settings()
        self._detect_engine()

    def _browse_engine(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select the xray binary", str(Path.home()))
        if path:
            self.ed_engine.setText(path)
            self._engine_path_changed()

    def _detect_engine(self) -> None:
        if self._detect_task is not None and not self._detect_task.done():
            self._detect_task.cancel()
        self._detect_task = self.loop.create_task(self._detect_engine_async())

    async def _detect_engine_async(self) -> None:
        binary = engine.find_binary(self.ed_engine.text())
        if binary is None:
            self.lbl_engine.setText("✗ Xray-core not found.  Press “Download Xray”, or install it and "
                                    "point to the binary with “Browse…”.")
            self.lbl_engine.setStyleSheet("color: #c0392b;")
            return
        self.lbl_engine.setText(f"Checking {binary} …")
        self.lbl_engine.setStyleSheet("")
        ver = await self.loop.run_in_executor(None, engine.binary_version, binary)   # never blocks the window
        if not ver:
            self.lbl_engine.setText(f"✗ {binary} cannot be run here (wrong architecture or no permission).")
            self.lbl_engine.setStyleSheet("color: #c0392b;")
            return
        self.lbl_engine.setText(f"✓ {ver}\n{binary}")
        self.lbl_engine.setStyleSheet("color: #1e6f3a;")

    def _download_engine(self) -> None:
        if self._engine_task and not self._engine_task.done():
            return
        self._engine_task = self.loop.create_task(self._download_engine_async())

    async def _download_engine_async(self) -> None:
        self.btn_download.setEnabled(False)
        try:
            path = await engine.download_xray(progress=self.lbl_engine.setText)
            self.ed_engine.setText(str(path))
            self._save_settings()
            self.main.log(f"Xray-core installed: {path}")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.main.log(f"Xray download failed: {exc}")
            QMessageBox.warning(self, "Download failed", str(exc))
        finally:
            self.btn_download.setEnabled(True)
            self._detect_engine()

    # ------------------------------------------------------------ input
    def _paste(self) -> None:
        clip = QGuiApplication.clipboard().text()
        if clip.strip():
            self._append_lines(expand_subscription(clip.splitlines()))

    def _browse_links(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select a file with links", str(Path.home()),
                                              "Text files (*.txt *.lst *.list);;All files (*)")
        if not path:
            return
        try:
            data = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            self.main.log(f"Cannot read {path}: {exc}")
            return
        self._append_lines(expand_subscription(data))

    def _append_lines(self, lines: list) -> None:
        text = "\n".join(lines).strip("\n")
        if not text:
            return
        if self.text.toPlainText().strip():
            self.text.appendPlainText(text)
        else:
            self.text.setPlainText(text)

    def _fetch_url(self) -> None:
        url = self.ed_url.text().strip()
        if not url:
            return
        self.loop.create_task(self._fetch_url_async(url))

    async def _fetch_url_async(self, url: str) -> None:
        self.btn_fetch.setEnabled(False)
        self.lbl_summary.setText(f"Downloading {url} …")
        try:
            lines = await fetch_lines(url)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.lbl_summary.setText(f"Download failed: {exc}")
            self.main.log(f"[links] {url}: {exc}")
            return
        finally:
            self.btn_fetch.setEnabled(True)
        lines = expand_subscription(lines)
        self._append_lines(lines)
        self.main.log(f"[links] {url}: {len(lines):,} lines")

    def _update_summary(self) -> None:
        self.report = parse_links(self.text.toPlainText().splitlines())
        black = sum(1 for e in self.report.entries if self.main.store.is_black(e.key))
        by_kind: dict = {}
        for e in self.report.entries:
            by_kind[e.proto] = by_kind.get(e.proto, 0) + 1
        parts = [f"<b>{len(self.report.entries) - black:,}</b> links to check"]
        if by_kind:
            parts.append(", ".join(f"{n} {k}" for k, n in sorted(by_kind.items())))
        if self.report.duplicates:
            parts.append(f"{self.report.duplicates:,} duplicates removed")
        if black:
            parts.append(f"{black:,} blacklisted skipped")
        if self.report.errors:
            parts.append(f"{len(self.report.errors):,} unusable (e.g. {self.report.errors[0][1]})")
        if self.report.other:
            parts.append(f"{self.report.other:,} ordinary proxy line(s) ignored (use the Proxy Checker tab)")
        self.lbl_summary.setText(" · ".join(parts))
        self.lbl_summary.setToolTip("\n".join(f"{why}:  {line[:60]}" for line, why in self.report.errors[:12]))

    # ------------------------------------------------------------ run / stop
    def start_check(self) -> None:
        if self.running or self._starting:
            return
        self._update_summary()
        entries = [e for e in self.report.entries if not self.main.store.is_black(e.key)]
        if not entries and not self.report.errors:
            QMessageBox.information(self, "Nothing to check", "Paste some links first.")
            return
        binary = engine.find_binary(self.ed_engine.text())
        if binary is None:
            QMessageBox.information(self, "Engine needed",
                                    "V2Ray-style links need the Xray-core engine.\n\n"
                                    "Press “Download Xray” (or install it and use “Browse…”).")
            return
        self._starting = True
        self.task = self.loop.create_task(self._run(entries, list(self.report.errors), binary))

    def stop_check(self) -> None:
        if not self.running:
            return
        self._stop = True
        self.btn_stop.setEnabled(False)
        self.main.log("[links] stopping…")
        if self.checker:
            self.checker.stop()
        if self._phase in ("prepare",) and self.task:
            self.task.cancel()

    def _wanted_keys(self) -> set:
        """Links whose engine must keep running: the ones in the pool and the live ones in the table."""
        keys = {m.key for m in self.main.server_tab.pool.members()}
        keys.update(r.key for r in self.model.results if r.live)
        return keys

    @staticmethod
    def _dead_row(link: str, reason: str, e=None) -> ProxyResult:
        if e is not None:
            return ProxyResult(key=e.key, host="127.0.0.1", port=0, proto="socks5", url=e.raw, live=False,
                               error=reason, link=e.raw, kind=e.kind, label=e.label)
        return ProxyResult(key="bad:" + hashlib.sha1(link.encode()).hexdigest()[:10], host="", port=0,
                           proto="socks5", url=link, live=False, error=reason, link=link,
                           kind=link.split("://", 1)[0], label=link[:70])

    async def _run(self, entries: list, errors: list, binary: Path) -> None:
        mapping: dict = {}
        self._stop = False
        self.running = True
        self._set_buttons(True)
        if not await self.loop.run_in_executor(None, engine.binary_version, binary):
            self.running = self._starting = False
            self._set_buttons(False)
            QMessageBox.warning(self, "Engine problem",
                                f"{binary} cannot be run on this computer (wrong architecture or no permission).")
            return
        self.model.clear()
        self._pending.clear()
        self._done, self._total, self._live, self._dead = 0, len(entries), 0, 0
        self._t0 = time.monotonic()
        self._flush_timer.start()
        log = self.main.log
        try:
            # engines of an earlier check that nothing needs any more (links of THIS check that already
            # have a running engine keep it - they are reused below instead of started a second time)
            self.group.prune(self._wanted_keys() | {e.key for e in entries})
            for line, why in errors:
                self._pending.append(self._dead_row(line, why))
                self._dead += 1
            cfg = self.main._build_config()
            log(f"[links] checking {len(entries):,} links · timeout {cfg.timeout:g}s · {cfg.rounds} round(s)")

            self._phase = "engine"
            self.lbl_stats.setText(f"Starting the engine for {len(entries):,} links…")
            fresh = [e for e in entries if self.group.endpoint(e.key) is None]
            if len(fresh) < len(entries):
                log(f"[links] {len(entries) - len(fresh):,} link(s) already have a running engine - reused")
            launched, failures = await self.loop.run_in_executor(
                self._exec, lambda: engine.launch(
                    binary, fresh, log=lambda m: self.loop.call_soon_threadsafe(log, f"[links] {m}"),
                    should_stop=lambda: self._stop))
            self.group.add(launched)
            for e, why in failures:
                why = engine.explain_error(why)
                self._pending.append(self._dead_row(e.raw, why, e))
                self._dead += 1
            if failures:
                log(f"[links] {len(failures)} link(s) refused by the engine: "
                    + "; ".join(f"{e.remark or e.host} ({engine.explain_error(why)[:70]})" for e, why in failures[:3]))

            local = []
            for e in entries:
                ep = self.group.endpoint(e.key)
                if ep:
                    port, user, pw = ep
                    mapping[port] = e
                    local.append(ProxyEntry(host="127.0.0.1", port=port, scheme="socks5", user=user, password=pw))
            self._base = self._dead
            self._done = self._base
            self._total = len(entries) + len(errors)

            if local and not self._stop:
                self._phase = "prepare"
                self.checker = Checker(cfg)
                self.lbl_stats.setText("Detecting your real IP…")
                await self.checker.prepare()
                for note in self.checker.notes:
                    log(note)
                self._phase = "check"
                await self.checker.run(local, lambda r: self._on_result(r, mapping), self._on_progress)
                self._flush()
                if self.main.cb_geo.isChecked() and not self.checker.is_stopped():
                    self._phase = "geo"
                    await self._geo()
            state = "Stopped" if self._stop else "Done"
            log(f"[links] {state}: {self._live:,} live / {len(entries):,} links in "
                f"{time.monotonic() - self._t0:.0f}s")
            live = [r for r in self.model.results if r.live]
            if live and self.cb_auto.isChecked():        # also after Stop: keep what was already found
                self._add_to_pool(live)
        except asyncio.CancelledError:
            log("[links] stopped.")
        except engine.EngineUnavailable as exc:
            log(f"[links] engine problem: {exc}")
            QMessageBox.warning(self, "Engine problem", str(exc))
        except Exception as exc:
            log(f"[links] error: {type(exc).__name__}: {exc}")
        finally:
            self._phase = ""
            self._flush_timer.stop()
            self._flush()
            self.running = False
            self._starting = False
            self._set_buttons(False)
            self.group.prune(self._wanted_keys())      # engines that only host dead links are not needed
            self._tick()

    def _on_result(self, res, mapping: dict) -> None:
        e = mapping.get(res.port)
        if e is not None:
            # host / port / user / password stay = the LOCAL engine inbound (what the proxy server
            # connects to); everything the user sees describes the real link
            res.key = e.key
            res.link = res.url = e.raw
            res.kind = e.kind
            res.label = e.label
        self._pending.append(res)
        if res.live:
            self._live += 1
        else:
            self._dead += 1

    def _on_progress(self, done: int, total: int) -> None:
        self._done = self._base + done
        self._total = max(self._total, self._done)

    async def _geo(self) -> None:
        ips = sorted({r.exit_ip for r in self.model.results if r.live and r.exit_ip})
        if not ips:
            return
        self.lbl_stats.setText(f"Looking up location of {len(ips):,} exit IPs…")
        info = await geo.lookup(ips, self.checker.is_stopped, self.main.log)
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

    def _flush(self) -> None:
        if self._pending:
            batch, self._pending = self._pending, []
            self.model.add_results(batch)
        if self._phase in ("check", ""):
            self.progress.setMaximum(max(self._total, 1))
            self.progress.setValue(min(self._done, max(self._total, 1)))
            if self._total:
                self.lbl_stats.setText(f"{self.model.rowCount():,}/{self._total:,} · live {self._live:,} · "
                                       f"dead {self._dead:,} · {time.monotonic() - self._t0:.0f}s")
        self._update_shown()

    def _set_buttons(self, running: bool) -> None:
        self.btn_start.setEnabled(not running)
        self.btn_stop.setEnabled(running)

    # ------------------------------------------------------------ table
    def _filter_changed(self) -> None:
        self.proxy.set_mode(SHOW_MODES[self.cmb_show.currentIndex()][1])
        self.proxy.set_text(self.ed_search.text())
        self._update_shown()

    def _update_shown(self) -> None:
        self.lbl_shown.setText(f"{self.proxy.rowCount():,} shown / {self.model.rowCount():,} total")

    def refresh(self) -> None:
        """Favourites / blacklist changed elsewhere."""
        self.model.refresh()
        self._filter_changed()

    def _selected_results(self) -> list:
        sel = self.table.selectionModel().selectedRows()
        rows = sorted({self.proxy.mapToSource(i).row() for i in sel})
        return [self.model.results[r] for r in rows]

    def _all_live(self) -> list:
        return [r for r in self.model.results if r.live]

    def _add_to_pool(self, results: list) -> None:
        live = [r for r in results if r.live]
        if not live:
            self.main.log("[links] nothing live to add")
            return
        n = self.main.server_tab.add_links_results(live)
        self.main.log(f"[links] {n} new link(s) added to the rotation pool ({len(live)} live)")

    def _context_menu(self, pos) -> None:
        res = self._selected_results()
        if not res:
            return
        store = self.main.store
        m = QMenu(self)
        m.addAction("＋ Add to rotation pool", lambda: self._add_to_pool(res))
        all_fav = all(store.is_fav(r.key) for r in res)
        m.addAction("☆ Remove favourite" if all_fav else "★ Add to favourites",
                    lambda: self._set_fav(res, not all_fav))
        m.addAction("⛔ Blacklist", lambda: self.main.set_blacklist({r.key for r in res}, True))
        m.addSeparator()
        m.addAction("Copy link(s)", lambda: QGuiApplication.clipboard().setText("\n".join(r.link for r in res)))
        m.addAction("Copy server (host:port)", lambda: QGuiApplication.clipboard().setText(
            "\n".join(r.label.split("  ·  ")[0] for r in res)))
        m.exec(self.table.viewport().mapToGlobal(pos))

    def _set_fav(self, res: list, on: bool) -> None:
        self.main.store.set_fav({r.key for r in res}, on)
        self.main.favourites_changed()

    def _export_links(self) -> None:
        live = self._all_live()
        if not live:
            QMessageBox.information(self, "Nothing to export", "There are no live links.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export live links", str(Path.home() / f"links-{datetime.now():%Y%m%d-%H%M%S}.txt"),
            "Text (*.txt)")
        if not path:
            return
        try:
            Path(path).write_text("\n".join(r.link for r in live) + "\n", encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self, "Export failed", str(exc))
            return
        self.main.log(f"[links] exported {len(live):,} live links → {path}")

    # ------------------------------------------------------------ upkeep
    def _tick(self) -> None:
        n, links_n = self.group.process_count, self.group.link_count
        self.lbl_engines.setText(f"Engine: {n} process(es) · {links_n:,} link(s) running" if n else "Engine: idle")
        if self.running or self._starting:
            return                                       # never touch engines while a check uses them
        wanted = self._wanted_keys()
        for msg, keys in self.group.revive(wanted):
            self.main.log(f"[links] {msg}")
            # the health monitor marked these links down while their engine was dead and now backs off
            # (minutes): ask for an immediate re-test instead
            self.main.server_tab.pool.mark_due(keys)
        self.group.prune(wanted)

    def shutdown(self) -> None:
        self._tick_timer.stop()
        self._flush_timer.stop()
        self._stop = True
        if self.checker:
            self.checker.stop()
        for t in (self.task, self._engine_task, self._detect_task):
            if t is not None and not t.done():
                t.cancel()
        self.group.stop_all()
        self._exec.shutdown(wait=False, cancel_futures=True)
