"""'Auto-fetch from URL' panel: a list of proxy-list URLs with an optional refresh interval."""
from __future__ import annotations

import time

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QMessageBox, QPushButton, QSpinBox, QVBoxLayout,
)

from core.sources import MIN_INTERVAL_MIN, Source, SourceStore


def _ago(ts: float) -> str:
    if not ts:
        return "never fetched"
    sec = max(0, int(time.time() - ts))
    if sec < 90:
        return "just now"
    if sec < 5400:
        return f"{sec // 60} min ago"
    if sec < 172800:
        return f"{sec // 3600} h ago"
    return f"{sec // 86400} days ago"


class SourcesPanel(QGroupBox):
    """Edits the SourceStore; the Rotation tab does the downloading / checking."""
    fetchRequested = pyqtSignal(list)            # list[Source] to download + check now

    def __init__(self, store: SourceStore):
        super().__init__("Auto-fetch from URL")
        self.store = store
        lay = QVBoxLayout(self)

        self.listw = QListWidget()
        self.listw.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.listw.setMinimumHeight(70)
        self.listw.setMaximumHeight(120)
        self.listw.setToolTip("Tick = included in auto-refresh and “Fetch all now”.\n"
                              "Lists are downloaded directly from this computer (your real IP).")
        self.listw.itemChanged.connect(self._item_changed)
        lay.addWidget(self.listw)

        row = QHBoxLayout()
        self.ed_url = QLineEdit()
        self.ed_url.setPlaceholderText("https://…/proxies.txt   (one proxy per line)")
        self.ed_url.returnPressed.connect(self._add)
        self.sp_every = QSpinBox()
        self.sp_every.setRange(0, 10080)
        self.sp_every.setSpecialValueText("manual")
        self.sp_every.setPrefix("every ")
        self.sp_every.setSuffix(" min")
        self.sp_every.setValue(60)
        self.sp_every.setToolTip(f"“manual” = only when you press Fetch.\n"
                                 f"Otherwise the list is downloaded, checked and added to the pool\n"
                                 f"automatically (minimum {MIN_INTERVAL_MIN} minutes).")
        b_add = QPushButton("Add")
        b_add.clicked.connect(self._add)
        row.addWidget(self.ed_url, 1)
        row.addWidget(self.sp_every)
        row.addWidget(b_add)
        lay.addLayout(row)

        row2 = QHBoxLayout()
        self.btn_fetch = QPushButton("Fetch now")
        self.btn_fetch.setToolTip("Download + check the selected lists (all ticked lists when nothing is selected)")
        self.btn_fetch.clicked.connect(self._fetch_clicked)
        b_rm = QPushButton("Remove")
        b_rm.clicked.connect(self._remove)
        row2.addWidget(self.btn_fetch)
        row2.addWidget(b_rm)
        row2.addStretch(1)
        lay.addLayout(row2)
        self.lbl = QLabel("Only verified live proxies are added to the pool.")
        self.lbl.setWordWrap(True)
        lay.addWidget(self.lbl)
        self.refresh()

    # ------------------------------------------------------------ view
    @staticmethod
    def _text(src: Source) -> str:
        every = f"every {src.interval_min} min" if src.interval_min else "manual"
        status = src.last_status or "not fetched yet"
        return f"{src.url}\n    {every} · {status} · {_ago(src.last_fetch)}"

    def refresh(self) -> None:
        selected = {i.data(Qt.ItemDataRole.UserRole) for i in self.listw.selectedItems()}
        self.listw.blockSignals(True)
        self.listw.clear()
        for src in self.store.sources:
            item = QListWidgetItem(self._text(src))
            item.setData(Qt.ItemDataRole.UserRole, src.url)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if src.enabled else Qt.CheckState.Unchecked)
            item.setToolTip(src.url)
            self.listw.addItem(item)
            if src.url in selected:
                item.setSelected(True)
        self.listw.blockSignals(False)

    # ------------------------------------------------------------ actions
    def _item_changed(self, item: QListWidgetItem) -> None:
        src = self.store.find(item.data(Qt.ItemDataRole.UserRole))
        if src:
            src.enabled = item.checkState() == Qt.CheckState.Checked
            self.store.save()

    def _add(self) -> None:
        try:
            self.store.add(self.ed_url.text(), self.sp_every.value())
        except ValueError as e:
            QMessageBox.warning(self, "Cannot add this URL", str(e))
            return
        self.ed_url.clear()
        self.refresh()
        self.lbl.setText("Added. Press “Fetch now” to download and check it.")

    def _remove(self) -> None:
        for item in self.listw.selectedItems():
            self.store.remove(item.data(Qt.ItemDataRole.UserRole))
        self.refresh()

    def selected_sources(self) -> list:
        urls = [i.data(Qt.ItemDataRole.UserRole) for i in self.listw.selectedItems()]
        if urls:
            return [s for s in (self.store.find(u) for u in urls) if s]
        return [s for s in self.store.sources if s.enabled]

    def _fetch_clicked(self) -> None:
        srcs = self.selected_sources()
        if not srcs:
            QMessageBox.information(self, "Nothing to fetch",
                                    "Add a URL first (or tick at least one list).")
            return
        self.fetchRequested.emit(srcs)

    def set_busy(self, busy: bool) -> None:
        self.btn_fetch.setEnabled(not busy)
