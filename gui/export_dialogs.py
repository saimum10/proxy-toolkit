"""Dialogs for the proxychains.conf / PAC exports (used by the Checker and the Rotation tab)."""
from __future__ import annotations

from pathlib import Path

from PyQt6.QtWidgets import QFileDialog, QInputDialog, QMessageBox

from core import export


def _ask_chain(parent, n: int):
    """Chain type (+ length for random_chain). None = cancelled."""
    labels = [label for _, label in export.PROXYCHAINS_TYPES]
    keys = [key for key, _ in export.PROXYCHAINS_TYPES]
    # "dynamic/strict_chain" chain EVERY listed proxy: fine for a few, useless for a big list
    default = keys.index("random_chain") if n > 5 else keys.index("dynamic_chain")
    label, ok = QInputDialog.getItem(
        parent, "proxychains chain type",
        f"{n:,} proxies will be written.\n"
        "Big lists need random_chain, otherwise proxychains would chain all of them.",
        labels, default, False)
    if not ok:
        return None
    chain = keys[labels.index(label)]
    chain_len = 1
    if chain == "random_chain":
        chain_len, ok = QInputDialog.getInt(
            parent, "random_chain length",
            "Proxies per connection (1 = plain rotation, 2+ = chained):", 1, 1, 10)
        if not ok:
            return None
    return chain, chain_len


_LINKS_NOTE = ("V2Ray links (tab 3) run on a local engine port that only exists while this app is "
               "running, so they cannot be written into such a file. To use them from other programs, export "
               "the file “for this local server” (Rotation tab ▸ Export ▾): the server rotates over them.")


def _split_links(results):
    live = [r for r in results if r.live]
    return [r for r in live if not r.link], sum(1 for r in live if r.link)


def save_proxychains(parent, results, log) -> None:
    """proxychains.conf from the live proxies in `results`."""
    live, n_links = _split_links(results)
    if not live:
        QMessageBox.information(parent, "Nothing to export",
                                _LINKS_NOTE if n_links else "There are no live proxies to export.")
        return
    opts = _ask_chain(parent, len(live))
    if not opts:
        return
    path, _ = QFileDialog.getSaveFileName(
        parent, "Save proxychains config", str(Path.home() / "proxychains.conf"),
        "proxychains config (*.conf);;All files (*)")
    if not path:
        return
    try:
        written, skipped = export.export_proxychains(live, path, opts[0], opts[1])
    except (OSError, ValueError) as e:
        QMessageBox.warning(parent, "Export failed", str(e))
        return
    note = (f" · {skipped:,} skipped (proxychains needs IPv4 addresses and http / socks4 / socks5; "
            "https proxies and passwords with spaces cannot be written)") if skipped else ""
    note += f" · {n_links:,} V2Ray link(s) left out" if n_links else ""
    log(f"proxychains config: {written:,} proxies → {path}{note}")
    if skipped or n_links:
        QMessageBox.information(parent, "proxychains export",
                                f"{written:,} proxies written, {skipped + n_links:,} left out.\n\n"
                                + (f"{skipped:,}: proxychains only supports http / socks4 / socks5 proxies with a "
                                   "literal IPv4 address (https proxies, hostnames, IPv6 and passwords with "
                                   "spaces are left out).\n\n" if skipped else "")
                                + (_LINKS_NOTE if n_links else ""))


def save_pac(parent, results, log) -> None:
    """PAC file with the best live proxies (fail-over list)."""
    live, n_links = _split_links(results)
    if not live:
        QMessageBox.information(parent, "Nothing to export",
                                _LINKS_NOTE if n_links else "There are no live proxies to export.")
        return
    limit, ok = QInputDialog.getInt(
        parent, "PAC file",
        "How many proxies to include (best first)?\n"
        "The browser tries them in this order and moves on when one fails.",
        min(10, len(live)), 1, 200)
    if not ok:
        return
    path, _ = QFileDialog.getSaveFileName(
        parent, "Save PAC file", str(Path.home() / "proxies.pac"), "PAC file (*.pac);;All files (*)")
    if not path:
        return
    try:
        written, skipped = export.export_pac(live, path, limit)
    except OSError as e:
        QMessageBox.warning(parent, "Export failed", str(e))
        return
    log(f"PAC file: {written:,} proxies → {path}"
        + (f" · {skipped:,} with username / password skipped (browsers cannot send them from a PAC)"
           if skipped else "")
        + (f" · {n_links:,} V2Ray link(s) left out" if n_links else ""))
    if not written:
        QMessageBox.information(parent, "PAC export",
                                "Nothing was written: every live proxy needs a username / password, "
                                "which a PAC file cannot carry.")
    elif n_links:
        QMessageBox.information(parent, "PAC export", f"{written:,} proxies written.\n\n" + _LINKS_NOTE)


def save_local_proxychains(parent, host: str, port: int, log) -> None:
    path, _ = QFileDialog.getSaveFileName(
        parent, "Save proxychains config for the local server", str(Path.home() / "proxychains-toolkit.conf"),
        "proxychains config (*.conf);;All files (*)")
    if not path:
        return
    try:
        export.export_proxychains_local(path, host, port)
    except OSError as e:
        QMessageBox.warning(parent, "Export failed", str(e))
        return
    log(f"proxychains config for the local server (socks5 {host or '127.0.0.1'}:{port}) → {path}")


def save_local_pac(parent, host: str, port: int, log) -> None:
    path, _ = QFileDialog.getSaveFileName(
        parent, "Save PAC file for the local server", str(Path.home() / "proxy-toolkit.pac"),
        "PAC file (*.pac);;All files (*)")
    if not path:
        return
    try:
        export.export_pac_local(path, host, port)
    except OSError as e:
        QMessageBox.warning(parent, "Export failed", str(e))
        return
    log(f"PAC file for the local server ({host or '127.0.0.1'}:{port}) → {path}")
