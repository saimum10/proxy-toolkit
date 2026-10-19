#!/usr/bin/env python3
"""Proxy Toolkit - entry point."""
import asyncio
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_API", "pyqt6")


def raise_nofile_limit() -> None:
    """Thousands of parallel checks need many sockets; lift the soft fd limit."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = 65536 if hard == resource.RLIM_INFINITY else min(hard, 65536)
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        pass


def main() -> int:
    raise_nofile_limit()

    from PyQt6.QtGui import QIcon
    from PyQt6.QtWidgets import QApplication
    import qasync

    from gui.main_window import MainWindow
    from core.version import __version__

    app = QApplication(sys.argv)
    app.setApplicationName("proxy-toolkit")          # also the X11 window class (StartupWMClass)
    app.setApplicationDisplayName("Proxy Toolkit")
    app.setApplicationVersion(__version__)
    app.setDesktopFileName("proxy-toolkit")          # Wayland: links the window to proxy-toolkit.desktop
    app.setStyle("Fusion")

    icon_dir = Path(__file__).resolve().parent / "assets"
    icon = QIcon()
    for size in (32, 48, 64, 128, 256):
        path = icon_dir / "icons" / f"{size}.png"
        if path.exists():
            icon.addFile(str(path))
    if (icon_dir / "icon.png").exists():
        icon.addFile(str(icon_dir / "icon.png"))
    if not icon.isNull():
        app.setWindowIcon(icon)

    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)
    closed = asyncio.Event()
    app.aboutToQuit.connect(closed.set)

    win = MainWindow(loop)
    win.show()

    with loop:
        loop.run_until_complete(closed.wait())
    return 0


if __name__ == "__main__":
    sys.exit(main())
