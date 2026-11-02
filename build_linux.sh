#!/usr/bin/env bash
# Builds a SELF-CONTAINED Linux binary (dist/proxy-toolkit) and a .deb wrapping it.
# Run on Debian/Ubuntu, inside the proxy-toolkit folder:   ./build_linux.sh
# Tip: build on the OLDEST distro you want to support (binary needs glibc >= build machine).
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

VERSION="$(sed -n 's/^__version__ *= *"\(.*\)"/\1/p' core/version.py)"
[ -n "$VERSION" ] || { echo "Cannot read __version__ from core/version.py"; exit 1; }
ARCH="$(dpkg --print-architecture)"
OUT="dist/proxy-toolkit_${VERSION}_${ARCH}.deb"

command -v python3 >/dev/null || { echo "python3 missing"; exit 1; }
python3 -c "import venv, ensurepip" 2>/dev/null || { echo "Run: sudo apt install python3-venv"; exit 1; }

if [ "${SKIP_BUILD:-0}" != "1" ]; then
    echo "[1/3] Proxy Toolkit ${VERSION}: creating clean build venv + installing dependencies..."
    python3 -m venv .venv-build
    .venv-build/bin/pip install -q --upgrade pip
    .venv-build/bin/pip install -q -r requirements.txt pyinstaller

    echo "[2/3] Building single-file binary..."
    .venv-build/bin/pyinstaller --noconfirm --clean --onefile \
        --name proxy-toolkit \
        --add-data "assets:assets" \
        --collect-submodules aiohttp_socks \
        --collect-submodules python_socks \
        main.py
fi
[ -x dist/proxy-toolkit ] || { echo "dist/proxy-toolkit not found"; exit 1; }

echo "[3/3] Packaging .deb ..."
PKG="$(mktemp -d)"
trap 'rm -rf "$PKG"' EXIT
mkdir -p "$PKG/DEBIAN" "$PKG/usr/bin" "$PKG/usr/share/applications"

install -m 755 dist/proxy-toolkit "$PKG/usr/bin/proxy-toolkit"

for s in 32 48 64 128 256; do
    install -D -m 644 "assets/icons/$s.png" "$PKG/usr/share/icons/hicolor/${s}x${s}/apps/proxy-toolkit.png"
done
install -D -m 644 assets/icon.png "$PKG/usr/share/icons/hicolor/512x512/apps/proxy-toolkit.png"

cat > "$PKG/usr/share/applications/proxy-toolkit.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Proxy Toolkit
Comment=Proxy checker, rotator and chain tool
Exec=proxy-toolkit
Icon=proxy-toolkit
Terminal=false
Categories=Network;Utility;
StartupWMClass=proxy-toolkit
DESKTOP

# Qt6 (bundled in the binary) needs these system libs for the xcb platform plugin.
cat > "$PKG/DEBIAN/control" <<CONTROL
Package: proxy-toolkit
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: libc6, libgl1, libegl1, libxkbcommon-x11-0, libxcb-cursor0, libxcb-icccm4, libxcb-image0, libxcb-keysyms1, libxcb-render-util0, libxcb-shape0, libxcb-xkb1
Maintainer: Local Build <root@localhost>
Description: Proxy checker, rotator and chain tool
 Self-contained build: Python and all Python libraries are bundled.
CONTROL

dpkg-deb --root-owner-group --build "$PKG" "$OUT"

echo
echo "DONE."
echo "  Binary : dist/proxy-toolkit        (run directly: ./dist/proxy-toolkit)"
echo "  Package: $OUT   (install: sudo apt install ./$OUT)"
