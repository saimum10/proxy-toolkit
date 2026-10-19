#!/usr/bin/env bash
# Adds "Proxy Toolkit" (with its icon) to the applications menu - current user only.
set -e
DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
APPS="$HOME/.local/share/applications"
ICONS="$HOME/.local/share/icons/hicolor"
mkdir -p "$APPS"
chmod +x "$DIR/run.sh"

# install the icon in every available size
for s in 32 48 64 128 256 512; do
    src="$DIR/assets/icons/$s.png"
    [ "$s" = "512" ] && src="$DIR/assets/icon.png"
    if [ -f "$src" ]; then
        mkdir -p "$ICONS/${s}x${s}/apps"
        cp "$src" "$ICONS/${s}x${s}/apps/proxy-toolkit.png"
    fi
done
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t -f "$ICONS" >/dev/null 2>&1 || true

cat > "$APPS/proxy-toolkit.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Proxy Toolkit
Comment=Proxy checker, rotator and chain tool
Exec=$DIR/run.sh
Path=$DIR
Icon=proxy-toolkit
Terminal=false
Categories=Network;Utility;
StartupWMClass=proxy-toolkit
DESKTOP
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS" >/dev/null 2>&1 || true

echo "Launcher installed: $APPS/proxy-toolkit.desktop"
echo "Tip: run ./run.sh once from a terminal first, so dependencies get installed."
