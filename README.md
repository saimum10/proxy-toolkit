<p align="center">
  <img src="assets/icon.png" alt="Proxy Toolkit" width="110">
</p>

<h1 align="center">Proxy Toolkit</h1>

<p align="center">
  A desktop app that <b>checks proxies</b> and then <b>uses them</b>:
  a local rotating / chaining proxy server, with a leak-protected browser launcher.
</p>

<p align="center"><b>Version 2.9.0</b> · Python · PyQt6 · asyncio</p>

---

## Features

**1 · Proxy Checker**

**2 · Proxy Rotation / Chain**

**3 · Two ways to get it**
- **Standalone app** — build a single binary (`.deb` on Linux, `.exe` on Windows); no Python needed to run it
- **Run from source** — start it straight from the cloned folder

## Requirements

| | Standalone app | Run from source |
|---|---|---|
| OS | Debian / Ubuntu (Linux), or Windows | Debian / Ubuntu or another Debian-based distribution |
| To build | Python 3 (3.12 recommended), internet access for the build | — |
| To run | nothing extra (the `.deb` pulls in the Qt system libraries) | Python 3, `git`, the packages listed below |

---

# Standalone app (build, install, uninstall)

## Build

### Linux (Debian / Ubuntu)

```bash
# 1. system packages
sudo apt update
sudo apt install git python3 python3-venv

# 2. download
git clone https://github.com/saimum10/proxy-toolkit.git
cd proxy-toolkit

# 3. build (creates a clean build venv, installs PyInstaller, builds the binary and the .deb)
bash build_linux.sh
```

Result:

```
dist/proxy-toolkit                      single-file binary (run it directly)
dist/proxy-toolkit_2.9.0_<arch>.deb     installable package
```

- The binary needs a glibc **at least as new as the build machine's**. To support older systems,
  build on the **oldest** distribution you want to support.
- `SKIP_BUILD=1 bash build_linux.sh` only re-packs the `.deb` from an existing `dist/proxy-toolkit`.

### Windows

1. Install **Python 3.12** from [python.org](https://www.python.org) and tick **Add python.exe to PATH**.
2. Download or clone the project, open the folder and run:

```bat
build_windows.bat            :: no console window (default)
build_windows.bat console    :: with a console window, to see errors
```

Result: `dist\ProxyToolkit.exe` — one single file.

The version number (`2.9.0`) lives in `core/version.py`; both build scripts read it from there.

## Install

### Linux

```bash
sudo apt install ./dist/proxy-toolkit_2.9.0_*.deb
```

This installs the app, its menu entry and its icons, and pulls in the required system libraries.
Start it from the application menu (**Proxy Toolkit**) or from a terminal:

```bash
proxy-toolkit
```

To update, build the new version and install the new `.deb` the same way — it replaces the old one.

You can also run the binary without installing it (`./dist/proxy-toolkit`); in that case install the
Qt libraries yourself: `sudo apt install libgl1 libegl1 libxkbcommon-x11-0 libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-render-util0 libxcb-shape0 libxcb-xkb1`.

### Windows

Copy `dist\ProxyToolkit.exe` anywhere and double-click it. Nothing is installed.
If Windows SmartScreen warns, choose **More info → Run anyway**. Some antivirus programs flag
single-file PyInstaller programs by mistake; the source is in this repository.

## Uninstall

### Linux

```bash
# the app, its menu entry and icons
sudo apt remove proxy-toolkit

# saved favourites / blacklist (optional)
rm -rf ~/.config/proxy-toolkit

# leftover temporary Safe-browser profiles (optional)
rm -rf ~/proxy-toolkit-profiles
```

### Windows

Delete `ProxyToolkit.exe`, then (optional) remove its saved data:

```
%USERPROFILE%\.config\proxy-toolkit        favourites / blacklist
%USERPROFILE%\proxy-toolkit-profiles       leftover temporary Safe-browser profiles
```

---

# Run from source (no build)

## Install

```bash
# 1. system packages
sudo apt update
sudo apt install git python3 python3-venv python3-pyqt6 libxcb-cursor0

# 2. download
git clone https://github.com/saimum10/proxy-toolkit.git
cd proxy-toolkit

# 3. first run: creates a .venv, installs the Python dependencies, starts the app
bash run.sh

# 4. Install the launcher (application menu + icon)
bash install_launcher.sh

# 5. delete installer file
# cd ..
# rm -rf proxy-toolkit

```

The first start takes a little longer because the dependencies are installed into the local `.venv`
(nothing is installed system-wide).

## Update

```bash
cd proxy-toolkit
git pull
rm -f .venv/.deps_ok      # re-installs the dependencies on the next start
bash run.sh
```

## Uninstall (delete everything)

```bash
# launcher + icons
rm -f ~/.local/share/applications/proxy-toolkit.desktop
rm -f ~/.local/share/icons/hicolor/*/apps/proxy-toolkit.png
rm -f ~/.local/share/icons/hicolor/icon-theme.cache
update-desktop-database ~/.local/share/applications 2>/dev/null || true

# saved favourites / blacklist (optional)
rm -rf ~/.config/proxy-toolkit

# leftover temporary Safe-browser profiles (optional)
rm -rf ~/proxy-toolkit-profiles

# the app itself (the cloned folder, including its .venv)
cd .. && rm -rf proxy-toolkit
```

---

# Usage

## 1 · Proxy Checker
1. Drop `.txt` files on the window, click **Browse files…**, or paste proxies (one per line):
   ```
   1.2.3.4:8080
   socks5://1.2.3.4:1080
   user:pass@1.2.3.4:3128
   1.2.3.4:8080:user:pass
   ```
2. Adjust the settings and click **Start check**.
3. Sort / filter the table. Right-click rows for favourite, blacklist, *Add to chain* and copy.
   **Export** saves the visible rows as JSON, CSV, TXT or per-country lists.

## 2 · Proxy Rotation / Chain
1. Get proxies into the pool — any of these:
   - paste / browse / drop a list into **Add proxies** and press **Check & add**
   - tick **Add live proxies from the Checker tab automatically** (same switch on both tabs)
   - press **Add live proxies from Checker**
2. Choose a mode and press **Start server**.
3. Point your browser, curl or Burp at `127.0.0.1:1080`:
   ```bash
   curl --proxy socks5h://127.0.0.1:1080 https://api.ipify.org
   curl --proxy http://127.0.0.1:1080    https://api.ipify.org
   ```
   Firefox: *Settings → Network Settings → Manual proxy* → SOCKS Host `127.0.0.1`, Port `1080`,
   SOCKS v5, and tick **Proxy DNS when using SOCKS v5**.
   Or skip the manual setup and use the **Safe browser** (next section).

### Modes

| Mode | What it does |
|---|---|
| Round-robin | Every new connection uses the next live proxy in turn |
| Random | Every new connection uses a random live proxy |
| Fastest first | Always the lowest-latency proxy; if it fails, the next fastest |
| Sticky per domain | One website keeps the same exit IP, other sites rotate — good for logins |
| Manual · hold one IP | The exit IP stays fixed until you press **Change IP** |
| Chain · strict | you → A → B → C → site; if any hop is down the connection is blocked |
| Chain · dynamic | Same, but dead hops are skipped |
| Chain · random | A new random chain of N live proxies for every connection |

Strict and dynamic chains use the **Chain builder** (add from the pool, drag to reorder).

## 3 · Safe browser

With the server running, press **🛡 Launch safe browser** on the Proxy Rotation / Chain tab.

- Pick the browser in the drop-down. Linux: Firefox, Chromium, Chrome and Brave are found on `PATH`.
  Windows: Firefox, Chrome, Edge and Brave are found in the usual Program Files / LocalAppData folders.
- It opens a **separate window with a temporary profile** that can only use this proxy:
  SOCKS5 with remote DNS, WebRTC off, QUIC (HTTP/3) off, IPv6 DNS off, DNS-over-HTTPS off,
  captive-portal checks off, and **no fallback to a direct connection** if the proxy stops.
- **Open WebRTC test page** — opens browserleaks.com/webrtc (loaded through the proxy) so you can verify.
  The *Public IP Address* there should be empty or the proxy's, never yours.
- **Keep profile** — keep cookies / history after closing (default: the profile is deleted on close).
  Profiles live in `~/proxy-toolkit-profiles/`.

Limits — read this:
- Only **that window** is protected. Your normal browser, curl, ssh, torrents and system updates
  still bypass the proxy.
- WebRTC is off, so video calls in that window (Meet, Discord web …) will not work.
- It is not Tor Browser: it does not stop browser fingerprinting. The upstream proxy still sees your
  real IP and, for plain HTTP, your traffic.
- Snap browsers can refuse a custom profile folder — use the apt / `.deb` version if the window does
  not open. Flatpak browsers are not detected.
- For an OS-level guarantee use a firewall (nftables / network namespace) that lets the browser reach
  only `127.0.0.1:<port>`.

---

# Safety notes

- The **kill-switch** protects traffic that is sent to this local proxy. Programs that bypass it are
  not covered.
- Browsers can leak your real IP through **WebRTC**, which no proxy can stop. Use the **Safe browser**,
  or disable WebRTC yourself (Firefox: `media.peerconnection.enabled = false`), and verify on a
  leak-test site.
- **Remote DNS**: hostnames are sent to the proxy, so no local DNS lookup happens — as long as the
  client sends hostnames (Firefox: *Proxy DNS*, curl: `socks5h://`).
- The Checker (and importing a proxy list) contacts ipify / Cloudflare / icanhazip / httpbin /
  postman-echo and ip-api.com **directly from your real IP**, to learn your real IP and the proxies'
  countries. Keep that in mind if your own connection must not be seen contacting them.
- The anonymity level is measured with a plain-HTTP header-echo page (httpbin.org /
  postman-echo.com). SOCKS proxies relay raw TCP, so they are always reported as *elite* — that says
  nothing about whether the proxy is trustworthy.
- Country / city / ISP data comes from [ip-api.com](https://ip-api.com) (free tier: 15 batch
  requests per minute, non-commercial use).
- Use this tool only with proxies you are allowed to use and on systems you are authorised to test.
- **It's not verified that it's leak-protected**

# Troubleshooting

| Problem | Fix |
|---|---|
| `Could not load the Qt platform plugin "xcb"` | `sudo apt install libxcb-cursor0` (the `.deb` installs it for you) |
| Launcher icon missing in the dock (Wayland) | Source install: run `bash install_launcher.sh` and start the app from the menu |
| `Cannot start the server` / port in use | Change the port in *Listen address* |
| A site still shows your real IP | Check the browser really uses the proxy (Firefox has its own proxy settings), then check WebRTC — or use the **Safe browser** |
| **Launch safe browser** is greyed out | Start the server first; if the drop-down says *No supported browser found*, install Firefox, Chromium, Chrome or Brave (Windows: Edge also works) |
| Safe browser window does not open | Snap / Flatpak browser: install the apt / `.deb` (Linux) or the normal installer (Windows) version |
| Country filter excludes everything | Enable *Country / city / ISP lookup* in the Checker settings and check again |
| A part of the window is cut off | Increase the window size; the side panels scroll and follow the system font size |
| `GLIBC_2.xx not found` when starting the Linux binary | The binary was built on a newer system — build it on the target (or an older) distribution |
| `dpkg-deb: command not found` while building | `sudo apt install dpkg` |
| Windows build: `Python not found` | Install Python 3.12 from python.org and tick *Add python.exe to PATH*, then open a new terminal |
| Windows: the `.exe` closes immediately | Rebuild with `build_windows.bat console` to see the error message |
