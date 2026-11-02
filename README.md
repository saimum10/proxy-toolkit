<p align="center">
  <img src="assets/icon.png" alt="Proxy Toolkit" width="110">
</p>

<h1 align="center">Proxy Toolkit</h1>

<p align="center">
  A desktop app that <b>checks proxies</b> and then <b>uses them</b>:
  a local rotating / chaining proxy server, with a leak-protected browser launcher.
</p>

<p align="center"><b>Version 2.9.0.2</b> · Python · PyQt6 · asyncio</p>

---

## Features

**1 · Proxy Checker**
- Tests HTTP / HTTPS / SOCKS4 / SOCKS5 proxies in parallel: latency, exit IP, country / ISP, anonymity level,
  remote-DNS (leak) test, stability over several rounds, and a score
- Sort, search and **advanced filters** (latency, score, anonymity, stability, type, remote DNS); favourites and a blacklist
- Export as JSON / CSV / TXT / per-country lists, **proxychains.conf** or a **PAC file**

**2 · Proxy Rotation / Chain**
- A local SOCKS5 + HTTP proxy server that sends your traffic through the pool: round-robin, random,
  **weighted random**, fastest, **favourites first**, **failover groups**, sticky per domain, manual hold,
  or chains (strict / dynamic / random). It never falls back to a direct connection
- **Change IP**, **auto-rotate** (every N minutes / N connections), and a health monitor that drops dead proxies
- Fill the pool from the Checker, from a pasted list, or **automatically from URLs** (re-downloaded on a schedule)
- **Right-click** a pool row: connect through this IP, re-test, favourite, failover group, chain, copy, blacklist, remove
- **System proxy** switch (GNOME / Cinnamon, Windows), terminal commands, PAC / proxychains files for the local server
- **Safe browser** window that can only use the proxy

**3 · V2Ray Links**
- Checks `ss://` `vmess://` `vless://` `trojan://` links (also base64 subscriptions) with the Xray-core engine
  and adds the live ones to the rotation pool, where every mode, chain and auto-rotate work unchanged

**4 · Two ways to get it**
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
dist/proxy-toolkit_2.9.0.2_<arch>.deb     installable package
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

The version number (`2.9.0.2`) lives in `core/version.py`; both build scripts read it from there.

## Install

### Linux

```bash
sudo apt install ./dist/proxy-toolkit_2.9.0.2_*.deb
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
3. Sort / filter the table. **Filters ▾** opens the advanced filter (max latency, min score,
   anonymity, stability, type, remote DNS). Right-click rows for favourite, blacklist, *Add to chain* and copy.
   **Export** saves the visible rows as JSON, CSV, TXT, per-country lists, a `proxychains.conf` or a PAC file.

## 2 · Proxy Rotation / Chain
1. Get proxies into the pool — any of these:
   - paste / browse / drop a list into **Add proxies** and press **Check & add**
   - tick **Add live proxies from the Checker tab automatically** (same switch on both tabs)
   - press **Add live proxies from Checker**
   - **Auto-fetch from URL**: add the address of a proxy list (a GitHub *blob* link is turned into the raw
     file), choose how often it is refreshed (minimum 5 minutes) — it is downloaded, checked and only the live
     proxies are added. Lists are downloaded directly from this computer, not through a proxy
2. Choose a mode and press **Start server**.
3. Point your browser, curl or Burp at `127.0.0.1:1080`:
   ```bash
   curl --proxy socks5h://127.0.0.1:1080 https://api.ipify.org
   curl --proxy http://127.0.0.1:1080    https://api.ipify.org
   ```
   Firefox: *Settings → Network Settings → Manual proxy* → SOCKS Host `127.0.0.1`, Port `1080`,
   SOCKS v5, and tick **Proxy DNS when using SOCKS v5**.
   Or skip the manual setup and use the **Safe browser** (section 4 below).

### Modes

| Mode | What it does |
|---|---|
| Round-robin | Every new connection uses the next live proxy in turn |
| Random | Every new connection uses a random live proxy |
| Weighted random | Random, but a high score and low latency make a proxy more likely; favourites (★) count 3× |
| Fastest first | Always the lowest-latency proxy; if it fails, the next fastest |
| Favourites first | Your ★ favourites in turn; other proxies only if none of them is usable (optional) |
| Failover groups | Primary group first; Backup 1 / Backup 2 only while the group before it has no usable proxy |
| Sticky per domain | One website keeps the same exit IP, other sites rotate — good for logins |
| Manual · hold one IP | The exit IP stays fixed until you press **Change IP** (or right-click ▸ *Connect through this IP*) |
| Chain · strict | you → A → B → C → site; if any hop is down the connection is blocked |
| Chain · dynamic | Same, but dead hops are skipped |
| Chain · random | A new random chain of N live proxies for every connection |

Strict and dynamic chains use the **Chain builder** (add from the pool, drag to reorder).

**Auto-rotate** (Manual and Sticky modes): a new IP every N minutes and/or every N connections, whichever comes
first. By default open pages and downloads are not cut — only new connections use the new IP; tick
*Auto-rotate also closes open connections* if you want the hard switch.

**Failover groups**: right-click pool rows ▸ *Failover group* ▸ Primary / Backup 1 / Backup 2.

**System proxy**: *Use as system proxy* points GNOME / Cinnamon (or Windows) at the server while it runs and puts the
old setting back when you untick it, stop the server or close the app (also after a crash, at the next start).
On other desktops use **Copy terminal commands** (`export ALL_PROXY=…`) or the PAC file.

## 3 · V2Ray Links

V2Ray-style links are not ordinary proxies; they are run by an engine ([Xray-core](https://github.com/XTLS/Xray-core)),
which this tab can download for you.

1. Press **Download Xray** (or install it yourself and use **Browse…**). The download is checked against the
   SHA-256 published next to it.
2. Paste links (one per line), pick a file, or fetch a subscription URL.
3. Press **Check links**. Live links appear in the table and — if the box is ticked — in the rotation pool.
   Start the server on the Rotation tab and use it as usual.

Notes:
- Each link becomes a local SOCKS5 port (password-protected, 127.0.0.1 only) of one Xray process; nothing can leave
  through your real IP. The processes stop when nothing needs them, and when you close the app.
- Newer Xray refuses some links: VLESS **without** TLS/Reality to a public IP address is prohibited by its
  security policy, and `allowInsecure` is replaced by pinning the server certificate (done automatically).
  The table shows the reason for every refused link.
- Not supported yet: hysteria2 / tuic, kcp / quic / h2 transports, Shadowsocks plugins.
- Links cannot be written into proxychains / PAC files (their ports exist only while the app runs); export those
  files "for the local server" from the Rotation tab instead.
- **Free public configs:** the operator of such a server can see — and for links without encryption change — your
  traffic. Do not log in to accounts you care about.

## 4 · Safe browser

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
- **V2Ray links** (tab 3): the Xray engine and the certificate check for `allowInsecure` links connect to the link's
  server directly from your real IP (like the Checker does); the server's own host name, if it has one, is resolved
  with your system DNS. Everything you send *through* a link uses remote DNS.
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
