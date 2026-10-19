#!/usr/bin/env bash
# Proxy Toolkit launcher: creates a virtualenv on first run, then starts the app.
set -e
cd "$(dirname "$(readlink -f "$0")")"

if [ ! -f .venv/.deps_ok ]; then
    echo "[setup] Creating virtualenv and installing dependencies (first run only)..."
    python3 -m venv --system-site-packages .venv
    .venv/bin/pip install -q --upgrade pip
    .venv/bin/pip install -q -r requirements.txt
    touch .venv/.deps_ok
fi

exec .venv/bin/python main.py "$@"
