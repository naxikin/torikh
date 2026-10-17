#!/bin/sh
set -eu

TORRC=/etc/xikin/torrc
TOR_LOG=/home/xikin/.tor-data/tor.log
TOR_CONSOLE=/tmp/tor.console.log

if [ "$#" -eq 0 ]; then
    set -- doctor.py
fi

if [ "$1" = "tor" ]; then
    exec tor -f "$TORRC"
fi

mkdir -p /home/xikin/.tor-data /home/xikin/.xikin

tor -f "$TORRC" >"$TOR_CONSOLE" 2>&1 &
TOR_PID=$!
trap 'kill "$TOR_PID" 2>/dev/null || true' EXIT INT TERM

i=0
while [ "$i" -lt 90 ]; do
    if grep -q "Bootstrapped 100%" "$TOR_LOG" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$TOR_PID" 2>/dev/null; then
        echo "[xikin] tor exited during startup:" >&2
        tail -n 20 "$TOR_CONSOLE" >&2 || true
        tail -n 10 "$TOR_LOG" >&2 || true
        exit 1
    fi
    i=$((i + 1))
    sleep 1
done

if ! grep -q "Bootstrapped 100%" "$TOR_LOG" 2>/dev/null; then
    echo "[xikin] tor did not bootstrap within 90s:" >&2
    tail -n 20 "$TOR_CONSOLE" >&2 || true
    tail -n 10 "$TOR_LOG" >&2 || true
    exit 1
fi

case "$1" in
    web)
        exec python -m xikin.web
        ;;
    python|python3|bash|sh)
        exec "$@"
        ;;
    *.py)
        exec python "$@"
        ;;
    *)
        SCRIPT="$1"
        shift
        exec python "$SCRIPT.py" "$@"
        ;;
esac
