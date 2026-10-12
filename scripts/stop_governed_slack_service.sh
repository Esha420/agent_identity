#!/bin/bash
# Governed Slack Operations Service Stopper

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
PID_FILE="$ROOT_DIR/.slack_listener.pid"

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "[*] Stopping Slack listener service (PID: $PID)..."
        kill "$PID" || true
        sleep 1
        if kill -0 "$PID" 2>/dev/null; then
            kill -9 "$PID" || true
        fi
        echo "[+] Service stopped."
    else
        echo "[!] Process $PID was not running."
    fi
    rm -f "$PID_FILE"
else
    PIDS=$(pgrep -f "scripts/slack_incident_listener.py" || true)
    if [ -n "$PIDS" ]; then
        echo "[*] Killing Slack listener PID(s): $PIDS..."
        kill $PIDS || true
        echo "[+] Done."
    else
        echo "[!] Slack listener is not currently running."
    fi
fi
