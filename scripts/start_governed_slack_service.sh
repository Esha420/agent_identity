#!/bin/bash
# Governed Slack Operations Service Starter
# Launches the Slack Socket Mode listener as a continuous long-running background service.
# Does NOT trigger any test runner or predefined workflows.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

PID_FILE="$ROOT_DIR/.slack_listener.pid"
LOG_DIR="$ROOT_DIR/logs"
LOG_FILE="$LOG_DIR/slack_listener.log"

mkdir -p "$LOG_DIR"

# 1. Health checks on prerequisites
echo "[1/3] Verifying Cerbos PDP health..."
if ! curl -sf http://localhost:3592/_cerbos/health > /dev/null; then
    echo "[-] Cerbos PDP is not healthy at http://localhost:3592. Starting via docker compose..."
    docker compose up -d cerbos mock-target
    sleep 2
fi
echo "[+] Cerbos PDP is active."

echo "[2/3] Verifying AX Control Plane..."
if ! "$ROOT_DIR/bin/ax" get tasks > /dev/null 2>&1; then
    echo "[-] AX control plane unreachable. Please verify kind cluster."
    exit 1
fi
echo "[+] AX Control Plane is active."

# 2. Check if listener is already running
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo "[!] Slack listener is already running (PID: $OLD_PID)."
        echo "    Logs: $LOG_FILE"
        exit 0
    else
        rm -f "$PID_FILE"
    fi
fi

# 3. Launch Slack Socket Mode listener in background
echo "[3/3] Starting continuous Slack Socket Mode listener service..."
nohup python3 -u "$ROOT_DIR/scripts/slack_incident_listener.py" >> "$LOG_FILE" 2>&1 &
NEW_PID=$!
echo "$NEW_PID" > "$PID_FILE"

sleep 2

if kill -0 "$NEW_PID" 2>/dev/null; then
    echo "================================================================="
    echo " [SERVICE STARTED] Governed Slack Operations Service is ONLINE"
    echo "================================================================="
    echo "• Service PID:       $NEW_PID"
    echo "• Channel:           #agent-operations (C0C5RC2GHQF)"
    echo "• Log Output:        $LOG_FILE"
    echo "• Operating Mode:    Continuous Slack Intent Dispatch"
    echo "• Autonomous Plan:   OpenClaw Coordinator (ax/coordinator.py)"
    echo "• Runtime PEP:       Tool Gateway PEP (tools/gateway.py)"
    echo "================================================================="
    echo "You can now send requests directly in Slack #agent-operations!"
else
    echo "[-] Service failed to start. Showing last 20 log lines:"
    tail -n 20 "$LOG_FILE"
    exit 1
fi
