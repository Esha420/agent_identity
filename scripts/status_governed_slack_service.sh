#!/bin/bash
# Governed Slack Operations Service Status Checker

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
PID_FILE="$ROOT_DIR/.slack_listener.pid"
LOG_FILE="$ROOT_DIR/logs/slack_listener.log"

echo "================================================================="
echo " Governed AI Operations Runtime Service Status"
echo "================================================================="

# 1. Cerbos
if curl -sf http://localhost:3592/_cerbos/health > /dev/null; then
    echo "• Cerbos PDP:        ONLINE (http://localhost:3592)"
else
    echo "• Cerbos PDP:        OFFLINE"
fi

# 2. AX Control Plane
if "$ROOT_DIR/bin/ax" get tasks > /dev/null 2>&1; then
    ACTIVE_TASKS=$("$ROOT_DIR/bin/ax" get tasks | wc -l)
    ACTIVE_TASKS=$((ACTIVE_TASKS > 1 ? ACTIVE_TASKS - 1 : 0))
    echo "• AX Control Plane:  ONLINE (Active workloads: $ACTIVE_TASKS)"
else
    echo "• AX Control Plane:  OFFLINE"
fi

# 3. Slack Listener
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "• Slack Listener:    RUNNING (PID: $PID)"
        echo "• Log File:          $LOG_FILE"
    else
        echo "• Slack Listener:    STOPPED (Stale PID: $PID)"
    fi
else
    # Check if python process is running
    RUNNING_PIDS=$(pgrep -f "scripts/slack_incident_listener.py" || true)
    if [ -n "$RUNNING_PIDS" ]; then
        echo "• Slack Listener:    RUNNING (PID(s): $RUNNING_PIDS)"
    else
        echo "• Slack Listener:    STOPPED"
    fi
fi

echo "================================================================="
if [ -f "$LOG_FILE" ]; then
    echo "Recent activity (last 5 log lines):"
    tail -n 5 "$LOG_FILE"
fi
