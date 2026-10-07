#!/usr/bin/env bash
set -euo pipefail

echo "================================================================="
echo "[TEARDOWN] Cleaning up project resources"
echo "================================================================="

# Stop project containers
echo "[+] Stopping Cerbos and mock services..."
docker compose down

# Clean any residual AX tasks
echo "[+] Checking for any residual AX tasks..."
TASKS=$(./bin/ax get tasks 2>/dev/null | tail -n +2 | awk '{print $1}' || true)
for t in $TASKS; do
    if [ -n "$t" ]; then
        echo "[+] Deleting residual task: $t"
        ./bin/ax delete task "$t" >/dev/null 2>&1 || true
    fi
done

echo "[+] Teardown completed successfully."
