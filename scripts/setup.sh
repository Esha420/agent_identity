#!/usr/bin/env bash
set -euo pipefail

echo "================================================================="
echo "[SETUP] Setting up Multi-Agent Authorization + AX/Substrate Lab"
echo "================================================================="

# 1. Verify Prerequisites
command -v docker >/dev/null 2>&1 || { echo "[ERROR] docker is required but not installed."; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "[ERROR] kubectl is required but not installed."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "[ERROR] python3 is required but not installed."; exit 1; }

echo "[+] Core prerequisites detected (docker, kubectl, python3)."

# 2. Verify AX & Substrate Infrastructure
echo "[+] Checking native AX and Substrate cluster state..."
kubectl get pods -n ax-system -l app.kubernetes.io/name=ax-server >/dev/null 2>&1 || {
    echo "[ERROR] Native ax-server not found in ax-system namespace."; exit 1;
}
kubectl get pods -n ate-system -l app=ate-api-server >/dev/null 2>&1 || {
    echo "[ERROR] Native Substrate (ate-api-server) not found in ate-system namespace."; exit 1;
}
echo "[+] Native AX control plane and Substrate (ATE) cluster verified."

# 3. Start Cerbos PDP and Mock Target
echo "[+] Starting Cerbos PDP and mock-target containers..."
docker compose up -d

# 4. Await Cerbos Health
echo "[+] Awaiting Cerbos PDP health check..."
for i in {1..15}; do
    if curl -s http://localhost:3592/_cerbos/health | grep -q "SERVING"; then
        echo "[+] Cerbos PDP is HEALTHY and SERVING on http://localhost:3592"
        break
    fi
    sleep 1
done

# 5. Compile Cerbos Policies
echo "[+] Compiling and validating Cerbos policies..."
docker run --rm \
  -v "$(pwd)/cerbos/policies:/policies:ro" \
  -v "$(pwd)/cerbos/tests:/tests:ro" \
  ghcr.io/cerbos/cerbos:latest compile --tests=/tests /policies

echo "================================================================="
echo "[SETUP COMPLETED] Lab is fully initialized and ready."
echo "Run './scripts/verify.sh' or './scripts/demo.sh'"
echo "================================================================="
