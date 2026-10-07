#!/usr/bin/env bash
set -euo pipefail

echo "================================================================="
echo "[VERIFY] Running Complete Automated Verification Suite"
echo "================================================================="

# 1. Compile Cerbos policies and run PDP unit tests
echo "[Step 1/2] Compiling Cerbos policies and running PDP unit tests..."
docker run --rm \
  -v "$(pwd)/cerbos/policies:/policies:ro" \
  -v "$(pwd)/cerbos/tests:/tests:ro" \
  ghcr.io/cerbos/cerbos:latest compile --tests=/tests /policies

# 2. Run Python End-to-End & Integration Test Suite
echo "[Step 2/2] Running automated Python test suite (23 tests)..."
PYTHONPATH=. python3 -m unittest discover -s tests -p "test_*.py"

echo "================================================================="
echo "[VERIFICATION SUCCESS] All authorization, AX, Substrate, and"
echo "end-to-end integration tests PASSED."
echo "================================================================="
