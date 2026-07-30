#!/usr/bin/env zsh
set -euo pipefail
cd "${0:A:h}"

echo "=== python-merkle-proof-lab ==="
echo

# find python
if (( $+commands[python3] )); then
    PY=python3
elif (( $+commands[python] )); then
    PY=python
else
    echo "error: python not found in PATH" >&2
    exit 1
fi

echo "Python: $($PY --version 2>&1)"
echo

echo "=== compile ==="
$PY -m compileall merkle_proof
echo

echo "=== run_lab.py ==="
$PY run_lab.py
echo

echo "=== unittest ==="
$PY -m unittest tests.test_merkle_independent -v
echo

echo "All checks passed."
