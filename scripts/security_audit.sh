#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "  Kryptotome Security & Dependency Audit Harness"
echo "=========================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${WORKSPACE_ROOT}"

echo ""
echo "[1/2] Running Rust Workspace Dependency Audit (cargo audit)..."
if command -v cargo-audit >/dev/null 2>&1 || cargo audit --version >/dev/null 2>&1; then
    cargo audit
    echo "✔ Cargo audit passed: 0 vulnerabilities found."
else
    echo "⚠ Warning: cargo-audit not found in PATH."
    exit 1
fi

echo ""
echo "[2/2] Running Node Workspace Dependency Audit (npm audit)..."
if command -v npm >/dev/null 2>&1; then
    npm audit --workspaces
    echo "✔ NPM audit passed: 0 vulnerabilities found."
else
    echo "⚠ Warning: npm not found in PATH."
    exit 1
fi

echo ""
echo "=========================================================="
echo "✔ All automated dependency security audits PASSED!"
echo "=========================================================="
