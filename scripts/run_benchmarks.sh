#!/usr/bin/env bash
###############################################################################
# AegisQoS — Master 1-Click Automated Benchmark & Experiment Runner
# Tata Elxsi TELIPORT Season 4 — Case Study 3 (Team CS-02)
#
# Executes all 3 Case Study scenarios across Baseline, Deterministic, and AegisQoS:
#   - Scenario 1: ISO Download vs Video Call Protection
#   - Scenario 2: Dynamic WAN Drop (100M -> 20M) & AIMD Adaptation
#   - Scenario 3: 3 Concurrent TV Streams vs Gaming Latency
#
# Generates real evidence in results/:
#   - benchmark_metrics.csv
#   - benchmark_summary.json
#   - scenario1_rtt_comparison.html
#   - scenario2_wan_adaptation.html
#   - scenario3_fairness_gaming.html
#   - BENCHMARK_REPORT.md
###############################################################################
set -euo pipefail

# Determine script and project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_DIR}"

echo "================================================================="
echo "  🛡️  AegisQoS Automated Benchmark Suite (Team CS-02)"
echo "  Tata Elxsi TELIPORT Season 4 — Case Study 3"
echo "================================================================="

# Check root/sudo
if [ "$EUID" -ne 0 ]; then
    echo "[error] This script requires root privileges to manage namespaces and tc."
    echo "        Please run with: sudo bash scripts/run_benchmarks.sh"
    exit 1
fi

# Step 1: Ensure testbed namespaces & routing are configured
echo ""
echo "[Step 1/3] Setting up / verifying 4-namespace testbed topology..."
bash "${SCRIPT_DIR}/setup_testbed.sh"

# Step 2: Locate Python environment
PYTHON_BIN="python3"
if [ -f "/home/ubuntu/aegis-venv/bin/python" ]; then
    PYTHON_BIN="/home/ubuntu/aegis-venv/bin/python"
elif [ -n "${VIRTUAL_ENV:-}" ]; then
    PYTHON_BIN="${VIRTUAL_ENV}/bin/python"
fi
echo "[info] Using Python: ${PYTHON_BIN}"

# Step 3: Run the scenario generator across all regimes
echo ""
echo "[Step 2/3] Executing real-packet benchmarks across all scenarios & regimes..."
DURATION="${1:-10}"
"${PYTHON_BIN}" -m src.traffic.scenario_generator \
    --scenario all \
    --duration "${DURATION}" \
    --results-dir "${PROJECT_DIR}/results"

echo ""
echo "[Step 3/3] Validating benchmark results & artifacts..."
RESULTS_DIR="${PROJECT_DIR}/results"

for file in "benchmark_metrics.csv" "benchmark_summary.json" "BENCHMARK_REPORT.md"; do
    if [ -f "${RESULTS_DIR}/${file}" ]; then
        echo "  [ok] ${file} generated successfully ($(wc -c < "${RESULTS_DIR}/${file}") bytes)"
    else
        echo "  [fail] Expected artifact ${file} not found in ${RESULTS_DIR}!"
        exit 1
    fi
done

echo ""
echo "================================================================="
echo "  🎉 Benchmark Run COMPLETE! Summary of Generated Artifacts:"
echo "================================================================="
echo "  - Report:  ${RESULTS_DIR}/BENCHMARK_REPORT.md"
echo "  - Metrics: ${RESULTS_DIR}/benchmark_metrics.csv"
echo "  - Summary: ${RESULTS_DIR}/benchmark_summary.json"
echo "  - Charts:  ${RESULTS_DIR}/*.html (Interactive Plotly Visualizations)"
echo "================================================================="
