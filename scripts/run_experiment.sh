#!/usr/bin/env bash
set -e

# ==============================================================================
# HOST PRIVILEGE CHECK (Enforce root privileges via sudo)
# ==============================================================================
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] This script must be run with root privileges (e.g., using 'sudo')."
    exit 1
fi

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BASE_DIR"

if [ ! -f "$BASE_DIR/.venv/bin/activate" ]; then
    echo "[ERROR] Python virtual environment not found at $BASE_DIR/.venv"
    echo "   Run setup.sh first: sudo ./setup.sh"
    echo "   If setup.sh failed, fix that error before running experiments."
    exit 1
fi

# ==============================================================================
# ARGUMENT PARSING & TEST SUITE SELECTION
# ==============================================================================
print_usage() {
    cat <<EOF
Usage: sudo ./scripts/run_experiment.sh [OPTIONS] [TEST_SUITE]

Options:
  --test-type <suite>   Run a specific suite: main_tests, short_main_tests, rtt_tests, test_tests
  --test-types <suite>  Alias for --test-type
  -h, --help            Show this usage message

Positional TEST_SUITE values are also accepted:
  main_tests, short_main_tests, rtt_tests, test_tests, short, rtt, test

Examples:
  sudo ./scripts/run_experiment.sh --test-types main_tests
  sudo ./scripts/run_experiment.sh --test-types short_main_tests
  sudo ./scripts/run_experiment.sh rtt_tests
EOF
}

TEST_TYPE=""
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --test-type|--test-types)
            TEST_TYPE="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        main_tests|short_main_tests|rtt_tests|test_tests|short|rtt|test)
            # Accept loose strings directly as the suite name
            TEST_TYPE="$1"
            shift
            ;;
        *)
            # Capture any other flags (like flags to code/experiments/run_experiment.py)
            EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done

if [[ -z "$TEST_TYPE" ]]; then
    echo "[ERROR] No test suite specified."
    print_usage
    exit 1
fi

# Normalize the short aliases and reject unknown suite names before invoking Python.
case "$TEST_TYPE" in
    short) TEST_TYPE="short_main_tests" ;;
    rtt)  TEST_TYPE="rtt_tests" ;;
    test) TEST_TYPE="test_tests" ;;
    main_tests|short_main_tests|rtt_tests|test_tests) ;;
    *)
        echo "[ERROR] Unknown test suite '$TEST_TYPE'."
        print_usage
        exit 1
        ;;
esac

# ==============================================================================
# DYNAMIC EXPERIMENT DIRECTORY (Timestamp + Test Type)
# ==============================================================================
# Generates a format like: 20260602_183500_rtt_tests
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
EXPERIMENT_DIR="$BASE_DIR/results/${TIMESTAMP}_${TEST_TYPE}"
mkdir -p "$EXPERIMENT_DIR"

# ==============================================================================
# ENVIRONMENT SETUP
# ==============================================================================
INSTALL_DIR="$BASE_DIR/openssl_patch/openssl-3.6.0-beta1-install"

if [ -d "$INSTALL_DIR/lib64" ]; then
    OPENSSL_LIB_DIR="$INSTALL_DIR/lib64"
else
    OPENSSL_LIB_DIR="$INSTALL_DIR/lib"
fi

export PATH="$INSTALL_DIR/bin:$BASE_DIR/.uv_bin:$PATH"
export LD_LIBRARY_PATH="$OPENSSL_LIB_DIR:$LD_LIBRARY_PATH"
export PYTHONPATH="$BASE_DIR"

source .venv/bin/activate

cleanup_netns() {
    for ns in srv_ns cli_ns; do
        pids=$(ip netns pids "$ns" 2>/dev/null || true)
        if [ -n "$pids" ]; then
            kill -9 $pids 2>/dev/null || true
        fi
    done
}
trap cleanup_netns EXIT

# ==============================================================================
# EXECUTION
# ==============================================================================
echo "========================================================================"
echo "[START] Starting Experiment Suite: $TEST_TYPE"
echo "[DIR]   Target Directory:         $EXPERIMENT_DIR"
echo "========================================================================"

# Execute your python test suite harness with the dynamic arguments
"$BASE_DIR/.venv/bin/python" code/experiments/run_experiment.py \
    --test-type "$TEST_TYPE" \
    --exp-dir "$EXPERIMENT_DIR" \
    "${EXTRA_ARGS[@]}"

echo "========================================================================"
echo "[OK]    Experiment suite '$TEST_TYPE' finished safely."
echo "[RESULTS] Results saved in: $EXPERIMENT_DIR"
echo "========================================================================"
