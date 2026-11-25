#!/usr/bin/env bash
set -e

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE_DIR"

INSTALL_DIR="$BASE_DIR/openssl_patch/openssl-3.6.0-beta1-install"

echo "=== Starting One-Time Setup ==="

# OpenSSL needs roughly 2 GB of scratch space while building.
if [ ! -f "$INSTALL_DIR/bin/openssl" ] || [ ! -d "$INSTALL_DIR/include/openssl" ]; then
    available_kb=$(df -Pk "$BASE_DIR" | awk 'NR==2 {print $4}')
    required_kb=$((2 * 1024 * 1024))
    if [ "${available_kb:-0}" -lt "$required_kb" ]; then
        echo "ERROR: Not enough free disk space to build patched OpenSSL."
        echo "       Available: $((available_kb / 1024)) MB, required: $((required_kb / 1024)) MB."
        echo "       Free up space, or extract the project onto a filesystem with at least 2 GB"
        echo "       free (for example /tmp on small-disk machines), then rerun setup.sh."
        df -h "$BASE_DIR"
        exit 1
    fi
fi

# 1. Prerequisites Check
missing_tools=()
for tool in gcc make perl curl wget python3; do
    if ! command -v $tool &> /dev/null; then
        missing_tools+=($tool)
    fi
done
if [ ${#missing_tools[@]} -ne 0 ]; then
    echo "ERROR: Missing required tools: ${missing_tools[*]}"
    exit 1
fi

# Make all shell scripts and Python files executable
echo "Setting execute permissions on all shell and Python scripts..."
find "$BASE_DIR" -type f \( -name "*.sh" -o -name "*.py" \) \
    ! -path "$BASE_DIR/.venv/*" \
    ! -path "$BASE_DIR/openssl_patch/download/*" \
    -exec chmod +x {} \;
echo "-> Execute permissions set."

# 2. Build Patched OpenSSL (Skips if the installation binary and headers exist)
if [ ! -f "$INSTALL_DIR/bin/openssl" ] || [ ! -d "$INSTALL_DIR/include/openssl" ]; then
    echo "Building patched OpenSSL..."
    cd "$BASE_DIR/openssl_patch"
    ./build_openssl.sh \
        --download-dir "$BASE_DIR/openssl_patch/download" \
        --source-dir "$BASE_DIR/openssl_patch/download/openssl-3.6.0-beta1" \
        --install-dir "$INSTALL_DIR" \
        --patch-file "$BASE_DIR/openssl_patch/openssl-3.6.0-beta1.patch"

    echo "Building OpenSSL demo servers..."
    cd "$BASE_DIR/openssl_patch/download/openssl-3.6.0-beta1/demos/quic/server" && make
    cd "$BASE_DIR/openssl_patch/download/openssl-3.6.0-beta1/demos/guide" && make
else
    echo "-> Patched OpenSSL installation found at $INSTALL_DIR. Skipping compilation."
fi

# 3. Determine Lib Directory Layout
if [ -d "$INSTALL_DIR/lib64" ]; then
    OPENSSL_LIB_DIR="$INSTALL_DIR/lib64"
else
    OPENSSL_LIB_DIR="$INSTALL_DIR/lib"
fi

# 4. Compile Client/Server against local OpenSSL (Skips if a previous build sentinel exists)
if [ ! -f "$BASE_DIR/code/client_server/.built" ]; then
    echo "Compiling client_server binaries..."
    export CPATH="$INSTALL_DIR/include:$CPATH"
    export LIBRARY_PATH="$OPENSSL_LIB_DIR:$LIBRARY_PATH"

    cd "$BASE_DIR/code/client_server"
    make clean
    make OPENSSL_INCLUDE="$INSTALL_DIR/include" OPENSSL_LIB="$OPENSSL_LIB_DIR"
    touch ".built" # Create a sentinel flag file to mark compilation completion
else
    echo "-> client_server binaries already compiled. Skipping compilation."
fi

# 5. Local UV Setup (Skips binary download if folder exists)
cd "$BASE_DIR"
export UV_INSTALL_DIR="$BASE_DIR/.uv_bin"
if [ ! -d "$UV_INSTALL_DIR" ]; then
    echo "Installing UV locally..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
else
    echo "-> UV toolchain already present at $UV_INSTALL_DIR. Skipping installation."
fi
export PATH="$UV_INSTALL_DIR:$PATH"

# 6. Python Venv Setup (recreates partial/broken environments, skips satisfied installs)
VENV_DIR="$BASE_DIR/.venv"

# Keep uv's cache inside the project so setup also works when $HOME is read-only.
export UV_CACHE_DIR="${UV_CACHE_DIR:-$BASE_DIR/.uv_cache}"

venv_ok() {
    [ -x "$VENV_DIR/bin/python" ] && "$VENV_DIR/bin/python" -c "import sys" >/dev/null 2>&1
}

if ! venv_ok; then
    if [ -e "$VENV_DIR" ]; then
        echo "-> Existing virtual environment is incomplete or broken; recreating it."
        rm -rf "$VENV_DIR"
    fi
    echo "Creating virtual environment..."
    uv venv --python python3 "$VENV_DIR"
fi

if "$VENV_DIR/bin/python" -c "import tqdm, cryptography, pyasn1" >/dev/null 2>&1; then
    echo "-> Python dependencies already installed. Skipping package installation."
else
    echo "Installing Python dependencies from requirements.txt..."
    uv pip install --python "$VENV_DIR/bin/python" -r requirements.txt
fi

# Ensure the runner script is executable for the user
if [ -f "$BASE_DIR/scripts/run_experiment.sh" ]; then
    chmod +x "$BASE_DIR/scripts/run_experiment.sh"
fi

echo "===================================================="
echo " Setup Complete! You do not need to run this again."
echo " Use sudo ./scripts/run_experiment.sh to execute your results."
echo "===================================================="
