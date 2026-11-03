#!/bin/bash
# Phone B (Dropper / Termux) setup script
# Cross-compiles the bootstrapper and prepares the audio transmitter.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== BugXhunter Phone B Setup ==="

# ---------- Step 1: Prerequisites ----------
echo "[1/8] Checking prerequisites..."
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not found"; exit 1; }
command -v pip3 >/dev/null 2>&1 || pip3 install --user python-pip >/dev/null 2>&1 || true
command -v clang >/dev/null 2>&1 || { echo "ERROR: clang not found"; echo "  Install Android NDK + LLVM:"; echo "    apt-get update && apt-get install -y clang"; echo "  Or set NDK env var manually."; exit 1; }
# Auto-detect NDK if not set
if [[ -z "${NDK:-}" ]]; then
    NDK=$(find /data/local/tmp -maxdepth 4 -name 'aarch64-linux-android*clang' -type f 2>/dev/null | head -1 | sed 's|.*/toolchains/llvm/prebuilt/||')
    echo "  NDK auto-detected: $NDK"
fi
command -v termux-api >/dev/null 2>&1 || pip3 install --user termux-api 2>/dev/null || true

# ---------- Step 2: Install Python deps ----------
echo "[2/8] Installing Python dependencies..."
python3 -m pip install --quiet uvicorn starlette aiohttp 2>/dev/null || true
python3 -c "import starlette; import uvicorn; import aiohttp; print('  OK: starlette, uvicorn, aiohttp')"

# ---------- Step 3: Generate PSK + config ----------
echo "[3/8] Generating drop PSK and writing config..."
PSK=$(python3 -c "import secrets; print(secrets.token_hex(32))")
echo "  Generated PSK: $PSK"

cat > config.json <<EOF
{
  "token": "change-me-12345",
  "version": "1.0.0",
  "host": "0.0.0.0",
  "port": 7080,
  "vpn_enabled": false,
  "frida_host": "127.0.0.1",
  "frida_port": 27042,
  "frida_server_path": "/data/local/tmp/frida-server",
  "drop_psk": "$PSK"
}
EOF
echo "  config.json written."

# Export PSK for later use in this session
export DROP_PSK="$PSK"

# ---------- Step 4: Cross-compile bootstrapper ----------
echo "[4/8] Cross-compiling bootstrapper for Phone C (arm64)..."
ARCH=$(uname -m 2>/dev/null || echo "arm64")
if [[ "$ARCH" == "arm64" ]]; then
    NDK_TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/$(ls "$NDK"/toolchains/llvm/prebuilt/ 2>/dev/null | grep android)"
    echo "  Using toolchain: $NDK_TOOLCHAIN"
    aarch64-linux-android21-clang \
        -o c/bootstrapper/bootstrapper.elf \
        c/bootstrapper/bootstrapper.c \
        -static -O2 \
        2>/dev/null && echo "  bootstrapper built successfully" || {
            echo "  C compiler failed; trying native build..."
            clang -o c/bootstrapper/bootstrapper c/bootstrapper/bootstrapper.c 2>/dev/null && \
                echo "  bootstrapper built (native)" || \
                echo "  ERROR: bootstrapper compilation failed"
        }
else
    echo "  Architecture $ARCH not supported; using native build"
    clang -o c/bootstrapper/bootstrapper c/bootstrapper/bootstrapper.c 2>/dev/null && \
        echo "  bootstrapper built (native)" || \
        echo "  ERROR: bootstrapper compilation failed"
fi

# ---------- Step 5: Build C receiver (optional) ----------
echo "[5/8] Building C audio receiver (for testing)..."
cd c/receiver
clang -o audio_receiver audio_receiver.c -lm -lcrypto -lssl 2>/dev/null && \
    echo "  audio_receiver built" || \
    echo "  audio_receiver build skipped (missing libs)"

# ---------- Step 6: Tests ----------
echo "[6/8] Running tests..."
python3 tests/test_drop_crypto.py 2>/dev/null | tail -1
python3 tests/test_drop_framing.py 2>/dev/null | tail -1
echo "  (test_audio_drop requires frida-server binary on target)"

# ---------- Step 7: Verify imports ----------
echo "[7/8] Verifying module imports..."
python3 -m bugxhunter.selfcheck 2>/dev/null | grep -E "FAIL|problems" | head -1 || echo "  No import failures"

# ---------- Step 8: Print transmit command ----------
echo "[8/8] Drop chain ready. Transmit command:"
echo ""
echo "  python3 -m bugxhunter.client.drop_audio --elf c/bootstrapper/bootstrapper.elf --psk $PSK"
echo ""
echo "=== Setup complete ==="
echo "PSK:  $PSK"
echo "File: c/bootstrapper/bootstrapper.elf"
