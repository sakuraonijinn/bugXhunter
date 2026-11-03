#!/bin/bash
# Phone A (Operator) setup script
# Sets up the bugXhunter server on this device.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== BugXhunter Phone A Setup ==="

# ---------- Step 1: Prerequisites ----------
echo "[1/8] Checking prerequisites..."
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not found"; exit 1; }
command -v pip3 >/dev/null 2>&1 || pip3 install --user python-pip >/dev/null 2>&1 || true
command -v clang >/dev/null 2>&1 || echo "  clang not installed; C components will be skipped"

# ---------- Step 2: Install Python deps ----------
echo "[2/8] Installing Python dependencies..."
python3 -m pip install --quiet uvicorn starlette aiohttp 2>/dev/null || true
python3 -c "import starlette; import uvicorn; import aiohttp; print('  OK: starlette, uvicorn, aiohttp')"

# ---------- Step 3: Generate token + config ----------
echo "[3/8] Generating auth token and writing config..."
TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(16))")
echo "  Generated token: $TOKEN"

cat > config.json <<EOF
{
  "token": "$TOKEN",
  "version": "1.0.0",
  "host": "0.0.0.0",
  "port": 7080,
  "vpn_enabled": false,
  "frida_host": "127.0.0.1",
  "frida_port": 27042,
  "frida_server_path": "/data/local/tmp/frida-server"
}
EOF
echo "  config.json written."

# ---------- Step 4: Build C components ----------
echo "[4/8] Building C components..."
cd c/receiver
if command -v clang >/dev/null 2>&1; then
    clang -o audio_receiver audio_receiver.c -lm -lcrypto -lssl 2>/dev/null && \
        echo "  audio_receiver built" || echo "  audio_receiver build skipped (missing crypto libs)"
else
    echo "  clang not found; skipping"
fi
cd ../bootstrapper
if command -v clang >/dev/null 2>&1; then
    clang -o bootstrapper bootstrapper.c 2>/dev/null && \
        echo "  bootstrapper built" || echo "  bootstrapper build skipped"
else
    echo "  clang not found; skipping"
fi

# ---------- Step 5: Run tests ----------
echo "[5/8] Running tests..."
python3 tests/test_drop_crypto.py 2>/dev/null | tail -1
python3 tests/test_drop_framing.py 2>/dev/null | tail -1
echo "  (test_audio_drop requires frida-server binary; see docs)"

# ---------- Step 6: Self-check imports ----------
echo "[6/8] Verifying module imports..."
python3 -m bugxhunter.selfcheck 2>/dev/null | grep -E "FAIL|problems" | head -1 || echo "  No import failures"

# ---------- Step 7: Start server ----------
echo "[7/8] Starting bugXhunter server..."
export AUTH_TOKEN="$TOKEN"
nohup python3 -m bugxhunter.server \
    --host 0.0.0.0 \
    --port 7080 \
    >"$SCRIPT_DIR/phone_a.log" 2>&1 &
PID=$!
echo "  Server PID: $PID"
echo "  Log: $SCRIPT_DIR/phone_a.log"
echo "  Stop with: kill $PID"

# ---------- Step 8: Verify health ----------
echo "[8/8] Verifying health endpoint..."
sleep 1
curl -sf http://127.0.0.1:7080/health && echo "" || { echo "ERROR: server did not start"; tail -5 phone_a.log; exit 1; }
echo "  Health check passed."
echo ""
echo "=== Setup complete ==="
echo "Token: $TOKEN"
echo "Log:  $SCRIPT_DIR/phone_a.log"
echo "Stop: kill $PID"
