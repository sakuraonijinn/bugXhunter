# BugXhunter — Update Prompt for Andi Assistants

## Context
This is the BugXhunter repository (bugxhunter). It's a self-hosted red-team operations hub for the BugDeck Android app. It exposes an HTTP API for remote posture checks and Frida control, and serves the Frida web UI.

## Workspace
- Primary workspace: `bugXhunter-10b0de66` (more complete, modular Python server)
- Secondary: `bugxhunter` (minimal single-file server, used for C code development)

## Key Components
- **Python Server** (`bugxhunter/server.py`): Modular Starlette app with Frida, hooks, posture, privileges, scanners, drop chain
- **C Bootstrapper** (`c/bootstrapper/bootstrapper.c`): Launches frida-server, establishes reverse tunnel to operator
- **C Audio Receiver** (`c/receiver/audio_receiver.c`): FSK demodulator for covert audio drop chain
- **Drop Chain** (`bugxhunter/drop/`): Crypto, framing, driver, audio emitter/receiver
- **Client CLI** (`bugxhunter/client/`): Operator field guide, status, diagnose, devices, frida, scan

## When Cloning to a New Machine

### 1. Install Dependencies
```bash
pip3 install uvicorn starlette aiohttp
# For C compilation (if needed):
pkg install clang openssl  # Termux
```

### 2. Configure
```bash
cp config.example.json config.json
# Edit config.json with your auth token and VPS settings
```

### 3. Start Server
```bash
python3 -m bugxhunter.server --host 0.0.0.0 --port 7080 --token your-secret
```

### 4. Run Tests
```bash
python3 tests/test_drop_crypto.py
python3 tests/test_drop_framing.py
python3 tests/test_audio_drop.py
```

### 5. Build C Components (optional, requires NDK)
```bash
# Audio receiver
clang -o audio_receiver c/receiver/audio_receiver.c -lm -lcrypto -lssl

# Bootstrapper
clang -o bootstrapper c/bootstrapper/bootstrapper.c
```

## Production Status (Updated)

All placeholder logic has been replaced with real implementations:

### C Code
- **audio_receiver.c**: Real demodulation state machine (SEARCH_PREAMBLE → READ_BITS → DECODE_FRAME), Goertzel with correct coefficient (2*cos(w)), 5-byte frame header matching Python, per-block SHA256 keystream, HMAC verification
- **bootstrapper.c**: CLI-configurable operator host/port, real ASensorManager magnetometer integration, socket proxy loop, buffer overflow guard

### Python
- **bugxhunter_server.py**: Auth guard fixed (auth_enabled uses == "1", unauthorized blocks startup correctly)
- **drop/crypto.py**: Full encrypt/decrypt with SHA256 counter-mode + HMAC-SHA256
- **drop/driver.py**: VibratorDriver delegates to AndroidCoil (DropShim socket)

### Tests
- test_drop_crypto.py: 4/4 passing
- test_drop_framing.py: 9/9 passing  
- test_audio_drop.py: passing

### Remaining for Full Production
- AAudio real-time sample capture in audio_receiver (currently uses state machine ready for integration)
- SSH reverse tunnel (currently uses raw TCP)
- VPN routing error recovery
- Scanner integration tests against real targets
1. **Auth guard**: `auth_enabled()` must use `== "1"` not `!= "1"` for ALLOW_UNAUTHENTICATED check
2. **Goertzel coefficient**: Must use `2*cos(w)` not `w` as recurrence coefficient
3. **Frame format**: 5-byte header (version + tag_flag + drop_id(2) + payload_len) + payload + CRC16(2)
4. **Crypto keystream**: Per-32-byte-block SHA256, not per-byte
5. **Buffer overflow**: Always bounds-check `cmd_str[bytes] = '\0'` against MAX_BUFFER

## Architecture Notes
- Server runs on Starlette (no FastAPI/pydantic — avoids Rust wheel issues on Android)
- Frida driven via native binary (no frida-python — Bionic vs glibc incompatibility)
- Audio drop chain: FSK modulation at 18500/19500 Hz, 10ms windows, Goertzel detection
- All crypto uses SHA256 counter-mode XOR with HMAC-SHA256 authentication

## File Structure
```
bugxhunter/
├── server.py          # Main HTTP server
├── config.py          # Configuration management
├── frida.py           # Frida server lifecycle
├── posture.py         # Device fingerprinting
├── privileges.py      # Elevation tier management
├── http.py            # HTTP client utilities
├── termux.py          # Termux detection
├── tools.py           # Tool bridge
├── vpn.py             # VPN routing
├── steps.py           # Operator field guide
├── client/            # CLI tools
├── drop/              # Audio drop chain
│   ├── crypto.py      # Encryption/decryption
│   ├── framing.py     # Frame encode/decode
│   ├── driver.py      # Coil/magnetometer drivers
│   ├── android_driver.py  # Android shim client
│   ├── audio.py       # Audio emitter
│   └── receiver.py    # Audio receiver (Python)
├── hooks/             # Frida hook library
├── scanners/          # Security scanners
└── templates/         # HTML templates
c/
├── bootstrapper/      # C bootstrapper ELF
└── receiver/          # C audio receiver
tests/                 # Test suite
```
