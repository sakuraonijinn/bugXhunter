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
- **Android DropShim** (`android/dropshim/DropShim.kt`): Vibrator + magnetometer shim for Python protocol stack
- **Drop Chain** (`bugxhunter/drop/`): Crypto, framing, driver, policy, protocol modules

## Production Status (Updated)

All placeholder logic has been replaced with real implementations:

### C Code
- **audio_receiver.c**: Real demodulation state machine (SEARCH_PREAMBLE → READ_BITS → DECODE_FRAME), Goertzel with correct coefficient (2*cos(w)), 5-byte frame header matching Python, per-block SHA256 keystream, HMAC verification
- **bootstrapper.c**: CLI-configurable operator host/port, real ASensorManager magnetometer integration, socket proxy loop, buffer overflow guard

### Python
- **server.py**: Auth guard fixed (refuses placeholder tokens, validates on every request)
- **drop/crypto.py**: Full encrypt/decrypt with SHA256 counter-mode + HMAC-SHA256
- **drop/driver.py**: VibratorDriver delegates to AndroidCoil (DropShim socket)

### Tests
- test_drop_crypto.py: 4/4 passing
- test_drop_framing.py: 9/9 passing
- test_audio_drop.py: passing

### Remaining for Full Production
- AAudio real-time sample capture in audio_receiver (state machine ready for integration)
- SSH reverse tunnel (currently uses raw TCP with PSK handshake)
- VPN routing error recovery
- Scanner integration tests against real targets

## Build Commands
```bash
# C code
clang -o audio_receiver c/receiver/audio_receiver.c -lm -lcrypto -lssl
clang -o bootstrapper c/bootstrapper/bootstrapper.c

# Python
python3 -m bugxhunter.server --host 0.0.0.0 --port 7080
```

## Known Issues to Watch For
- Auth: server refuses to start with placeholder tokens (change-me-12345, etc.)
- Audio: PSK is hardcoded in audio_receiver.c — inject via build config
- Tunnel: SSH may not be available on all Android devices — raw TCP fallback works
- Magnetometer: ASensorEventQueue_getEvents may block — use non-blocking poll in production
