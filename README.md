# BugXhunter - Frida + Xhunter Control Plane

A lightweight control plane for Android pentesting that runs on Linux/macOS/Windows.
No root required. Drives `frida-server` natively and manages SSH reverse tunnels for remote device control.

## Quick Start

### 1. Install dependencies
```bash
pip3 install uvicorn starlette aiohttp
```

### 2. Configure (config.json)
```json
{
  "auth_token": "your-secret-token",
  "frida": {
    "host": "127.0.0.1",
    "port": 27042,
    "remotes": []
  },
  "xhunter": {
    "vps_host": "100.121.217.115",
    "vps_user": "root",
    "vps_port": 2222,
    "vps_key": "/path/to/private/key",
    "listen_port": 9090,
    "gateway_ports": true
  }
}
```

### 3. Start the server
```bash
AUTH_TOKEN=your-secret-token python3 -m uvicorn bugxhunter_server:app --host 0.0.0.0 --port 7080
```

### 4. Connect BugDeck Android app
1. Install BugDeck APK (build from `Download/bugdeck`)
2. Open BugDeck → Settings → Server Configuration
3. Enter `http://<your-server-ip>:7080` and your auth token
4. Navigate to the Frida tab

### 5. Docker deployment (one-liner)
```bash
docker run -p 7080:7080 -e AUTH_TOKEN=secret bugxhunter:latest
```

## API Endpoints

### Health & Status
- `GET /health` - Health check (no auth)
- `GET /status` - Server status (auth required)

### Frida Control
- `GET /frida/status` - Frida server status
- `POST /frida/start` - Start Frida server
- `POST /frida/stop` - Stop Frida server
- `GET /frida/devices` - List connected devices
- `GET /frida/processes?device=<id>` - List processes on device
- `GET /frida/applications` - List running applications
- `POST /frida/script` - Execute a Frida script
- `GET /frida/results` - List script results
- `GET /frida/results/{result_id}` - Get specific result
- `DELETE /frida/results/{result_id}` - Delete result

### Xhunter (Remote Device Management)
- `GET /xhunter/status` - Tunnel status
- `POST /xhunter/tunnel` - Start tunnel
- `GET /xhunter/devices` - List enrolled devices
- `POST /xhunter/enroll` - Enroll a new device
- `POST /xhunter/command` - Send command to device
- `GET /xhunter/logs` - Get device logs

### WebSockets
- `WS /frida/stream/{result_id}` - Stream Frida script output
- `WS /xhunter/stream/{result_id}` - Stream remote command output

## Authentication

All requests require the `X-Auth-Token` header (except `/health`).

Token is set via:
- `AUTH_TOKEN` environment variable, or
- `auth_token` field in `config.json`

With `ALLOW_UNAUTHENTICATED=1`, the server skips auth (for local testing only).

## Deployment Options

### GitHub Actions (Free)
- Push to main branch to auto-build APK + test server
- Create release tags to upload APK as release artifact

### Docker
```bash
docker build -t bugxhunter .
docker run -p 7080:7080 -e AUTH_TOKEN=secret bugxhunter
```

### Tailscale Funnel (Free)
```bash
# On your server
tailscale funnel --hostname=bugxhunter.yourdomain.ts.net http://localhost:7080
```

### Cloudflare Tunnel (Free tier)
```bash
cloudflared tunnel --url http://localhost:7080
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Target Device (with Frida)                                 │
│  ┌──────────────────────────────────────┐                   │
│  │ frida-server (native binary)         │                   │
│  │ Listens on 127.0.0.1:27042           │                   │
│  └──────────────────────────────────────┘                   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  BugXhunter Server                                          │
│  ┌──────────────────────────────────────┐                   │
│  │ Starlette app (bugxhunter_server.py) │                   │
│  │ ├── /frida/* → drives frida-server   │                   │
│  │ └── /xhunter/* → manages SSH tunnels │                   │
│  │     └─→ VPS relay for remote devices  │                   │
│  └──────────────────────────────────────┘                   │
│           Exposes: port 7080                                │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  BugDeck Android App                                        │
│  ┌──────────────────────────────────────┐                   │
│  │ FridaFragment.kt                     │                   │
│  │ ├── UnifiedClient (HTTP API calls)   │                   │
│  │ └── Frida script editor + output     │                   │
│  └──────────────────────────────────────┘                   │
│           Connects: HTTP to BugXhunter server              │
└─────────────────────────────────────────────────────────────┘
```

## Why Starlette (not FastAPI)?

FastAPI requires pydantic v2, whose pydantic-core is a Rust extension with no Android/aarch64 wheel.
Starlette has no compiled dependency, so the whole server runs natively anywhere Python 3 works.

## License

Same as BugDeck - see LICENSE file.
