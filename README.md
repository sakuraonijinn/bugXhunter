# bugXhunter

Self-hosted red-team operations hub for the [BugDeck](https://github.com/bugtraqapps/bugDeck) Android app.

Run it on the same device as the app (via Termux) or on a separate VPS. It exposes a small HTTP API for remote posture checks and Frida control, and serves the Frida web UI.

## Features

- **Remote posture checks** — run the same device-fingerprinting checks the Android app does locally, but on an enrolled target device
- **Frida control** — start/stop the Frida server, list devices and processes, execute scripts
- **Reverse SSH tunneling** — tunnel traffic from the target back to the operator host without opening inbound ports
- **VPN routing** — route all server traffic through a VPN tunnel for stealth
- **Web application scanning** — debug-endpoint discovery, CORS checks, security-header audit
- **Vulnerability probes** — differential SQLi, reflected XSS, path traversal, LFI
- **Credential exposure scanning** — find secrets in files and blobs
- **Configuration auditing** — TLS version floors, debug flags, missing security headers

## Quick start

```bash
# On the target device (Termux):
pkg install python-uvicorn
pip install uvicorn starlette aiohttp
git clone https://github.com/bugtraqapps/bugxhunter
cd bugxhunter
cp config.example.json config.json   # edit with your token
python3 -m bugxhunter.server --host 0.0.0.0 --port 7080 --token your-secret
```

Then in the BugDeck Android app, configure the Device tab and Frida tab with the server URL and token.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                bugXhunter Server                      │
│  server.py    ← HTTP API + Frida web UI              │
│  frida.py     ← Frida server lifecycle               │
│  posture.py   ← device fingerprint checks            │
│  vpn.py       ← VPN tunnel routing                   │
│  termux.py    ← Termux package management            │
│  client/      ← smart client with auto-provisioning  │
│    smart.py   ← goal-oriented API                     │
│    reverse_ssh.py ← reverse tunnel support           │
│  scanners/    ← network, web, vuln, cred, config     │
└──────────────────────┬──────────────────────────────┘
                       │  HTTP + X-Auth-Token
                       ▼
┌─────────────────────────────────────────────────────┐
│              BugDeck Android App                      │
│  Device tab  → /diagnose                             │
│  Frida tab   → /frida/page                           │
└─────────────────────────────────────────────────────┘
```

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | no | Link status check |
| GET | `/status` | yes | Server info, Frida status |
| GET | `/diagnose` | yes | Run posture checks |
| GET | `/frida/status` | yes | Frida server state |
| POST | `/frida/start` | yes | Start Frida |
| POST | `/frida/stop` | yes | Stop Frida |
| GET | `/frida/devices` | yes | List devices |
| GET | `/frida/processes` | yes | List processes |
| POST | `/frida/script` | yes | Execute script |
| GET | `/frida/page` | yes | Frida web UI |

## License

MIT
