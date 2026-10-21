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
│  http.py      ← HTTP client for the scanners         │
│  client/      ← smart client with auto-provisioning  │
│    smart.py   ← goal-oriented API                     │
│    reverse_ssh.py ← reverse tunnel support           │
│    cli.py     ← operator CLI (`python3 -m bugxhunter.client`) │
│  steps.py     ← operator field guide (hidden)        │
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

## Working against a remote target

Three roles, one tunnel:

```
Target (frida-server :27042)
   │  ssh -N -R 27042:localhost:27042 operator@host     ← outbound, target-initiated
   ▼
Operator (127.0.0.1:27042 → target :27042)               ← FridaClient binds here
   │
   ▼
Server host (:7080)   ← /status, /diagnose, /frida/* API
```

The target never needs an inbound port. It dials the operator, and the
operator's `27042` is forwarded to the target's Frida server, so
`FridaClient` reaches the target transparently through `127.0.0.1`.

Two forwards are carried by a single SSH process: `7080` for the server
API and `27042` for Frida. Starting `frida-server` happens *on the
target* over SSH — spawning it locally is the one move that looks right
and silently does nothing.

## Local privileges (root / Shizuku)

The server uses the best local elevation it can find, and reports which
tier it got in `/status` under `privileges`.

| Tier | Via | Gives | Enables |
|------|-----|-------|---------|
| `root` | `su` | uid 0 | everything, including Frida |
| `shizuku` | `rish` | uid 2000, shell | package enumeration, `dumpsys`, device-admin and lock-screen state |
| `plain` | — | the app's own uid | the unprivileged posture checks and every network scanner |

The tiers are **not** interchangeable. Shizuku gives shell privileges,
which is enough to enumerate packages and read `dumpsys` output. It is
*not* enough to ptrace another app's process, so **it does not help
with Frida** — the target still needs root and the `frida-server` binary.

Set up Shizuku so Termux can use it:

```bash
termux-setup-storage
# In the Shizuku app: "Use Shizuku in terminal apps" -> Export files
cp ~/storage/downloads/rish $PREFIX/bin/
cp ~/storage/downloads/rish_shizuku.dex $PREFIX/lib/
rish                    # first run does the binder setup
rish -c 'id -u'         # should print 2000
```

With that in place the posture checks enumerate installed packages,
flag Magisk/Frida/VPN apps, list debuggable apps and read the device
administrator and lock-screen state — none of which an app-level check
can see.

**This is orthogonal to the network plane.** A VPN or WireGuard link
carries the traffic; Shizuku only decides how much the server can see
about its own device. Use both, for different jobs.

## Running the server on a PRoot VM (second Android)

A PRoot userland on another Android makes a cheap, self-contained server.
It is a Linux box, though, and three things follow from that.

**A frida-server cannot run inside PRoot.** PRoot already occupies the
ptrace slot, so a frida-server spawned in the guest cannot instrument a
host process. The VM must therefore be a Frida *client*: point it at a
frida-server running natively on the target.

```bash
pkg install proot proot-distro termux-api
proot-distro install ubuntu
proot-distro login ubuntu

apt update && apt install -y python3 python3-pip
pip3 install uvicorn starlette aiohttp
git clone https://github.com/bugtraqapps/bugxhunter && cd bugxhunter
cp config.example.json config.json    # set the token
```

Bind the Termux prefix so `termux-*` tools and `pkg` work in the guest,
and bind `/system` and `/property` so `pm` and `getprop` work:

```bash
proot-distro login ubuntu --bind /data/data/com.termux/files/usr
proot-distro login ubuntu --bind /system --bind /property
```

Then point the Frida client at the target and start the server:

```bash
export AUTH_TOKEN=your-token
python3 -m bugxhunter.server --host 0.0.0.0 --port 7080 --frida-host 10.0.0.42
```

| | Native Android / Termux | PRoot VM |
|---|---|---|
| Frida | spawns `frida-server` locally | drives a remote one; `start()` refuses with a reason |
| Network | works | works — socket syscalls pass through |
| `TracerPid` check | meaningful | always non-zero, PRoot is the tracer → reported as INFO |
| `pm` / `getprop` checks | meaningful | degrade to INFO unless `/system` is bound |
| Speed | native | slower, everything is under ptrace |

`/status` reports `emulated: true` when it detects a PRoot userland, and
`frida.mode` reports `local` or `remote`.

## The hook library

Nine Frida scripts ship in `bugxhunter/hooks/`, each with a header saying what it does and how to run it:

| Hook | What it does |
|------|--------------|
| `ssl_pinning_bypass` | defeats certificate pinning (OkHttp, Conscrypt, TrustManager) |
| `root_detection` | finds how the app decides it is rooted, and prints the stack for each check |
| `crypto_hook` | captures keys, plaintext and ciphertext from the JCA |
| `keystore_hook` | watches Android Keystore use, flags software keys |
| `network_capture` | shows requests and responses without a proxy in the path |
| `file_access` | watches disk reads and writes, plus every SQL statement |
| `shared_prefs_dump` | dumps SharedPreferences and watches writes |
| `anti_debug_bypass` | stops the app noticing it is being instrumented |
| `method_trace` | traces every call to one class, with timings |

```bash
xbug hooks list
xbug hooks show ssl_pinning_bypass
xbug hooks pull --dest ./hooks
xbug hooks run ssl_pinning_bypass --target com.example.app
```

The server serves them too, so a target can pull them over the tunnel without git:

```
GET /hooks              manifest: every hook with its SHA-256
GET /hooks/{name}       one script, with its hash
POST /hooks/run         {"hook": "...", "target": "com.example.app"}
```

**Why not gists.** A gist is mutable and has no history, so "the script was in a gist" is not evidence of what ran against a target. A gist URL fetched at execution time is a remote-code-execution path by design — anyone who can edit the gist runs code on your target. Here every hook carries a SHA-256 and the library carries a version that is the hash of all of them, so a finding cites an exact script and two runs of the same version are comparable.

### Checking the hooks without a device

The hooks need a live app to run against, which makes it easy to ship one that never installs a single hook. `xbug hooks lint` checks them statically:

```bash
$ xbug hooks lint
{"checked": 10, "failed": 0, "results": []}
```

It catches the failure modes that otherwise only show up on a target:

- **syntax errors** — parsed with `node --check`
- **hooks on a dispatcher** — `X.method.overload(...).implementation = ...` throws at runtime when the method is overloaded; the overload has to be saved first
- **self-recursion** — a replacement that calls the method it replaces
- **the same method hooked twice** in one file, which nests the replacements
- **no `Purpose:`/`Usage:` header**, so a reader cannot tell what the script does

Each hook is also required to print a completion message, so a *partial* install is visible in the output rather than looking like a clean run. A hook that skips a target says so:

```
[ssl-pinning] skipped com.android.org.conscrypt.TrustManagerImpl.checkTrustedRecursive: ...
```

When a hook fails with "no such overload", the reason is almost always a version difference. `discover_overloads` prints the real signatures for the build you actually have:

```bash
xbug hooks run discover_overloads --target com.example.app --class com.example.Api
```

## Dropping the agent on a target

The client is **stdlib-only** — no third-party imports anywhere in `bugxhunter/client/`. So the target needs nothing but Python 3 and SSH. No git, no pip, no packages.

```bash
xbug drop --host 10.0.0.42 --user operator --key ~/.ssh/id_ed25519
```

That builds a 56K tarball of the whole package, pushes it over `scp`, unpacks it, and **verifies the hook library's content hash on the far side matches the local one** — so you know the scripts on the device are the scripts you reviewed.

```bash
# on the target
~/xbug/run.sh hooks list
~/xbug/run.sh hooks pull
```

## Operator CLI

```bash
export BUGXHUNTER_HOST=http://server-host:7080
export BUGXHUNTER_TOKEN=your-token
export BUGXHUNTER_SSH=operator-host        # for the reverse tunnel
export BUGXHUNTER_KEY=~/.ssh/id_ed25519

python3 -m bugxhunter.client steps          # the field guide, works offline
python3 -m bugxhunter.client status         # server + Frida state
python3 -m bugxhunter.client diagnose       # posture findings
python3 -m bugxhunter.client devices        # Frida-visible devices
python3 -m bugxhunter.client frida start    # start frida-server on the target
python3 -m bugxhunter.client frida exec com.example.app hook.js
python3 -m bugxhunter.client scan web https://target.example
```

## The field guide

`bugSteps` is the operator's field guide: nine phases from standing up
the server to tearing down, each with the command, the expected result
and a verification, plus troubleshooting for the five failure modes that
actually bite.

It is served from a hidden endpoint and is deliberately absent from
`/status`, so a casual endpoint sweep will not find it. It is still
token-gated.

```bash
curl -s -H "X-Auth-Token: $BUGXHUNTER_TOKEN" \
  http://$BUGXHUNTER_HOST/bugSteps
```

The same content is bundled locally, so `xbug steps` works with no
server running.

## License

MIT
