"""Operational guide for the bugXhunter suite.

Kept in its own module so the server can serve it without importing the
client or the scanners, and so the text can be regenerated/verified
independently of the HTTP layer.

The guide is intentionally terse: it is meant to be read on a phone screen
during an engagement, not as documentation.
"""

# Role names, used as keys throughout the guide.
SERVER = "server-host"
OPERATOR = "operator"
TARGET = "target-device"

GUIDE = {
    "command": "bugSteps",
    "version": "1.0.0",
    "summary": (
        "Three roles, one tunnel. The server host exposes the API, the "
        "operator drives it, the target runs Frida and dials out. The "
        "reverse SSH tunnel is the only thing that has to work."
    ),
    "roles": {
        SERVER: {
            "runs": "python3 -m bugxhunter.server --host 0.0.0.0 --port 7080",
            "needs": "Python 3.8+, starlette, uvicorn",
            "exposes": "HTTP API on :7080, token-gated",
        },
        OPERATOR: {
            "runs": "SmartClient + frida CLI + ssh",
            "needs": "SSH key to the target, bugxhunter installed",
            "exposes": "Nothing. Issues every request.",
        },
        TARGET: {
            "runs": "frida-server :27042, xbug agent",
            "needs": "root, frida-server binary at /data/local/tmp/frida-server",
            "exposes": "Nothing inbound. Dials the operator.",
        },
    },
    "phases": [
        {
            "step": 1,
            "name": "Stand up the server",
            "where": SERVER,
            "commands": [
                "export AUTH_TOKEN=$(openssl rand -hex 16)",
                "python3 -m bugxhunter.server --host 0.0.0.0 --port 7080",
            ],
            "expect": "Server binds :7080. AUTH_TOKEN gates everything but /health.",
            "verify": "curl -s http://127.0.0.1:7080/health  ->  {\"ok\":true,...}",
        },
        {
            "step": 2,
            "name": "Provision the target",
            "where": TARGET,
            "commands": [
                "# frida-server binary must be at this exact path",
                "ls -l /data/local/tmp/frida-server",
                "adb push frida-server /data/local/tmp/frida-server",
                "adb shell chmod 755 /data/local/tmp/frida-server",
            ],
            "expect": "Binary present and executable.",
            "verify": "adb shell /data/local/tmp/frida-server --version",
        },
        {
            "step": 3,
            "name": "Open the reverse tunnel",
            "where": TARGET,
            "commands": [
                "# target dials out; no inbound ports needed on the target",
                "ssh -i operator_key -p 22 -N \\",
                "  -R 27042:localhost:27042 \\",
                "  -R 7080:localhost:7080 \\",
                "  operator@OPERATOR_HOST",
            ],
            "expect": (
                "Operator's 127.0.0.1:27042 now reaches the target's Frida "
                "server; operator's :7080 reaches the target's agent."
            ),
            "verify": "On the operator: nc -z 127.0.0.1 27042  ->  open",
        },
        {
            "step": 4,
            "name": "Verify the link",
            "where": OPERATOR,
            "commands": [
                "curl -s http://SERVER_HOST:7080/health",
                "curl -s -H \"X-Auth-Token: $AUTH_TOKEN\" \\",
                "  http://SERVER_HOST:7080/status",
                "frida-ps -D 127.0.0.1:27042",
            ],
            "expect": "health ok, status 200, frida-ps lists the target's processes.",
            "verify": "frida-ps output is non-empty",
        },
        {
            "step": 5,
            "name": "Run posture checks",
            "where": OPERATOR,
            "commands": [
                "curl -s -H \"X-Auth-Token: $AUTH_TOKEN\" \\",
                "  http://SERVER_HOST:7080/diagnose",
            ],
            "expect": "JSON list of findings, each with level/category/detail.",
            "verify": "Compare against the previous run to spot new findings.",
        },
        {
            "step": 6,
            "name": "Start Frida on the target",
            "where": TARGET,
            "commands": [
                "adb shell su -c '/data/local/tmp/frida-server --no-pause &'",
            ],
            "expect": "Frida server listening on the target's :27042.",
            "verify": (
                "curl -s -H \"X-Auth-Token: $AUTH_TOKEN\" "
                "http://SERVER_HOST:7080/frida/status  ->  running:true"
            ),
        },
        {
            "step": 7,
            "name": "Execute instrumentation",
            "where": OPERATOR,
            "commands": [
                "curl -s -X POST -H \"X-Auth-Token: $AUTH_TOKEN\" \\",
                "  -H 'Content-Type: application/json' \\",
                "  -d '{\"target\":\"com.example.app\",\"script\":\"/path/hook.js\"}' \\",
                "  http://SERVER_HOST:7080/frida/script",
                "# or drive it from Python",
                "from bugxhunter.client.smart import SmartClient",
                "c = SmartClient(host='http://SERVER_HOST:7080', token=TOKEN)",
                "c.ensure_ready()",
                "c.frida_execute('com.example.app', 'hook.js')",
            ],
            "expect": "ok:true with the script's stdout captured.",
            "verify": "Response body contains the hook's output.",
        },
        {
            "step": 8,
            "name": "Run the web scanners",
            "where": OPERATOR,
            "commands": [
                "from bugxhunter.client.smart import SmartClient",
                "c = SmartClient(host='http://SERVER_HOST:7080', token=TOKEN)",
                "c.scan_web('https://target.example')",
                "c.scan_vuln('https://target.example/id=1')",
                "c.scan_credentials('/path/to/repo')",
            ],
            "expect": "Per-target finding lists with verdicts, never silent passes.",
            "verify": "BLOCKED/SKIPPED results are treated as inconclusive.",
        },
        {
            "step": 9,
            "name": "Teardown",
            "where": OPERATOR,
            "commands": [
                "curl -s -X POST -H \"X-Auth-Token: $AUTH_TOKEN\" \\",
                "  http://SERVER_HOST:7080/frida/stop",
                "# kill the tunnel and the remote frida-server",
                "adb shell su -c 'pkill -f frida-server'",
            ],
            "expect": "Frida stopped, tunnel closed, no residue on the target.",
            "verify": "curl /frida/status  ->  running:false",
        },
    ],
    "endpoints": {
        "public": ["GET /health"],
        "token": [
            "GET /status", "GET /diagnose",
            "GET /frida/status", "GET /frida/devices",
            "GET /frida/processes", "GET /frida/results",
            "POST /frida/start", "POST /frida/stop", "POST /frida/script",
            "GET /frida/page",
        ],
    },
    "troubleshooting": [
        {
            "symptom": "frida-ps says 'unable to connect'",
            "cause": "Tunnel up but frida-server not started on the target.",
            "fix": "adb shell su -c '/data/local/tmp/frida-server --no-pause &'",
        },
        {
            "symptom": "SSH exits immediately",
            "cause": "Key not accepted, or RemoteForward refused on the operator.",
            "fix": "ssh -v -i KEY -N -R 27042:localhost:27042 user@host, read the log",
        },
        {
            "symptom": "401 on every call",
            "cause": "Token mismatch between server env and client header.",
            "fix": "Server reads AUTH_TOKEN from env; confirm both sides match.",
        },
        {
            "symptom": "/frida/status reports port closed but frida-ps works",
            "cause": "Status is checked on the server host, frida-ps on the operator.",
            "fix": "Tunnel :27042 to the server host too, or check from the operator.",
        },
        {
            "symptom": "frida script returns ok:false",
            "cause": "Target process name wrong, or script errored on load.",
            "fix": "frida-ps to get the exact name; check stderr in the response.",
        },
    ],
}


def guide():
    """Return the operational guide."""
    return GUIDE
