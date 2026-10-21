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
            "name": "Use the Kali tools",
            "where": SERVER,
            "commands": [
                "# what is reachable, and whether it is native or via nethunter",
                "xbug tools",
                "curl -s -H \"X-Auth-Token: $AUTH_TOKEN\" \\",
                "  http://SERVER_HOST:7080/tools",
                "# content discovery with a wordlist",
                "xbug scan web https://target.example --wordlist /path/to/words.txt",
                "# port and service scan",
                "xbug scan ports 10.0.0.42",
            ],
            "expect": (
                "The same scanners as step 8, but sqlmap, nmap, nikto, "
                "gobuster, trufflehog, whatweb and sslscan run alongside "
                "the built-in probes when they are present."
            ),
            "verify": (
                "Findings from a Kali tool carry a category naming it, "
                "such as vuln.sqli or web.nikto."
            ),
        },
        {
            "step": 10,
            "name": "Drop the agent on a target",
            "where": OPERATOR,
            "commands": [
                "# build the bundle and push it over SSH",
                "xbug drop --host 10.0.0.42 --user operator --key ~/.ssh/id_ed25519",
                "# on the target, it is now just:",
                "~/xbug/run.sh hooks list",
                "~/xbug/run.sh hooks pull",
            ],
            "expect": (
                "A 56K tarball with the whole package and the hook "
                "library, unpacked and verified against the local hook "
                "hash."
            ),
            "verify": (
                "delivery.verified is true, and "
                "delivery.remote_hooks_version matches hooks_version."
            ),
        },
        {
            "step": 11,
            "name": "Use the hook library",
            "where": OPERATOR,
            "commands": [
                "xbug hooks list",
                "xbug hooks show ssl_pinning_bypass",
                "xbug hooks pull --dest ./hooks",
                "xbug hooks run ssl_pinning_bypass --target com.example.app",
                "curl -s -H \"X-Auth-Token: $AUTH_TOKEN\" \\",
                "  http://SERVER_HOST:7080/hooks",
                "curl -s -H \"X-Auth-Token: $AUTH_TOKEN\" \\",
                "  http://SERVER_HOST:7080/hooks/root_detection",
            ],
            "expect": (
                "Every hook carries a SHA-256, and the library carries a "
                "version that is the hash of all of them. A finding can "
                "cite the exact script that produced it."
            ),
            "verify": (
                "The version does not change unless a script changes, so "
                "two runs of the same version are comparable."
            ),
        },
        {
            "step": 12,
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
    "privileges": {
        "summary": (
            "The server uses the best local elevation it can find. The "
            "tiers are not interchangeable: root beats shell, and shell "
            "does not help with Frida."
        ),
        "tiers": [
            {
                "level": "root",
                "via": "su",
                "gives": "uid 0. Full control of the device.",
                "enables": "package enumeration, dumpsys, Frida, everything",
            },
            {
                "level": "shizuku",
                "via": "rish",
                "gives": "uid 2000, shell privileges.",
                "enables": (
                    "package enumeration, dumpsys, device admin and "
                    "accessibility state"
                ),
                "does_not_enable": (
                    "ptrace of another app's process, so Frida still needs "
                    "root on the target"
                ),
            },
            {
                "level": "plain",
                "via": "nothing",
                "gives": "the app's own uid.",
                "enables": (
                    "the local posture checks that need no privilege, and "
                    "every network scanner"
                ),
            },
        ],
        "shizuku_setup": [
            "termux-setup-storage",
            "# Shizuku app: 'Use Shizuku in terminal apps' -> Export files",
            "# export rish and rish_shizuku.dex to ~/storage/downloads",
            "cp ~/storage/downloads/rish $PREFIX/bin/",
            "cp ~/storage/downloads/rish_shizuku.dex $PREFIX/lib/",
            "rish            # first run does the binder setup",
            "rish -c 'id -u'   # should print 2000",
        ],
        "check": [
            "xbug status      # 'privileges' field: root, shizuku or plain",
            "curl -s -H \"X-Auth-Token: $AUTH_TOKEN\" \\",
            "  http://SERVER_HOST:7080/status",
        ],
        "note": (
            "Shizuku is orthogonal to the network plane. A VPN or "
            "WireGuard link carries the traffic; Shizuku only decides "
            "how much the server can see about its own device. Use both."
        ),
    },
    "deployment_profiles": {
        "nethunter-kali": {
            "summary": (
                "The server runs in native Termux on the second Android, "
                "with the Kali tools beside it. The server stays out of "
                "the PRoot userland on purpose: Termux API and the "
                "posture checks work natively there, and the Kali tools "
                "are reached through the nethunter wrapper."
            ),
            "install": [
                "termux-setup-storage",
                "pkg install wget",
                "wget -O install-nethunter-termux https://offs.ec/2MceZWr",
                "chmod +x install-nethunter-termux",
                "./install-nethunter-termux",
                "# the toolset, this is the big download",
                "pkg install kali-tools",
                "# or just what you need",
                "pkg install nmap sqlmap nikto gobuster",
            ],
            "layout": {
                "rootfs": "~/kali-arm64 (or kali-armhf on older devices)",
                "kali_cli": "nethunter",
                "kali_root_cli": "nethunter -r",
                "run_one_command": "nethunter <command>",
                "server": "stays in native Termux, not in the proot",
            },
            "run": [
                "export AUTH_TOKEN=your-token",
                "# in native Termux, so termux API and posture checks work",
                "python3 -m bugxhunter.server --host 0.0.0.0 --port 7080",
            ],
            "why_not_in_the_proot": [
                "The server is pure Python. PRoot exists to provide a "
                "glibc userland, and this server does not need one.",
                "Every HTTP probe in a web scan pays a ptrace tax under "
                "PRoot, and a web scan is 45 sequential requests.",
                "termux-location, termux-sms-inbox and friends are Termux "
                "binaries. In the guest they need the prefix bound and on "
                "PATH, which is a bind flag you can forget.",
                "The posture checks read getprop and pm from /system, which "
                "is simpler outside the guest.",
                "nethunter <command> already runs a tool in the Kali "
                "environment, so there is no reason to put the server "
                "there too.",
            ],
            "tool_bridge": [
                "The server uses the Kali tools when it finds them, and "
                "falls back to its own pure-Python scanners when it "
                "does not. Nothing needs configuring.",
                "xbug tools          # what is reachable, and how",
                "GET /tools          # the same, from the server",
                "nmap    -> port, service and version detection",
                "sqlmap  -> real SQL injection testing",
                "nikto   -> web server misconfiguration",
                "gobuster/ffuf -> content discovery",
                "trufflehog/gitleaks -> secret detection, including git history",
                "whatweb -> technology fingerprinting",
                "sslscan / testssl.sh -> TLS configuration",
            ],
            "caveats": [
                "A frida-server still cannot run under PRoot, and cannot "
                "run in Termux without root. The target needs root and "
                "the frida-server binary; point the server at it with "
                "--frida-host.",
                "The Kali rootfs is large. A full kali-linux-default "
                "install is several gigabytes; kali-tools is the "
                "practical minimum.",
                "Kali ships its own python. Install the bugXhunter "
                "dependencies in the Termux python, not the Kali one, "
                "because the server runs in Termux.",
            ],
        },
        "proot-vm": {
            "summary": (
                "bugXhunter on a second Android, inside a plain PRoot "
                "userland. Works, but see the nethunter-kali profile: "
                "this one is only worth it if you already have a PRoot "
                "distro set up."
            ),
            "install": [
                "pkg install proot proot-distro termux-api",
                "proot-distro install ubuntu",
                "proot-distro login ubuntu",
                "apt update && apt install -y python3 python3-pip",
                "pip3 install uvicorn starlette aiohttp",
                "git clone https://github.com/bugtraqapps/bugxhunter && cd bugxhunter",
                "cp config.example.json config.json   # set the token",
            ],
            "binds": [
                "# Termux prefix, so termux-* tools and pkg work in the guest",
                "proot-distro login ubuntu --bind /data/data/com.termux/files/usr",
                "# Android system binaries, so getprop and pm work",
                "proot-distro login ubuntu --bind /system --bind /property",
            ],
            "run": [
                "export AUTH_TOKEN=your-token",
                "# frida_host points at the target, not at the VM",
                "python3 -m bugxhunter.server --host 0.0.0.0 --port 7080 \\",
                "  --frida-host 10.0.0.42",
            ],
            "caveats": [
                "A frida-server cannot run inside PRoot: PRoot already holds "
                "the ptrace slot, so a guest server cannot instrument a host "
                "process. The VM is a Frida *client* only.",
                "TracerPid is always non-zero under PRoot, because PRoot is "
                "the tracer. The posture check reports this as INFO, not a "
                "HIGH debugger finding.",
                "pm and getprop are absent from a bare guest, so the "
                "root, bootloader and encryption checks degrade. Bind "
                "/system and /property to get them working.",
                "Network syscalls pass through unharmed, so binding "
                "0.0.0.0:7080 and making outbound requests both work "
                "normally.",
                "Everything runs slower under ptrace. Lower the scanner "
                "timeout rather than letting probes pile up.",
            ],
        },
    },
    "endpoints": {
        "public": ["GET /health"],
        "token": [
            "GET /status", "GET /diagnose",
            "GET /frida/status", "GET /frida/devices",
            "GET /frida/processes", "GET /frida/results",
            "POST /frida/start", "POST /frida/stop", "POST /frida/script",
            "GET /frida/page",
            "GET /tools", "GET /hooks", "GET /hooks/{name}",
            "POST /hooks/run",
        ],
        "hidden": ["GET /bugSteps"],
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
