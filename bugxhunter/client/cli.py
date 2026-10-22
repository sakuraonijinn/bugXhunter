"""Operator CLI for the bugXhunter client.

    xbug steps                     # print the field guide (works offline)
    xbug status                    # server status
    xbug diagnose                  # posture findings
    xbug devices                   # frida-visible devices
    xbug processes                 # processes on the target
    xbug frida start|stop          # control the target's frida-server
    xbug frida exec <target> <js>  # run a script against a target
    xbug scan web <url>            # web posture scan
    xbug scan vuln <url>           # vulnerability probes

Server connection is read from the environment:

    BUGXHUNTER_HOST   e.g. http://127.0.0.1:7080
    BUGXHUNTER_TOKEN  the X-Auth-Token value
    BUGXHUNTER_SSH    operator SSH host, for the reverse tunnel
    BUGXHUNTER_KEY    SSH private key path
"""

import argparse
import json
import os
import sys

from .smart import SmartClient
from ..tools import ToolBridge


def _client(args, tunnel=True):
    """Build a SmartClient from args and environment."""
    ssh_host = args.ssh or os.environ.get("BUGXHUNTER_SSH")
    ssh_key = args.key or os.environ.get("BUGXHUNTER_KEY")
    return SmartClient(
        host=args.host,
        token=args.token,
        ssh_host=ssh_host if tunnel else None,
        ssh_user=args.user or os.environ.get("BUGXHUNTER_USER", "operator"),
        ssh_key=ssh_key,
    )


def _print(obj):
    if isinstance(obj, (dict, list)):
        print(json.dumps(obj, indent=2, default=str))
    else:
        print(obj)


def cmd_steps(args, client):
    """Print the field guide. Deliberately works without a server."""
    from ..steps import guide
    _print(guide())


def cmd_status(args, client):
    """Server status. Does not wait for Frida to come up."""
    server_ok = client.ensure_server()
    _print({
        "server": {
            "host": client.host,
            "reachable": server_ok,
            "error": client.last_error,
        },
        "frida": client.frida.status(),
    })


def cmd_diagnose(args, client):
    """Posture findings."""
    _print(client.diagnose())


def cmd_devices(args, client):
    """Frida-visible devices."""
    client.ensure_ready()
    _print(client.frida.list_devices())


def cmd_processes(args, client):
    """Processes on the target."""
    client.ensure_ready()
    _print(client.frida.list_processes())


def cmd_frida(args, client):
    """Control the target's frida-server."""
    if args.frida_action == "start":
        client.ensure_server()
        _print(client._start_frida_on_target())
        return
    if not client.ensure_ready():
        _print({"ok": False, "error": client.last_error})
        return
    if args.frida_action == "stop":
        _print(client.frida.stop())
    elif args.frida_action == "exec":
        _print(client.frida_execute(args.target, args.script))


def cmd_gadget(args, client):
    """Rootless instrumentation: patch an APK to carry Frida Gadget."""
    from .gadget import GadgetError, GadgetTool
    tool = GadgetTool()

    if args.gadget_action == "check":
        report = tool.check_tools()
        _print({
            "tools": report,
            "missing_required": tool.missing_required(),
            "note": ("apktool is required. apksigner gives a v2/v3 "
                     "signature; jarsigner gives a v1 signature, which some "
                     "devices will not accept."),
        })
        return

    if args.gadget_action == "config":
        _print(tool.gadget_config(port=args.port, address=args.address))
        return

    if args.gadget_action == "build":
        try:
            result = tool.instrument(
                args.apk, abi=args.abi, version=args.version,
                port=args.port, address=args.address, aapt=args.aapt)
        except GadgetError as exc:
            _print({"ok": False, "error": str(exc)})
            raise SystemExit(1)
        _print(result)
        return

    if args.gadget_action == "install":
        try:
            _print(tool.install(args.apk, device=args.device))
            if args.forward:
                _print(tool.forward(port=args.port, device=args.device))
        except GadgetError as exc:
            _print({"ok": False, "error": str(exc)})
            raise SystemExit(1)
        return

    if args.gadget_action == "forward":
        try:
            _print(tool.forward(port=args.port, device=args.device))
        except GadgetError as exc:
            _print({"ok": False, "error": str(exc)})
            raise SystemExit(1)
        return


def cmd_vpn(args, client):
    """Report or change the outbound traffic routing."""
    import json as _json
    import urllib.request
    url = client.host.rstrip("/") + "/vpn"
    data = None
    if args.mode:
        data = args.mode.encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    if client.token:
        req.add_header("X-Auth-Token", client.token)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            _print(_json.loads(resp.read().decode("utf-8", "replace")))
    except Exception as exc:
        _print({"error": str(exc)})


def cmd_termux(args, client):
    """Report the Termux device state."""
    import json as _json
    import urllib.request
    url = client.host.rstrip("/") + "/termux"
    if args.limit:
        url += "?limit={}".format(int(args.limit))
    req = urllib.request.Request(url)
    if client.token:
        req.add_header("X-Auth-Token", client.token)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            _print(_json.loads(resp.read().decode("utf-8", "replace")))
    except Exception as exc:
        _print({"error": str(exc)})


def cmd_hooks(args, client):
    """List, show, pull or run the Frida hook library."""
    from ..hooks import HookLibrary
    library = HookLibrary()

    if args.hooks_action == "lint":
        from ..hooks.lint import lint_directory
        results = lint_directory()
        failed = [r for r in results if not r.ok]
        _print({
            "checked": len(results),
            "failed": len(failed),
            "results": [r.as_dict() for r in results if not r.ok or r.warnings],
        })
        if failed:
            raise SystemExit(1)
        return

    if args.hooks_action == "list":
        manifest = library.manifest()
        _print({
            "version": manifest["version"],
            "git_commit": manifest["git_commit"],
            "count": manifest["count"],
            "hooks": [
                {"name": h["name"], "sha256": h["sha256"],
                 "description": h["description"]}
                for h in manifest["hooks"]
            ],
        })
        return

    if args.hooks_action == "show":
        meta = library.get(args.name)
        if not meta:
            _print({"error": "no such hook: {}".format(args.name)})
            return
        _print({
            "name": meta["name"],
            "sha256": meta["sha256"],
            "size": meta["size"],
            "description": meta["description"],
            "run": meta["run"],
            "script": library.read(args.name),
        })
        return

    if args.hooks_action == "pull":
        dest = args.dest or "hooks"
        os.makedirs(dest, exist_ok=True)
        pulled = []
        for meta in library.list():
            text = library.read(meta["name"])
            if text is None:
                continue
            path = os.path.join(dest, meta["name"])
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
            pulled.append({"name": meta["name"], "sha256": meta["sha256"],
                           "path": path})
        _print({"pulled": len(pulled), "dest": dest, "hooks": pulled,
                "version": library.version()})
        return

    if args.hooks_action == "run":
        meta = library.get(args.name)
        if not meta:
            _print({"error": "no such hook: {}".format(args.name)})
            return
        if not args.target:
            _print({"error": "a target process is required, e.g. --target com.example.app"})
            return
        result = client.frida_execute(args.target, meta["path"])
        if result is None:
            _print({"ok": False, "error": client.last_error or "frida not ready"})
            return
        result["hook"] = meta["name"]
        result["sha256"] = meta["sha256"]
        _print(result)
        return


def cmd_drop(args, client):
    """Build the agent bundle and deliver it to a remote target."""
    from .drop import Dropper
    dropper = Dropper()
    archive = dropper.build()
    result = {
        "built": archive,
        "sha256": dropper.archive_hash(archive),
        "hooks_version": dropper.hooks_version(),
    }
    if not args.host:
        result["error"] = ("no target given, so the bundle was only built; "
                           "add --host to deliver it")
        _print(result)
        return
    result["delivery"] = dropper.deliver(
        archive, host=args.host, user=args.user or "operator",
        port=args.port, key=args.key, dest_dir=args.dest or "~/xbug")
    _print(result)


def cmd_tools(args, client):
    """List the reachable Kali tools."""
    bridge = ToolBridge()
    report = bridge.available()
    _print({
        "kali_root": bridge.kali_root,
        "nethunter": bridge._nethunter_path() is not None,
        "available": [n for n, m in report.items() if m["available"]],
        "tools": report,
    })


def cmd_scan(args, client):
    """Run a scanner."""
    bridge = ToolBridge()
    if args.scan_kind == "web":
        _print(client.scan_web(args.url, tools=bridge, wordlist=args.wordlist))
    elif args.scan_kind == "vuln":
        _print(client.scan_vuln(args.url, tools=bridge))
    elif args.scan_kind == "creds":
        _print(client.scan_credentials(args.url, tools=bridge))
    elif args.scan_kind == "ports":
        _print(client.scan_ports(args.url, tools=bridge))


def build_parser():
    parser = argparse.ArgumentParser(
        prog="xbug", description="bugXhunter operator client")
    parser.add_argument("--host", default=os.environ.get(
        "BUGXHUNTER_HOST", "http://127.0.0.1:7080"))
    parser.add_argument("--token", default=os.environ.get("BUGXHUNTER_TOKEN"))
    parser.add_argument("--ssh", help="operator SSH host for the reverse tunnel")
    parser.add_argument("--user", help="SSH user (default: operator)")
    parser.add_argument("--key", help="SSH private key path")

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("steps", help="print the operator field guide")
    sub.add_parser("status", help="server and Frida status")
    sub.add_parser("diagnose", help="run posture checks")
    sub.add_parser("devices", help="list Frida-visible devices")
    sub.add_parser("processes", help="list processes on the target")
    sub.add_parser("tools", help="list reachable Kali tools")

    hooks = sub.add_parser("hooks", help="the Frida hook library")
    hooks_sub = hooks.add_subparsers(dest="hooks_action", required=True)
    hooks_sub.add_parser("list", help="list the hooks with their hashes")
    hooks_sub.add_parser("lint", help="statically check the hooks")
    hs = hooks_sub.add_parser("show", help="show one hook")
    hs.add_argument("name", help="hook name, with or without the .js")
    hp = hooks_sub.add_parser("pull", help="copy the hooks to a directory")
    hp.add_argument("--dest", help="destination directory (default: hooks)")
    hr = hooks_sub.add_parser("run", help="run a hook against a target")
    hr.add_argument("name", help="hook name")
    hr.add_argument("--target", help="target process or package name")

    drop = sub.add_parser("drop", help="deliver the agent to a remote target")
    drop.add_argument("--host", help="target SSH host")
    drop.add_argument("--user", help="SSH user (default: operator)")
    drop.add_argument("--port", type=int, default=22, help="SSH port")
    drop.add_argument("--key", help="SSH private key path")
    drop.add_argument("--dest", help="destination directory (default: ~/xbug)")

    gadget = sub.add_parser("gadget", help="rootless APK instrumentation")
    gadget_sub = gadget.add_subparsers(dest="gadget_action", required=True)
    gadget_sub.add_parser("check", help="report the host tools that are present")
    gc = gadget_sub.add_parser("config", help="print the gadget config")
    gc.add_argument("--port", type=int, default=27042)
    gc.add_argument("--address", default="127.0.0.1")
    gb = gadget_sub.add_parser("build", help="rebuild the APK with the gadget")
    gb.add_argument("apk", help="path to the APK to instrument")
    gb.add_argument("--abi", default="arm64",
                    choices=("arm64", "arm", "x86_64", "x86"))
    gb.add_argument("--version", default="17.24.3",
                    help="the Frida version the gadget must match")
    gb.add_argument("--port", type=int, default=27042)
    gb.add_argument("--address", default="127.0.0.1")
    gb.add_argument("--aapt", help="path to an aapt2 for this architecture")
    gi = gadget_sub.add_parser("install", help="install the instrumented APK")
    gi.add_argument("apk", help="path to the signed APK")
    gi.add_argument("--device", help="adb device serial")
    gi.add_argument("--port", type=int, default=27042)
    gi.add_argument("--forward", action="store_true",
                    help="also forward the gadget port over adb")
    gf = gadget_sub.add_parser("forward", help="forward the gadget port")
    gf.add_argument("--port", type=int, default=27042)
    gf.add_argument("--device", help="adb device serial")

    vpn = sub.add_parser("vpn", help="report or change the traffic routing")
    vpn.add_argument("--mode", choices=("auto", "off", "proxy", "tun"),
                     help="routing mode to apply")

    termux = sub.add_parser("termux", help="report the Termux device state")
    termux.add_argument("--limit", type=int, help="how many SMS to read")

    frida = sub.add_parser("frida", help="control the target's frida-server")
    frida_sub = frida.add_subparsers(dest="frida_action", required=True)
    frida_sub.add_parser("start", help="start frida-server on the target")
    frida_sub.add_parser("stop", help="stop frida-server on the target")
    ex = frida_sub.add_parser("exec", help="execute a script")
    ex.add_argument("target", help="process name or package")
    ex.add_argument("script", help="path to a Frida .js script")

    scan = sub.add_parser("scan", help="run a scanner")
    scan_sub = scan.add_subparsers(dest="scan_kind", required=True)
    scan_sub.add_parser("web", help="web posture scan")
    scan_sub.add_parser("vuln", help="vulnerability probes")
    scan_sub.add_parser("creds", help="credential exposure scan")
    scan_sub.add_parser("ports", help="port and service scan")
    for p in scan_sub.choices.values():
        p.add_argument("url", help="target URL, host or path")
        p.add_argument("--wordlist", help="wordlist for content discovery")

    return parser


HANDLERS = {
    "steps": cmd_steps,
    "status": cmd_status,
    "diagnose": cmd_diagnose,
    "devices": cmd_devices,
    "processes": cmd_processes,
    "frida": cmd_frida,
    "scan": cmd_scan,
    "tools": cmd_tools,
    "hooks": cmd_hooks,
    "drop": cmd_drop,
    "vpn": cmd_vpn,
    "termux": cmd_termux,
    "gadget": cmd_gadget,
}


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 2

    handler = HANDLERS.get(args.command)
    if handler is None:
        parser.print_help()
        return 2

    # `steps` is pure local content, so do not open a tunnel for it.
    client = _client(args, tunnel=(args.command != "steps"))

    try:
        handler(args, client)
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 130
    finally:
        if args.command != "steps":
            client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
