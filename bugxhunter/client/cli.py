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


def cmd_scan(args, client):
    """Run a scanner."""
    if args.scan_kind == "web":
        _print(client.scan_web(args.url))
    elif args.scan_kind == "vuln":
        _print(client.scan_vuln(args.url))
    elif args.scan_kind == "creds":
        _print(client.scan_credentials(args.url))


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
    for p in scan_sub.choices.values():
        p.add_argument("url", help="target URL or path")

    return parser


HANDLERS = {
    "steps": cmd_steps,
    "status": cmd_status,
    "diagnose": cmd_diagnose,
    "devices": cmd_devices,
    "processes": cmd_processes,
    "frida": cmd_frida,
    "scan": cmd_scan,
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
