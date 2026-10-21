"""Deliver the agent and its hooks to a remote target.

The question this answers is "how do I get the tooling onto a device I
do not have physical access to". The answer is not gists. Gists are
mutable, have no history, and fetching one at execution time is a
remote-code-execution path by design.

What this does instead:

* Bundles the client, which is stdlib-only, plus the hook library into
  a single tarball.
* Pushes it over SSH to the target, using the same reverse-tunnel
  machinery the rest of the client uses.
* Verifies the copy landed by checking the hook library's content hash
  on the far side.

The target needs nothing but Python 3 and SSH. No git, no pip, no
packages. On a locked-down phone that is the difference between
possible and not.
"""

import hashlib
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
from typing import Dict, List, Optional

# The whole package is bundled, not just the client subtree, so the
# relative imports inside it keep working. The client half of the
# package is stdlib-only, so the target needs no pip install.
_HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGE_DIR = os.path.dirname(_HERE)          # .../bugxhunter
PARENT_DIR = os.path.dirname(PACKAGE_DIR)     # the folder that holds it

# Files inside the package that are not worth shipping.
SKIP_DIRS = {"__pycache__", ".git", "templates"}
SKIP_SUFFIXES = (".pyc", ".pyo", ".log")

RUN_SH = """#!/bin/sh
# bugXhunter xbug agent, dropped onto this device.
#
#   ./run.sh hooks list       list the hook library
#   ./run.sh hooks pull       fetch the hooks from the server
#   ./run.sh hooks run <name> --target <app>
#
# The hooks are pulled from the server over the tunnel, so the device
# needs no git and no packages. Python 3 and SSH are enough.
set -e
DIR=$(cd "$(dirname "$0")" && pwd)
export BUGXHUNTER_HOST="${BUGXHUNTER_HOST:-http://127.0.0.1:7080}"
export BUGXHUNTER_TOKEN="${BUGXHUNTER_TOKEN:-}"
cd "$DIR"
exec python3 -m bugxhunter.client "$@"
"""


class Dropper:
    """Build and deliver the agent bundle."""

    def __init__(self, client_dir: str = None, hooks_dir: str = None):
        here = os.path.dirname(os.path.abspath(__file__))
        self.client_dir = client_dir or here
        self.package_dir = os.path.dirname(here)
        self.hooks_dir = hooks_dir or os.path.join(self.package_dir, "hooks")

    # ------------------------------------------------------------------
    # Bundle
    # ------------------------------------------------------------------
    def build(self, dest: str = None) -> str:
        """Build the tarball and return its path."""
        dest = dest or tempfile.mkdtemp(prefix="xbug-drop-")
        os.makedirs(dest, exist_ok=True)
        archive = os.path.join(dest, "xbug-agent.tar.gz")

        with tarfile.open(archive, "w:gz") as tar:
            # The package, laid out so `python3 -m bugxhunter.client`
            # works on the target exactly as it does here.
            for dirpath, dirnames, filenames in os.walk(self.package_dir):
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
                for name in filenames:
                    if name.endswith(SKIP_SUFFIXES):
                        continue
                    full = os.path.join(dirpath, name)
                    rel = os.path.relpath(full, os.path.dirname(self.package_dir))
                    tar.add(full, arcname=rel)

            # The run script.
            info = tarfile.TarInfo("run.sh")
            data = RUN_SH.encode("utf-8")
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))

        return archive

    @staticmethod
    def archive_hash(path: str) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def hooks_version(self) -> str:
        """The content hash of the hook library.

        Computed as the sha256 of a canonical listing, "name hash" per
        line. The target computes the same thing with sha256sum, so the
        two can be compared directly.
        """
        lines = []
        if os.path.isdir(self.hooks_dir):
            for name in sorted(os.listdir(self.hooks_dir)):
                if not name.endswith(".js"):
                    continue
                with open(os.path.join(self.hooks_dir, name), "rb") as handle:
                    digest = hashlib.sha256(handle.read()).hexdigest()
                lines.append("{} {}\n".format(name, digest))
        return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Delivery
    # ------------------------------------------------------------------
    def deliver(self, archive: str, host: str, user: str = "operator",
                port: int = 22, key: str = None, dest_dir: str = "~/xbug",
                timeout: int = 120) -> dict:
        """Copy the bundle to the target over SSH.

        Uses scp, so the target needs an SSH server and nothing else.
        """
        scp = shutil.which("scp")
        if not scp:
            return {"ok": False, "reason": "scp is not available"}

        # Make sure the destination exists first.
        prep = self._ssh(host, user, port, key,
                          "mkdir -p {}".format(dest_dir), timeout=30)
        if not prep.get("ok"):
            return {"ok": False, "reason": "could not create {}: {}".format(
                dest_dir, (prep.get("stderr") or "").strip()[:200])}

        argv = [scp]
        if key:
            argv.extend(["-i", key])
        argv.extend(["-P", str(port),
                     "-o", "StrictHostKeyChecking=no",
                     "-o", "UserKnownHostsFile=/dev/null",
                     "-o", "LogLevel=ERROR",
                     archive, "{}@{}:{}".format(user, host, dest_dir)])
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=timeout)
        except subprocess.TimeoutExpired:
            return {"ok": False, "reason": "scp timed out"}
        except OSError as exc:
            return {"ok": False, "reason": str(exc)}

        if proc.returncode != 0:
            return {"ok": False, "reason": (proc.stderr or "").strip()[:300]}

        # Unpack and verify on the far side.
        unpack = self._ssh(
            host, user, port, key,
            "cd {d} && tar xzf xbug-agent.tar.gz && chmod +x run.sh && "
            "ls -1 bugxhunter/hooks/ 2>/dev/null | wc -l".format(d=dest_dir),
            timeout=60)
        if not unpack.get("ok"):
            return {"ok": False, "reason": "deployed but unpack failed: {}".format(
                (unpack.get("stderr") or "").strip()[:200])}

        remote_count = (unpack.get("stdout") or "").strip()

        # Verify the hook hash on the target matches ours.
        remote_hash = self._ssh(
            host, user, port, key,
            "cd {d}/bugxhunter/hooks 2>/dev/null && for f in *.js; do "
            "printf '%s %s\\n' \"$f\" \"$(sha256sum \"$f\" | cut -d' ' -f1)\"; "
            "done | sha256sum | cut -d' ' -f1".format(d=dest_dir),
            timeout=60)
        remote_version = (remote_hash.get("stdout") or "").strip()

        return {
            "ok": True,
            "host": host,
            "dest_dir": dest_dir,
            "hooks_on_target": remote_count,
            "local_hooks_version": self.hooks_version(),
            "remote_hooks_version": remote_version,
            "verified": bool(remote_version) and remote_version == self.hooks_version(),
        }

    def _ssh(self, host, user, port, key, command, timeout=30) -> dict:
        """Run a command on the target over SSH."""
        ssh = shutil.which("ssh")
        if not ssh:
            return {"ok": False, "stderr": "ssh is not available"}
        argv = [ssh]
        if key:
            argv.extend(["-i", key])
        argv.extend([
            "-p", str(port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", "ConnectTimeout=10",
            "-o", "BatchMode=yes",
            "{}@{}".format(user, host),
            command,
        ])
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=timeout)
            return {"ok": proc.returncode == 0, "stdout": proc.stdout,
                    "stderr": proc.stderr, "code": proc.returncode}
        except subprocess.TimeoutExpired:
            return {"ok": False, "stdout": "", "stderr": "timeout"}
        except OSError as exc:
            return {"ok": False, "stdout": "", "stderr": str(exc)}
