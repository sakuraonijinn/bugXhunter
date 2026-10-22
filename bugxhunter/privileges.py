"""Local privilege escalation, when the device offers any.

Three tiers, in descending order:

``root``    — ``su`` is available and grants uid 0.
``shizuku`` — the Shizuku service is running and ``rish`` can run
              commands with shell (uid 2000) privileges.
``plain``   — neither. Whatever the process can see is all there is.

The tiers are not interchangeable. Shizuku gives shell privileges, which
is enough to enumerate packages, read dumpsys output and inspect system
settings. It is *not* enough to ptrace another app's process, so it does
not help with Frida, and it does not replace root.

Everything here degrades to the plain tier, so the server works
unchanged on a device with neither.
"""

import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

ROOT = "root"
SHIZUKU = "shizuku"
PLAIN = "plain"

# Packages worth knowing about on a device being assessed. Matched by
# substring against the package name, so it covers the forks and clones.
KNOWN_PACKAGES = {
    "root": [
        ("com.topjohnwu.magisk", "Magisk"),
        ("eu.chainfire.supersu", "SuperSU"),
        ("com.noshufou.android.su", "SU"),
        ("com.thirdparty.superuser", "Superuser"),
        ("com.koushikdutta.superbackup", "SuperBackup"),
        ("com.geohot.towelroot", "Towelroot"),
        ("me.phh.superuser", "Superuser (Phh)"),
    ],
    "instrumentation": [
        ("io.github.lucasxx44.frida", "Frida"),
        ("com.galaxysnote.appcloner", "App cloner"),
        ("com.lody.xhook", "Xposed"),
        ("de.robv.android.xposed.installer", "Xposed"),
        ("org.meowcat.edxposed.manager", "EdXposed"),
    ],
    "vpn_proxy": [
        ("com.windscribe.vpn", "Windscribe"),
        ("com.protonvpn.android", "ProtonVPN"),
        ("org.torproject.torbrowser", "Tor Browser"),
        ("com.expresVPN", "ExpressVPN"),
        ("com.nordvpn.android", "NordVPN"),
    ],
    "security": [
        ("com.bitdefender.security", "Bitdefender"),
        ("com.mcafee.mobile", "McAfee"),
        ("com.symantec.mobilesecurity", "Avast"),
        ("com.lookout.mobile", "Lookout"),
        ("com.microsoft.emm", "Intune"),
    ],
}


class Privileges:
    """Detect and use the best available elevation."""

    def __init__(self, su_cmd=None, rish_cmd=None):
        self.su_cmd = su_cmd or shutil.which("su")
        self.rish_cmd = rish_cmd or shutil.which("rish")
        self.level = PLAIN
        self._detected = False
        self.evidence = ""

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------
    def detect(self) -> str:
        """Work out the best tier available. Cached after the first call.

        The tier is decided by the uid that is actually reached, not by
        which binary was found. A "su" that is really a wrapper around
        rish reports uid 2000, so it is the shell tier and not root.
        That distinction matters: root can ptrace another app's
        process, shell cannot, and pretending otherwise would send an
        operator down the frida-server path with no way to make it work.
        """
        if self._detected:
            return self.level

        # Root first: it is strictly more capable than shell.
        if self.su_cmd:
            probe = self._run_su("id -u")
            uid = probe.get("stdout", "").strip()
            if probe.get("ok") and uid == "0":
                self.level = ROOT
                self.evidence = "{} gives uid 0".format(self.su_cmd)
                self._detected = True
                return self.level
            if probe.get("ok") and uid:
                # A su that is not root. It is a wrapper of some kind,
                # most likely around rish.
                self.evidence = ("{} gives uid {}, not root".format(
                    self.su_cmd, uid))

        # Shizuku via rish.
        if self.rish_cmd:
            probe = self._run_rish("id -u")
            uid = probe.get("stdout", "").strip()
            if probe.get("ok") and uid.isdigit() and int(uid) >= 2000:
                self.level = SHIZUKU
                self.evidence = "{} gives uid {}".format(self.rish_cmd, uid)
                self._detected = True
                return self.level

        if not self.evidence:
            self.evidence = "no su and no rish on PATH"
        self.level = PLAIN
        self._detected = True
        return self.level

    def report(self) -> Dict[str, Any]:
        """The tier, the evidence behind it, and what to do next."""
        tier = self.detect()
        next_step = {
            ROOT: (
                "Already root. frida-server can be started on the target "
                "and it can attach to other apps."
            ),
            SHIZUKU: (
                "Shell privileges. Enough for package enumeration, dumpsys "
                "and settings, and enough to start a frida-server on a "
                "target that is already root. Not enough to ptrace another "
                "app, so for a non-root target use Frida Gadget instead."
            ),
            PLAIN: (
                "No elevation. The posture checks that need no privilege "
                "still work. For Shizuku, install it and export the rish "
                "files into the Termux prefix; for root, install a su."
            ),
        }[tier]

        return {
            "tier": tier,
            "evidence": self.evidence,
            "su": self.su_cmd or "",
            "rish": self.rish_cmd or "",
            "next_step": next_step,
            "can_ptrace_other_apps": tier == ROOT,
        }

    def is_root(self) -> bool:
        return self.detect() == ROOT

    def is_shizuku(self) -> bool:
        return self.detect() == SHIZUKU

    def is_elevated(self) -> bool:
        """True when commands can run with more than app-level rights."""
        return self.detect() in (ROOT, SHIZUKU)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------
    def _run_su(self, command: str, timeout: int = 15) -> dict:
        return self._spawn([self.su_cmd, "-c", command], timeout)

    def _run_rish(self, command: str, timeout: int = 15) -> dict:
        return self._spawn([self.rish_cmd, "-c", command], timeout)

    @staticmethod
    def _spawn(argv, timeout) -> dict:
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=timeout)
            return {
                "ok": proc.returncode == 0,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "code": proc.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"ok": False, "stdout": "", "stderr": "timeout", "code": -1}
        except OSError as exc:
            return {"ok": False, "stdout": "", "stderr": str(exc), "code": -1}

    def run(self, command: str, timeout: int = 15) -> dict:
        """Run a shell command with the best available privileges.

        Returns ok, stdout, stderr, code and the tier that was used.
        """
        tier = self.detect()
        if tier == ROOT:
            result = self._run_su(command, timeout)
        elif tier == SHIZUKU:
            result = self._run_rish(command, timeout)
        else:
            result = self._spawn(["/system/bin/sh", "-c", command], timeout)
        result["tier"] = tier
        return result

    # ------------------------------------------------------------------
    # Package inspection
    # ------------------------------------------------------------------
    def list_packages(self, extra_args=None) -> List[str]:
        """List installed package names.

        Uses the privileged path when there is one, because an app-level
        ``pm list packages`` cannot see most of what is installed.
        """
        args = ["list", "packages"]
        if extra_args:
            args.extend(extra_args)
        result = self.run("/system/bin/pm " + " ".join(args), timeout=30)
        packages = []
        for line in result.get("stdout", "").splitlines():
            line = line.strip()
            if not line.startswith("package:"):
                continue
            packages.append(line.split("package:", 1)[1].strip())
        return packages

    @staticmethod
    def classify_packages(package_names: List[str]) -> List[dict]:
        """Flag packages that matter for a device assessment."""
        flagged = []
        for name in package_names:
            lowered = name.lower()
            for category, patterns in KNOWN_PACKAGES.items():
                for pattern, label in patterns:
                    if pattern.lower() in lowered:
                        flagged.append({
                            "category": category,
                            "package": name,
                            "label": label,
                        })
                        break
        return flagged

    @staticmethod
    def parse_dumpsys_device_policy(text: str) -> dict:
        """Pull the interesting parts out of dumpsys device_policy."""
        info = {"admins": [], "camera_disabled": False, "password_quality": None}
        for line in text.splitlines():
            stripped = line.strip()
            m = re.search(r"admin=(?:.*?package=)?([\w.]+)", stripped)
            if m:
                info["admins"].append(m.group(1))
            if "cameraDisabled=true" in stripped:
                info["camera_disabled"] = True
            m = re.search(r"passwordQuality=(\w+)", stripped)
            if m:
                info["password_quality"] = m.group(1)
        return info
