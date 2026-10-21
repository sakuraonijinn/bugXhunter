"""Device posture checks.

Mirrors the SecurityCheck model from the Android app so the server can run
the same checks on an enrolled target device and return findings in the same
JSON shape.
"""

import os
import re
import shutil
import subprocess
import sys


def _proc_name(pid):
    """The kernel's process name for *pid*, or "" if unreadable."""
    try:
        with open("/proc/{}/comm".format(pid), "r") as handle:
            return handle.read().strip().lower()
    except OSError:
        return ""


def _ancestors(max_depth=12):
    """Walk up the process tree, yielding (pid, comm) pairs."""
    pid = os.getpid()
    seen = set()
    for _ in range(max_depth):
        if pid <= 1 or pid in seen:
            return
        seen.add(pid)
        yield pid, _proc_name(pid)
        try:
            with open("/proc/{}/stat".format(pid), "r") as handle:
                # The comm field is parenthesised and may contain spaces,
                # so parse from the right: state is the field after it.
                stat = handle.read()
                ppid = int(stat.rsplit(")", 1)[1].split()[1])
        except (OSError, IndexError, ValueError):
            return
        pid = ppid


def under_proot() -> bool:
    """True when this process is running inside a PRoot userland.

    PRoot is a ptrace-based userland emulator. A process inside it is
    being traced by the PRoot launcher, and the guest filesystem is a
    Linux root rather than Android's. That changes what the posture
    checks can honestly report, so it is detected up front.

    The ancestor walk matches on the kernel process name, not on
    arbitrary command text. A substring search over a parent's cmdline
    false-positives the moment any argument happens to contain the
    word, which is exactly the kind of bug that makes a check worse
    than useless.
    """
    # 1. Environment markers, set by proot and proot-distro.
    if os.environ.get("PROOT_TMP_DIR") or os.environ.get("PROOT_NO_SECCOMP"):
        return True
    if os.environ.get("PROOT_L2S_DIR"):
        return True

    # 2. An ancestor process is actually named proot.
    for _pid, comm in _ancestors():
        if comm == "proot" or comm.startswith("proot-"):
            return True

    # 3. Guest filesystem marker.
    for marker in ("/.proot", "/etc/proot-distro", "/.proot-distro"):
        if os.path.exists(marker):
            return True

    return False


class PostureCheck:
    """Run device posture checks and return findings."""

    LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    def __init__(self):
        self.findings = []
        self.emulated = under_proot()

    def _add(self, level, category, detail):
        self.findings.append({
            "level": level,
            "category": category,
            "detail": detail,
        })

    # ------------------------------------------------------------------
    # Root / bootloader
    # ------------------------------------------------------------------
    def check_root(self):
        """Detect root access via common indicators."""
        # su binary present?
        for path in ("/system/bin/su", "/system/xbin/su", "/magisk/bin/magisk"):
            if os.path.exists(path):
                self._add("CRITICAL", "posture.root_binary", "Found {}".format(path))
                return
        # magisk manager app?
        try:
            out = subprocess.run(
                ["pm", "list", "packages", "com.topjohnwu.magisk"],
                capture_output=True, text=True, timeout=5,
            )
            if "com.topjohnwu.magisk" in out.stdout:
                self._add("CRITICAL", "posture.magisk", "Magisk manager installed")
                return
        except OSError:
            pass
        # build tags?
        try:
            with open("/build.prop", "r") as handle:
                for line in handle:
                    if "test-keys" in line:
                        self._add("HIGH", "posture.test_keys", "Build is a test-keys build")
                        return
        except OSError:
            pass

    def check_bootloader(self):
        """Check whether the bootloader is unlocked."""
        try:
            out = subprocess.run(
                ["getprop", "ro.boot.bootloader"], capture_output=True, text=True, timeout=5
            )
            status = out.stdout.strip().lower()
            if "unlocked" in status:
                self._add("HIGH", "posture.bootloader_unlocked", "Bootloader is unlocked")
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Debugger / tracing
    # ------------------------------------------------------------------
    def check_debugger(self):
        """Detect attached debuggers.

        Under PRoot this check is meaningless: PRoot is itself a
        tracer, so TracerPid is always non-zero and every guest process
        looks debugged. Reporting that as a HIGH finding would be a
        false positive on every single run, so it is downgraded and
        labelled instead.
        """
        try:
            with open("/proc/self/status", "r") as handle:
                for line in handle:
                    if line.startswith("TracerPid:") and not line.endswith("0"):
                        if self.emulated:
                            self._add(
                                "INFO", "posture.tracer",
                                "TracerPid is non-zero, but this process is "
                                "under PRoot, which traces every syscall. "
                                "Not a debugger finding.",
                            )
                        else:
                            self._add("HIGH", "posture.tracer",
                                      "TracerPid is non-zero")
                        return
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Emulator / spoofing
    # ------------------------------------------------------------------
    def check_emulator(self):
        """Detect emulator indicators."""
        indicators = [
            ("/system/bin/qemu-props", "qemu-props binary"),
            ("/dev/qemu", "qemu device node"),
            ("/system/lib/libhypervisor.so", "hypervisor library"),
        ]
        for path, label in indicators:
            if os.path.exists(path):
                self._add("MEDIUM", "posture.emulator", "Emulator indicator: {}".format(label))
                return
        try:
            with open("/build.prop", "r") as handle:
                for line in handle:
                    if "generic" in line.lower() or "sdk" in line.lower():
                        self._add("MEDIUM", "posture.emulator", "Generic SDK build property")
                        return
        except OSError:
            pass

    # ------------------------------------------------------------------
    # VPN / proxy
    # ------------------------------------------------------------------
    def check_vpn(self):
        """Detect active VPN or proxy tunnels."""
        try:
            out = subprocess.run(
                ["ip", "route"], capture_output=True, text=True, timeout=5
            )
            if "tun" in out.stdout:
                self._add("MEDIUM", "posture.vpn", "Tunnel interface detected")
        except OSError:
            pass
        # DNS hijack?
        try:
            with open("/etc/resolv.conf", "r") as handle:
                for line in handle:
                    if "127.0.0.1" in line or "10.0.0.3" in line:
                        self._add("MEDIUM", "posture.dns_hijack", "DNS points to loopback/emulator")
                        return
        except OSError:
            pass

    # ------------------------------------------------------------------
    # File integrity
    # ------------------------------------------------------------------
    def check_file_integrity(self):
        """Check for tampered system binaries.

        Inside a PRoot guest the Android ``pm`` binary is not on PATH,
        because the guest is a Linux userland. Its absence says nothing
        about the health of the underlying Android system, so under PRoot
        this is informational rather than a HIGH finding.
        """
        if not shutil.which("pm"):
            if self.emulated:
                self._add(
                    "INFO", "posture.missing_pm",
                    "pm is not on PATH inside the PRoot guest. Bind the "
                    "Android system binaries to run this check properly.",
                )
            else:
                self._add("HIGH", "posture.missing_pm",
                          "pm binary missing — system may be broken")

    # ------------------------------------------------------------------
    # Storage encryption
    # ------------------------------------------------------------------
    def check_encryption(self):
        """Check whether storage encryption is enabled."""
        try:
            out = subprocess.run(
                ["getprop", "ro.crypto.state"], capture_output=True, text=True, timeout=5
            )
            state = out.stdout.strip().lower()
            if state != "encrypted":
                self._add("MEDIUM", "posture.no_encryption", "Storage is not encrypted")
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Run all
    # ------------------------------------------------------------------
    def run(self):
        """Run all posture checks and return findings."""
        self.findings = []

        if self.emulated:
            self._add(
                "INFO", "posture.emulated",
                "Running inside a PRoot userland. Checks that depend on "
                "the Android runtime (pm, getprop, build.prop) are "
                "degraded unless the system directories are bound in.",
            )

        for name in (
            "check_root",
            "check_bootloader",
            "check_debugger",
            "check_emulator",
            "check_vpn",
            "check_file_integrity",
            "check_encryption",
        ):
            try:
                getattr(self, name)()
            except Exception as exc:  # pragma: no cover - defensive
                self._add("LOW", "posture.error", "{} failed: {}".format(name, exc))
        return self.findings
