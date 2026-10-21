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


class PostureCheck:
    """Run device posture checks and return findings."""

    LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    def __init__(self):
        self.findings = []

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
        """Detect attached debuggers."""
        try:
            with open("/proc/self/status", "r") as handle:
                for line in handle:
                    if line.startswith("TracerPid:") and not line.endswith("0"):
                        self._add("HIGH", "posture.tracer", "TracerPid is non-zero")
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
        """Check for tampered system binaries."""
        # If pm is missing, the system is likely broken or heavily modified.
        if not shutil.which("pm"):
            self._add("HIGH", "posture.missing_pm", "pm binary missing — system may be broken")

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
