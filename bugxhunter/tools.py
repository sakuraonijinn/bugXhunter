"""Bridge to Kali tooling, when it is available.

The built-in scanners are pure Python and always work. But they are
deliberately small: a differential SQLi probe, a banner grab, a list of
debug paths. The Kali tools do those jobs far better, and the operator
running a NetHunter box has them sitting right there.

So the bridge does two things:

1. Works out which tools are actually reachable. A tool might be on
   PATH natively, or it might live inside the NetHunter rootfs and have
   to be reached through the ``nethunter`` wrapper.
2. Runs them, with a timeout, and parses the output into the same
   finding shape the built-in scanners use.

Everything degrades to the built-in path when a tool is missing. Nothing
here is required for the suite to function.
"""

import os
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple

# Tools worth reaching for, with the built-in scanner each one improves
# on. "replaces" means the Kali tool is strictly better and should be
# preferred when present.
KALI_TOOLS: Dict[str, dict] = {
    "nmap": {
        "purpose": "port, service and version detection",
        "improves": "network",
        "command": ["nmap", "-sV", "-Pn", "--top-ports", "100", "-oX", "-"],
    },
    "sqlmap": {
        "purpose": "real SQL injection testing",
        "improves": "vuln",
        "command": ["sqlmap", "-u", "", "--batch", "--risk=1", "--level=1",
                    "--timeout=10", "--retries=1"],
    },
    "nikto": {
        "purpose": "web server misconfiguration scan",
        "improves": "web",
        "command": ["nikto", "-h", "", "-Format", "json", "-nointeractive"],
    },
    "gobuster": {
        "purpose": "directory and file discovery",
        "improves": "web",
        "command": ["gobuster", "dir", "-u", "", "-w", "", "-q", "--no-error"],
    },
    "ffuf": {
        "purpose": "directory and file discovery (gobuster alternative)",
        "improves": "web",
        "command": ["ffuf", "-u", "", "-w", "", "-noninteractive", "-s"],
    },
    "trufflehog": {
        "purpose": "secret detection in files and git history",
        "improves": "credential",
        "command": ["trufflehog", "filesystem", "", "--json"],
    },
    "gitleaks": {
        "purpose": "secret detection in git history (trufflehog alternative)",
        "improves": "credential",
        "command": ["gitleaks", "detect", "--source", "", "--report-format",
                    "json", "--no-banner", "-r"],
    },
    "whatweb": {
        "purpose": "web technology fingerprinting",
        "improves": "web",
        "command": ["whatweb", "--log-json=-", ""],
    },
    "sslscan": {
        "purpose": "TLS configuration audit",
        "improves": "config_audit",
        "command": ["sslscan", "--no-colour", ""],
    },
    "testssl.sh": {
        "purpose": "deep TLS configuration audit",
        "improves": "config_audit",
        "command": ["testssl.sh", "--jsonfile-pretty", "/dev/stdout", ""],
    },
    "nikto_alt": {},  # placeholder removed below
}
KALI_TOOLS.pop("nikto_alt")

# The NetHunter rootfs, where the Kali binaries live.
KALI_ROOTS = ("kali-arm64", "kali-armhf", "kali")


def _kali_root() -> Optional[str]:
    """Locate the NetHunter rootfs, if this box has one."""
    home = os.path.expanduser("~")
    for name in KALI_ROOTS:
        candidate = os.path.join(home, name)
        if os.path.isdir(candidate):
            return candidate
    return None


class ToolBridge:
    """Find and run Kali tools, natively or through ``nethunter``."""

    def __init__(self, nethunter_cmd="nethunter", kali_root=None):
        self.nethunter_cmd = nethunter_cmd
        self.kali_root = kali_root or _kali_root()
        self._resolved: Dict[str, Optional[List[str]]] = {}

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------
    def _nethunter_path(self) -> Optional[str]:
        return shutil.which(self.nethunter_cmd)

    def resolve(self, tool: str) -> Optional[List[str]]:
        """Return the argv prefix to run *tool* with, or None if absent.

        Two shapes are possible:

        * ``["nmap", ...]`` — the tool is on PATH natively.
        * ``["nethunter", "nmap", ...]`` — the tool lives in the NetHunter
          rootfs and has to be reached through the wrapper.
        """
        if tool in self._resolved:
            return self._resolved[tool]

        result = None
        native = shutil.which(tool)
        if native:
            result = [tool]
        else:
            # Look inside the NetHunter rootfs.
            if self.kali_root:
                for sub in ("usr/bin", "usr/sbin", "bin", "sbin"):
                    candidate = os.path.join(self.kali_root, sub, tool)
                    if os.path.exists(candidate):
                        nh = self._nethunter_path()
                        if nh:
                            result = [self.nethunter_cmd, tool]
                        break
            else:
                nh = self._nethunter_path()
                if nh:
                    # The wrapper exists. Assume the tool is in the
                    # rootfs; the run will report if it is not.
                    result = [self.nethunter_cmd, tool]

        self._resolved[tool] = result
        return result

    def available(self) -> Dict[str, dict]:
        """Report which tools are reachable and how."""
        report = {}
        for tool, meta in KALI_TOOLS.items():
            prefix = self.resolve(tool)
            report[tool] = {
                "available": prefix is not None,
                "via": ("native" if prefix and len(prefix) == 1
                        else "nethunter" if prefix else None),
                "purpose": meta.get("purpose", ""),
                "improves": meta.get("improves", ""),
            }
        return report

    def has(self, tool: str) -> bool:
        return self.resolve(tool) is not None

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------
    def run(self, tool: str, args: List[str], timeout: int = 300,
            cwd: Optional[str] = None) -> dict:
        """Run a Kali tool and capture its output.

        Returns a dict with ok, stdout, stderr, code and the argv used.
        Never raises: a missing tool or a timeout is a result, not an
        exception.
        """
        prefix = self.resolve(tool)
        if prefix is None:
            return {"ok": False, "reason": "{} not available".format(tool),
                    "argv": [tool] + list(args)}

        argv = prefix + list(args)
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout,
                cwd=cwd,
                # Many of these tools want a pager and a tty they will not
                # get here.
                env=dict(os.environ, PAGER="cat", TERM="dumb"),
            )
            return {
                "ok": proc.returncode == 0,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "code": proc.returncode,
                "argv": argv,
            }
        except subprocess.TimeoutExpired:
            return {"ok": False, "reason": "timeout after {}s".format(timeout),
                    "argv": argv}
        except OSError as exc:
            return {"ok": False, "reason": str(exc), "argv": argv}

    # ------------------------------------------------------------------
    # Parsers
    # ------------------------------------------------------------------
    @staticmethod
    def parse_nmap_xml(xml_text: str) -> List[dict]:
        """Parse nmap's XML output into a flat list of open ports."""
        ports = []
        # nmap -oX - emits one <port> block per open port.
        for block in re.findall(r"<port\b.*?</port>", xml_text, re.DOTALL):
            port = re.search(r'portid="(\d+)"', block)
            proto = re.search(r'protocol="(\w+)"', block)
            state = re.search(r'<state state="(\w+)"', block)
            service = re.search(r'<service[^>]*name="([^"]*)"', block)
            version = re.search(r'<service[^>]*version="([^"]*)"', block)
            product = re.search(r'<service[^>]*product="([^"]*)"', block)
            extrainfo = re.search(r'<service[^>]*extrainfo="([^"]*)"', block)
            if not port or not state:
                continue
            if state.group(1) != "open":
                continue
            ports.append({
                "port": int(port.group(1)),
                "protocol": proto.group(1) if proto else "tcp",
                "state": state.group(1),
                "service": service.group(1) if service else "unknown",
                "version": version.group(1) if version else "",
                "product": product.group(1) if product else "",
                "extra": extrainfo.group(1) if extrainfo else "",
            })
        return ports

    @staticmethod
    def parse_sqlmap_output(text: str) -> List[dict]:
        """Pull the injectable parameters out of sqlmap's output.

        sqlmap reports an injection several different ways depending on
        the version and the phase, so all of them are handled:

        * ``parameter 'id' appears to be injectable``
        * ``the 1st parameter is injectable: id``
        * ``injectable parameter 'id' found``
        * the ``---`` block with a Parameter and a Type/Title
        """
        findings = []
        seen = set()

        def add(param, technique="", evidence=""):
            name = (param or "").strip().strip("'\"")
            name = name.split("(")[0].strip()
            if not name or name in seen:
                return
            seen.add(name)
            findings.append({
                "level": "HIGH",
                "category": "vuln.sqli",
                "detail": "sqlmap: parameter '{}' is injectable".format(name),
                "parameter": name,
                "technique": technique,
                "evidence": evidence,
            })

        # "parameter 'id' appears to be injectable"
        for m in re.finditer(
                r"parameter\s+'([^']+)'\s+appears to be injectable", text, re.I):
            add(m.group(1))

        # "the 1st parameter is injectable: id"
        for m in re.finditer(
                r"the\s+\d+(?:st|nd|rd|th)\s+parameter\s+is injectable:\s*(\S+)",
                text, re.I):
            add(m.group(1))

        # "injectable parameter 'id' found"
        for m in re.finditer(
                r"injectable parameter\s+'([^']+)'\s+found", text, re.I):
            add(m.group(1))

        # "id' is vulnerable" / "id is vulnerable" (older sqlmap wording)
        for m in re.finditer(r"'?(\w[\w.]*)'?\s+is vulnerable", text, re.I):
            add(m.group(1))

        # The --- blocks. A block carrying a Parameter and a Type or a
        # Title is a confirmed injection point.
        for block in re.findall(r"(?ms)^---\s*\n(.*?)^---\s*$", text):
            pm = re.search(r"Parameter:\s*(.+)", block)
            if not pm:
                continue
            name = pm.group(1).split("(")[0].strip()
            technique = ""
            tm = re.search(r"Type:\s*(.+)", block)
            if tm:
                technique = tm.group(1).strip()
            evidence = ""
            xm = re.search(r"Title:\s*(.+)", block)
            if xm:
                evidence = xm.group(1).strip()
            if technique or evidence:
                add(name, technique, evidence)

        return findings

    @staticmethod
    def parse_nikto_json(text: str) -> List[dict]:
        """Parse nikto's JSON output into findings."""
        import json
        findings = []
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return findings
        for item in data.get("items", []):
            description = item.get("description", "")
            if not description:
                continue
            if description.lower().startswith(("item ", "the file ", "retrieved ", "no robots")):
                continue
            osvdb = str(item.get("osvdb", "") or "")
            level = "MEDIUM"
            if osvdb and osvdb.startswith(("0", "1", "2")):
                level = "HIGH"
            findings.append({
                "level": level,
                "category": "web.nikto",
                "detail": description,
                "osvdb": osvdb,
            })
        return findings

    @staticmethod
    def parse_ffuf_lines(text: str) -> List[dict]:
        """Parse ffuf's plain output into findings."""
        findings = []
        for line in text.splitlines():
            if not line.startswith("http://") and not line.startswith("https://"):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            url, status, size = parts[0], parts[1], parts[2]
            try:
                code = int(status)
            except ValueError:
                continue
            if code in (404, 400, 403):
                continue
            findings.append({
                "level": "LOW" if code in (200, 301, 302) else "MEDIUM",
                "category": "web.discovered_path",
                "detail": "discovered {} ({})".format(url, code),
                "url": url,
                "status": code,
                "size": size,
            })
        return findings
