"""Credential exposure scanner.

Looks for secrets that should never reach a repository, a log file, or a
client-side bundle: hardcoded API keys, AWS keys, private keys, connection
strings, and password-in-URL patterns.
"""

import os
import re

# AWS access key IDs (AKIA...) and secret keys (40-char base64-ish).
AWS_KEY_ID = re.compile(r"AKIA[0-9A-Z]{16}")
AWS_SECRET = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")
GITHUB_TOKEN = re.compile(r"gh[pousr]_[A-Za-z0-9]{36}")
SLACK_TOKEN = re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")
PRIVATE_KEY = re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
PASSWORD_URL = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^:@/]+:[^@/]+@", re.IGNORECASE)
GENERIC_SECRET = re.compile(
    r"(api[_-]?key|apikey|secret|token|passwd|password)\s*[=:]\s*['\"]?([^\s'\"]{8,})",
    re.IGNORECASE,
)
ENV_FILE = re.compile(r"^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.+)$")


class CredentialScanner:
    """Scan files and blobs for exposed credentials."""

    def __init__(self, max_file_size=1024 * 1024):
        self.max_file_size = max_file_size

    def scan_bytes(self, data, source="memory"):
        """Scan raw bytes for credential patterns."""
        findings = []
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return findings

        for pattern, category in (
            (AWS_KEY_ID, "credential.aws_key_id"),
            (AWS_SECRET, "credential.aws_secret"),
            (GITHUB_TOKEN, "credential.github_token"),
            (SLACK_TOKEN, "credential.slack_token"),
            (PRIVATE_KEY, "credential.private_key"),
            (PASSWORD_URL, "credential.password_in_url"),
        ):
            for match in pattern.finditer(text):
                findings.append({
                    "level": "HIGH",
                    "category": category,
                    "detail": "{} exposed in {}".format(category, source),
                    "match": match.group(0)[:80],
                })

        for match in GENERIC_SECRET.finditer(text):
            findings.append({
                "level": "MEDIUM",
                "category": "credential.generic_secret",
                "detail": "{} exposed in {}".format(
                    match.group(1).lower(), source),
                "match": match.group(0)[:80],
            })

        return findings

    def scan_file(self, path):
        """Scan a single file for credentials."""
        try:
            size = os.path.getsize(path)
            if size > self.max_file_size:
                return []
            with open(path, "rb") as handle:
                return self.scan_bytes(handle.read(), source=path)
        except OSError:
            return []

    def scan_dir(self, root, recursive=True, tools=None):
        """Scan a directory tree for credentials.

        When *tools* is a ToolBridge, trufflehog or gitleaks is run over
        the tree as well. They catch secrets the regex patterns miss,
        especially in git history.
        """
        findings = []
        for dirpath, dirnames, filenames in os.walk(root):
            if not recursive:
                dirnames[:] = []
            for name in filenames:
                path = os.path.join(dirpath, name)
                findings.extend(self.scan_file(path))
            # Skip hidden and binary-heavy directories.
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        if tools is not None:
            findings.extend(self._kali_findings(root, tools))
        return findings

    def _kali_findings(self, root, tools):
        """Run trufflehog or gitleaks over the tree."""
        findings = []
        if tools.has("trufflehog"):
            result = tools.run("trufflehog", ["filesystem", root, "--json"],
                               timeout=600)
            if result.get("ok"):
                for line in result.get("stdout", "").splitlines():
                    line = line.strip()
                    if not line.startswith("{"):
                        continue
                    try:
                        import json
                        data = json.loads(line)
                    except ValueError:
                        continue
                    source = (data.get("SourceMetadata") or {}).get("Data", {})
                    path = source.get("Filesystem", {}).get("file", "")
                    raw = data.get("Raw", "")
                    findings.append({
                        "level": "HIGH" if data.get("VerificationStatus") == "VERIFIED"
                                 else "MEDIUM",
                        "category": "credential.trufflehog",
                        "detail": "{} found in {}".format(
                            data.get("DetectorName", "secret"), path or "unknown"),
                        "match": raw[:120],
                    })
        elif tools.has("gitleaks"):
            result = tools.run("gitleaks", ["detect", "--source", root,
                                            "--report-format", "json",
                                            "--no-banner", "-r"], timeout=600)
            if result.get("ok") and result.get("stdout"):
                try:
                    import json
                    data = json.loads(result["stdout"])
                except ValueError:
                    data = []
                for item in data:
                    findings.append({
                        "level": "HIGH" if item.get("Secret") else "MEDIUM",
                        "category": "credential.gitleaks",
                        "detail": "{} found in {}".format(
                            item.get("RuleID", "secret"),
                            item.get("File", "unknown")),
                        "match": (item.get("Secret") or "")[:120],
                    })
        return findings
