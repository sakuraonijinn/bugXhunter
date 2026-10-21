"""Configuration audit scanner.

Checks for common security misconfigurations in config files, build scripts,
and container definitions: TLS version floors, permissive CORS, debug flags,
and missing security headers.
"""

import os
import re

CORS_WILDCARD = re.compile(r"Access-Control-Allow-Origin\s*[:=]\s*\*", re.IGNORECASE)
DEBUG_FLAG = re.compile(r"\b(debug|DEBUG)\s*[:=]\s*(true|1|yes|on)\b")
INSECURE_TLS = re.compile(r"(SSLv?2|SSLv?3|TLSv1\.0|TLSv1\.1)", re.IGNORECASE)
SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "Referrer-Policy",
]


class ConfigAudit:
    """Audit configuration files and HTTP responses for misconfigurations."""

    def __init__(self):
        pass

    def audit_bytes(self, data, source="memory"):
        """Audit raw config bytes."""
        findings = []
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return findings

        for pattern, category, level in (
            (CORS_WILDCARD, "config.cors_wildcard", "MEDIUM"),
            (DEBUG_FLAG, "config.debug_enabled", "HIGH"),
            (INSECURE_TLS, "config.insecure_tls", "HIGH"),
        ):
            for match in pattern.finditer(text):
                findings.append({
                    "level": level,
                    "category": category,
                    "detail": "{} detected in {}".format(category, source),
                    "match": match.group(0)[:80],
                })
        return findings

    def audit_headers(self, headers):
        """Audit HTTP response headers for missing security headers."""
        findings = []
        present = {h.split(":", 1)[0].strip().lower() for h in headers if ":" in h}
        for header in SECURITY_HEADERS:
            if header.lower() not in present:
                findings.append({
                    "level": "MEDIUM",
                    "category": "config.missing_header",
                    "detail": "Missing security header: {}".format(header),
                })
        return findings

    def audit_file(self, path):
        """Audit a single config file."""
        try:
            with open(path, "rb") as handle:
                return self.audit_bytes(handle.read(), source=path)
        except OSError:
            return []

    def audit_dir(self, root):
        """Audit a directory tree for config misconfigurations."""
        findings = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            for name in filenames:
                findings.extend(self.audit_file(os.path.join(dirpath, name)))
        return findings
