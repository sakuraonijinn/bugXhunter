"""Vulnerability probes.

Differential probes that look for real, exploitable conditions rather than
banner-grabbing. Each probe is read-only and safe to run against any host
you own or are authorised to test.
"""

import re

from .network import NetworkScan

# SQL error fingerprints from common databases / drivers.
SQL_ERROR_PATTERNS = [
    re.compile(r"SQL syntax.*?error", re.IGNORECASE),
    re.compile(r"mysql_fetch\(\)", re.IGNORECASE),
    re.compile(r"mysql_num_rows\(\)", re.IGNORECASE),
    re.compile(r"PostgreSQL.*?ERROR", re.IGNORECASE),
    re.compile(r"ORA-[0-9]{5}", re.IGNORECASE),
    re.compile(r"SQLite3::", re.IGNORECASE),
    re.compile(r"SQLSTATE\[\d{2}\]", re.IGNORECASE),
    re.compile(r"Unclosed quotation", re.IGNORECASE),
    re.compile(r"Microsoft OLE DB", re.IGNORECASE),
    re.compile(r"JDBC.*?Exception", re.IGNORECASE),
]

XSS_MARKER = re.compile(r"<script[^>]*>", re.IGNORECASE)

# Path traversal probes that should not resolve on a well-configured host.
TRAVERSAL_PROBE = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc/passwd",
    "....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
]

LFI_PROBE = [
    "/etc/passwd",
    "/etc/hostname",
    "/proc/self/environ",
    "php://filter/convert.base64-encode/resource=index.php",
    "expect://id",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
]


class VulnScanner:
    """Differential vulnerability probes."""

    def __init__(self, net=None):
        self.net = net or NetworkScan()

    def _sql_error(self, body):
        for pattern in SQL_ERROR_PATTERNS:
            if pattern.search(body):
                return pattern.pattern
        return None

    def _xss_reflected(self, body, marker):
        return marker in body

    def _path_traversal(self, body):
        # If the response contains a root user line, the traversal succeeded.
        return "root:" in body and "/bin/bash" in body

    def sql_inject(self, url):
        """Differential SQLi probe: baseline vs. quote-appended probe."""
        base = self.net.get(url)
        if not base.ok:
            return {"vulnerable": False, "reason": "baseline failed: {}".format(base.err)}

        probe = self.net.get(url + "'")
        if not probe.ok:
            return {"vulnerable": False, "reason": "probe failed: {}".format(probe.err)}

        hit = self._sql_error(probe.body)
        if hit:
            # Differential: only count it if the baseline did not already contain it.
            if not self._sql_error(base.body):
                return {"vulnerable": True, "evidence": hit}
        return {"vulnerable": False, "reason": "no SQL error differential"}

    def xss(self, url, marker="<script>alert(1)</script>"):
        """Reflected XSS probe."""
        target = url + marker if "?" in url else url + "?xss=" + marker
        f = self.net.get(target)
        if not f.ok:
            return {"vulnerable": False, "reason": "request failed: {}".format(f.err)}
        if self._xss_reflected(f.body, marker):
            return {"vulnerable": True, "evidence": "marker reflected verbatim"}
        return {"vulnerable": False, "reason": "marker not reflected"}

    def path_traversal(self, url):
        """Path traversal probe."""
        suffix = "" if "?" in url else "?file="
        for payload in TRAVERSAL_PROBE:
            target = url + suffix + payload
            f = self.net.get(target)
            if not f.ok:
                continue
            if self._path_traversal(f.body):
                return {"vulnerable": True, "evidence": payload}
        return {"vulnerable": False, "reason": "no traversal resolved"}

    def lfi(self, url):
        """Local file inclusion probe."""
        suffix = "" if "?" in url else "?page="
        for payload in LFI_PROBE:
            target = url + suffix + payload
            f = self.net.get(target)
            if not f.ok:
                continue
            # crude but effective: if the response contains a known secret marker
            if "root:" in f.body and "/bin/bash" in f.body:
                return {"vulnerable": True, "evidence": payload}
            if "PD9waHAgcGhwaW5mbygpOyA/Pg==" in f.body:
                return {"vulnerable": True, "evidence": payload}
        return {"vulnerable": False, "reason": "no LFI resolved"}

    def scan(self, url):
        """Run all probes and return findings."""
        findings = []
        for name in ("sql_inject", "xss", "path_traversal", "lfi"):
            try:
                result = getattr(self, name)(url)
            except Exception as exc:  # pragma: no cover - defensive
                result = {"vulnerable": False, "reason": "probe error: {}".format(exc)}
            if result.get("vulnerable"):
                findings.append({
                    "level": "HIGH",
                    "category": "vuln.{}".format(name),
                    "detail": "{} vulnerable at {} — {}".format(
                        name, url, result.get("evidence", "")),
                })
        return findings
