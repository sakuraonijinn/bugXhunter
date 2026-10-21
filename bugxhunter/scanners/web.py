"""Web-application posture scanner.

Answers the questions a red-teamer asks before touching a target:
what server and language is it running, does it expose debug endpoints,
and are there common misconfigurations (CORS, methods, headers)?

Every probe is read-only and safe to run against any host you own or are
authorised to test.
"""

import re

from .network import NetworkScan

# Debug / management endpoints that should never be public.
DEBUG_PATHS = [
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
    "/actuator/mappings", "/actuator/configprops", "/actuator/threaddump",
    "/env", "/spring-boot/actuator", "/admin", "/admin/", "/manager/html",
    "/server-status", "/server-info", "/status", "/debug.php",
    "/wp-admin", "/wp-login.php", "/config.php", "/configuration.php",
    "/install.php", "/setup.php", "/backup", "/backup.zip", "/dump.sql",
    "/phpinfo.php", "/info.php", "/test.php", "/cgi-bin/", "/shell.php",
    "/api-docs", "/swagger-ui.html", "/swagger.json", "/openapi.json",
    "/v2/api-docs", "/v3/api-docs", "/graphql", "/graphql/playground",
    "/console", "/console/Gui", "/jmx", "/jmx/html", "/solr/admin",
    "/elasticsearch/_cat/health", "/kibana", "/grafana", "/prometheus",
]

SERVER_HEADER = re.compile(r"^Server:\s*(.+)$", re.IGNORECASE)
X_POWERED = re.compile(r"^X-Powered-By:\s*(.+)$", re.IGNORECASE)
SET_COOKIE = re.compile(r"^Set-Cookie:\s*([^;]+)", re.IGNORECASE)


class WebScanner:
    """Web-application posture scanner."""

    def __init__(self, net=None):
        self.net = net or NetworkScan()

    def scan(self, base_url):
        """Run all web-posture checks against a base URL."""
        findings = []
        origin = base_url if base_url.endswith("/") else base_url + "/"

        # Fingerprint the root page.
        root = self.net.get(base_url)
        if not root.ok:
            findings.append({
                "level": "HIGH",
                "category": "web.unreachable",
                "detail": "Web root did not respond: {}".format(root.err),
            })
            return findings

        # Server / X-Powered-By headers.
        for header in root.headers:
            m = SERVER_HEADER.match(header)
            if m:
                findings.append({
                    "level": "LOW",
                    "category": "web.server_header",
                    "detail": "Server header: {}".format(m.group(1).strip()),
                })
            m = X_POWERED.match(header)
            if m:
                findings.append({
                    "level": "MEDIUM",
                    "category": "web.x_powered_by",
                    "detail": "X-Powered-By: {}".format(m.group(1).strip()),
                })
            m = SET_COOKIE.match(header)
            if m:
                cookie = m.group(1).strip()
                lower = cookie.lower()
                if "httponly" not in lower or "secure" not in lower:
                    findings.append({
                        "level": "MEDIUM",
                        "category": "web.cookie_flags",
                        "detail": "Cookie missing HttpOnly/Secure: {}".format(cookie),
                    })

        # CORS misconfiguration.
        acao = root.header("Access-Control-Allow-Origin")
        if acao and acao != "null":
            findings.append({
                "level": "MEDIUM",
                "category": "web.cors",
                "detail": "Access-Control-Allow-Origin: {}".format(acao),
            })

        # Debug / management endpoints.
        for path in DEBUG_PATHS:
            target = origin + path[1:]
            f = self.net.get(target)
            if f.ok and f.status < 400:
                findings.append({
                    "level": "HIGH",
                    "category": "web.debug_endpoint",
                    "detail": "Exposed debug/management path: {} (HTTP {})".format(
                        path, f.status),
                })

        return findings
