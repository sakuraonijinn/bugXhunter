"""Network-layer scanner.

Probes a target host for open ports, service banners, TLS settings,
and basic reachability. Pure stdlib — uses socket + ssl.
"""

import socket
import ssl
import json
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple


# Well-known ports and what they usually serve.
WELL_KNOWN: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "SMTP (submission)", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 9000: "MinIO/Ceph", 9200: "Elasticsearch",
    27017: "MongoDB", 5000: "Flask-dev", 11211: "Memcached",
    2375: "Docker", 2376: "Docker-TLS", 10250: "Kubelet",
}


@dataclass
class PortResult:
    port: int
    state: str          # open | closed | filtered
    service: str        # guessed from port
    banner: str = ""
    tls: bool = False
    tls_version: str = ""
    tls_subject: str = ""
    error: str = ""


@dataclass
class NetworkScan:
    target: str
    timestamp: float = field(default_factory=time.time)
    reachable: bool = False
    latency_ms: float = 0.0
    open_ports: List[PortResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def _grab_banner(sock: socket.socket, timeout: float = 3.0) -> str:
    """Receive a banner from an open socket."""
    sock.settimeout(timeout)
    try:
        data = sock.recv(1024)
        return data.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _probe_tcp(host: str, port: int, timeout: float = 3.0) -> PortResult:
    pr = PortResult(port=port, state="filtered",
                    service=WELL_KNOWN.get(port, "unknown"))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        if result == 0:
            pr.state = "open"
            pr.banner = _grab_banner(s)
            # try TLS
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                raw = s
                tls_sock = ctx.wrap_socket(raw, server_hostname=host)
                pr.tls = True
                pr.tls_version = tls_sock.version() or ""
                cert = tls_sock.getpeercert()
                if cert:
                    subj = cert.get("subject", ())
                    for r in subj:
                        for k, v in r:
                            if k == "commonName":
                                pr.tls_subject = v
                tls_sock.close()
            except Exception:
                pass
        else:
            pr.state = "closed"
        s.close()
    except socket.timeout:
        pr.state = "filtered"
        pr.error = "timeout"
    except Exception as e:
        pr.state = "filtered"
        pr.error = str(e)
    return pr


def _ping_latency(host: str, timeout: float = 3.0) -> Tuple[bool, float]:
    """TCP connect to port 80 as a reachability + latency probe."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start = time.time()
        result = s.connect_ex((host, 80))
        latency = (time.time() - start) * 1000.0
        s.close()
        if result == 0:
            return True, latency
        # try 443 if 80 closed
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start = time.time()
        result = s.connect_ex((host, 443))
        latency = (time.time() - start) * 1000.0
        s.close()
        return result == 0, latency
    except Exception:
        return False, 0.0


def scan(target: str, ports: Optional[List[int]] = None,
         timeout: float = 3.0, max_ports: int = 30) -> NetworkScan:
    """Run a network scan against *target*.

    If *ports* is None, uses a curated list of the most common ports.
    """
    ns = NetworkScan(target=target)
    if ports is None:
        ports = sorted(WELL_KNOWN.keys())[:max_ports]

    reachable, latency = _ping_latency(target, timeout)
    ns.reachable = reachable
    ns.latency_ms = latency
    if not reachable:
        ns.errors.append("host not reachable")
        return ns

    for port in ports:
        pr = _probe_tcp(target, port, timeout)
        ns.open_ports.append(pr)
        if pr.error:
            ns.errors.append(f"port {port}: {pr.error}")
    return ns


def to_dict(ns: NetworkScan) -> dict:
    return {
        "target": ns.target,
        "timestamp": ns.timestamp,
        "reachable": ns.reachable,
        "latency_ms": round(ns.latency_ms, 2),
        "open_ports": [
            {
                "port": p.port, "state": p.state, "service": p.service,
                "banner": p.banner[:500], "tls": p.tls,
                "tls_version": p.tls_version, "tls_subject": p.tls_subject,
                "error": p.error,
            }
            for p in ns.open_ports
        ],
        "errors": ns.errors,
    }
