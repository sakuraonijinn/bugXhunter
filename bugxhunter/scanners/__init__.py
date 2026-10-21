"""bugXhunter scanner modules.

Each scanner is a self-contained module that:
  - takes a target (URL, host, or raw data)
  - returns structured findings
  - never raises on bad input

They are pure Python with no third-party deps so they run on Termux.
"""

from .network import NetworkScanner
from .web import WebScanner
from .vuln import VulnScanner
from .credential import CredentialScanner
from .config_audit import ConfigAudit

__all__ = ["NetworkScanner", "WebScanner", "VulnScanner", "CredentialScanner", "ConfigAudit"]
