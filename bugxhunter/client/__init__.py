"""bugXhunter client package.

Smart client for the bugXhunter server. Auto-provisions a Frida server,
tunnels traffic through reverse SSH, and exposes a high-level API that
takes a goal (not a command list) and figures out the rest.
"""

__version__ = "1.0.0"
