"""Entry point so the operator client can be run as `python3 -m bugxhunter.client`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
