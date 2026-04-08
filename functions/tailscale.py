#!/usr/bin/env python3
"""Compatibility wrapper.

The active provider lives in functions/providers/tailscale.py.
This wrapper keeps older references stable.
"""

from pathlib import Path
import runpy

if __name__ == "__main__":
    target = Path(__file__).resolve().parent / "providers" / "tailscale.py"
    runpy.run_path(str(target), run_name="__main__")
