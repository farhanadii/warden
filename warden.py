"""
Warden: Network Control — compatibility entry point.

The real code now lives in the ``warden_app`` package so Warden can be
installed with pip/pipx (``pip install .`` exposes a ``warden`` command).
This shim keeps the familiar ``python warden.py`` invocation working; it
self-elevates to root when needed (raw packets require it).
"""

from warden_app.cli import main

if __name__ == "__main__":
    main()
