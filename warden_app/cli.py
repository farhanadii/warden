"""Command-line entry point for Warden.

``main()`` is the installed ``warden`` console command. Warden must send raw
ARP packets, which the OS only permits as root, so when we are not already
root we re-exec the *same* Python interpreter under ``sudo``. Re-using
``sys.executable`` guarantees the elevated process still has PyQt5 and scapy
available (it is the exact environment Warden was installed into), and sudo
prompts for the password in the terminal.

``launch()`` is the real application start, run once we have privileges.
"""

from __future__ import annotations

import os
import sys


def launch() -> None:
    """Start the Qt application. Assumes the process already has root."""
    from PyQt5.QtWidgets import QApplication, QStyleFactory

    from .app import WardenApp
    from .theme import APP_STYLE

    app = QApplication(sys.argv)
    # Fusion gives Qt full control over widget drawing (see warden_app/theme.py).
    app.setStyle(QStyleFactory.create("Fusion"))
    app.setStyleSheet(APP_STYLE)
    window = WardenApp()
    window.show()
    sys.exit(app.exec_())


def main() -> None:
    """Entry point: elevate to root if needed, then launch."""
    if os.name == "posix" and os.geteuid() != 0:
        # Re-run this very interpreter under sudo so the elevated process keeps
        # the dependencies of the environment Warden was installed into.
        try:
            os.execvp(
                "sudo",
                ["sudo", sys.executable, "-m", "warden_app", *sys.argv[1:]],
            )
        except OSError as exc:  # sudo missing, or exec failed
            sys.exit(f"warden: could not elevate privileges via sudo: {exc}")

    launch()


if __name__ == "__main__":
    main()
