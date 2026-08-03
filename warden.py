"""
Warden: Network Control
Entry point. Bootstraps the Qt application and launches the main window.
Run with: sudo python3 warden.py
"""

import sys

from PyQt5.QtWidgets import QApplication, QStyleFactory

from app import WardenApp
from theme import APP_STYLE


def main() -> None:
    app = QApplication(sys.argv)
    # Fusion replaces the native macOS style renderer, giving Qt full control over
    # widget drawing and removing the platform 3D appearance on QLineEdit and other inputs.
    app.setStyle(QStyleFactory.create("Fusion"))
    app.setStyleSheet(APP_STYLE)
    window = WardenApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
