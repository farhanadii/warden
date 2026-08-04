"""
Main application window and UI bridge.

WardenApp is the top-level QMainWindow. It owns all UI state and orchestrates
background threads for scanning, name resolution, latency measurement, and ARP spoofing.
_UIBridge provides the thread-safe signal used to schedule main-thread calls from
background workers.
"""

from __future__ import annotations

import threading
import time

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QAbstractItemView, QStackedWidget
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject, QEvent
from PyQt5.QtGui import QColor

import network
import oui

VERSION = "1.0.0"
from theme import (
    BG, CANVAS, SURFACE, SURFACE2, BORDER,
    ACCENT, ACCENT_H, SUCCESS, DANGER, WARNING, FG, FG2, FG3,
    ROW_A, ROW_B, ROW_BLK,
    EYE_SVG, EYE_SLASH_SVG, RELOAD_SVG,
    button, icon_button, label, alert, vdivider, svg_icon, TOOLTIP_CSS
)


class _UIBridge(QObject):
    """Provides a thread-safe channel for scheduling calls on the Qt main thread.

    Any background thread can emit call(fn) and fn() will be executed in the
    main thread via Qt's signal/slot queued connection, which is thread-safe by design.
    """
    call = pyqtSignal(object)


class _IconHover(QObject):
    """Event filter that swaps a QPushButton's icon between a dim and a bright version on hover.

    Parented to the button so its lifetime is automatically tied to the button's lifetime.
    """
    def __init__(self, btn: "QPushButton", off_icon, on_icon) -> None:
        super().__init__(btn)
        self._btn = btn
        self._off = off_icon
        self._on  = on_icon
        btn.setIcon(off_icon)
        btn.installEventFilter(self)

    def eventFilter(self, obj, event) -> bool:
        if obj is self._btn:
            t = event.type()
            if t == QEvent.Enter and obj.isEnabled():
                self._btn.setIcon(self._on)
            elif t == QEvent.Leave:
                self._btn.setIcon(self._off)
        return False


class _ToggleIconHover(QObject):
    """Event filter for icon buttons whose icon source also changes on click
    (the eye/eye-slash visibility toggles), so a fixed off/on icon pair like
    _IconHover uses doesn't fit. Calls back into a refresh function that
    knows the button's current toggle state and re-renders the icon with a
    hover-appropriate color — same "no background fill, color shift only"
    hover language as every other icon control in the app.
    """
    def __init__(self, btn: "QPushButton", refresh_fn) -> None:
        super().__init__(btn)
        self._btn = btn
        self._refresh = refresh_fn
        btn.installEventFilter(self)

    def eventFilter(self, obj, event) -> bool:
        if obj is self._btn and event.type() in (QEvent.Enter, QEvent.Leave):
            self._refresh()
        return False


class WardenApp(QMainWindow):

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Warden")
        self.resize(1080, 720)
        self.setMinimumSize(860, 560)

        self._bridge = _UIBridge()
        self._bridge.call.connect(lambda fn: fn())

        self.gateway_ip:   str  = "192.168.0.1"
        self.gateway_mac:  str  = ""
        self.iface:        str  = ""
        self.my_mac:       str  = ""
        self.scan_running: bool = False
        self._arp_names:   dict = {}   # ip -> hostname from the most recent arp -a run
        self.devices:      dict = {}   # ip -> {mac, hn, status, running, thread, ping_ms}
        self.ip_to_row:    dict = {}   # ip -> table row index; stable while the table is active

        self._gw_mac_visible:   bool = False   # GW MAC hidden until user reveals it
        self._iface_visible:    bool = False   # local IP hidden until user reveals it
        self._gw_mac_actual:    str  = "—"    # actual GW MAC, populated after each scan
        self._iface_actual:     str  = ""     # local IP only, populated after each scan
        self._iface_name_actual: str = ""     # interface name (e.g. en0), shown separately

        self._build_ui()

    # ---------------------------------------------------------------------------
    # Thread safety
    # ---------------------------------------------------------------------------

    def _ui(self, fn) -> None:
        """Schedule fn() for execution on the Qt main thread from any background thread."""
        self._bridge.call.emit(fn)

    # ---------------------------------------------------------------------------
    # UI construction
    # ---------------------------------------------------------------------------

    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        vbox = QVBoxLayout(root)
        vbox.setSpacing(0)
        vbox.setContentsMargins(0, 0, 0, 0)

        self._build_nav(vbox)
        self._build_stats_strip(vbox)
        self._build_toolbar(vbox)
        self._build_content(vbox)
        self._build_controls(vbox)
        self._build_status_bar(vbox)

        self._on_selection_changed()

    def _build_nav(self, parent: QVBoxLayout) -> None:
        """Top navigation bar with brand mark on the left and live network status on the right."""
        nav = QFrame()
        nav.setFixedHeight(54)
        nav.setStyleSheet(f"background:{CANVAS}; border-bottom:1px solid {BORDER};")
        nl = QHBoxLayout(nav)
        nl.setContentsMargins(20, 0, 20, 0)
        nl.setSpacing(0)

        nl.addWidget(label("⬡", ACCENT, 17, bold=True))
        nl.addSpacing(8)
        nl.addWidget(label("Warden", FG, 14, bold=True))
        nl.addSpacing(10)

        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setFixedHeight(14)
        sep.setStyleSheet(f"background:{BORDER}; border:none;")
        nl.addWidget(sep)
        nl.addSpacing(10)
        nl.addWidget(label("Network Control", FG3, 12))
        nl.addStretch()

        self.nav_dot    = label("●", FG3, 9)
        self.nav_status = label("No network selected", FG3, 11)
        self.nav_status.setToolTip("Network status — updates after each scan")
        # iface_name_lbl shows the interface (e.g. "en0") always once a scan runs
        self.iface_name_lbl = label("", FG3, 11)
        self.iface_name_lbl.setToolTip("Network interface in use (en0 = Wi-Fi, en1 = Ethernet)")
        self.iface_name_lbl.setVisible(False)
        # iface_type_lbl is the "IP" text prefix; toggles with the IP value
        self.iface_type_lbl = label("IP", FG3, 10)
        self.iface_type_lbl.setVisible(False)
        self.iface_lbl  = label("", FG3, 11)
        self.iface_toggle = self._visibility_btn()
        self.iface_toggle.setVisible(False)
        self.iface_toggle.setToolTip("Show local IP address")
        self.iface_toggle.clicked.connect(self._toggle_iface)
        _ToggleIconHover(self.iface_toggle,
                          lambda: self._set_eye_icon(self.iface_toggle, self._iface_visible))
        nl.addWidget(self.nav_dot)
        nl.addSpacing(5)
        nl.addWidget(self.nav_status)
        nl.addSpacing(16)
        nl.addWidget(self.iface_name_lbl)
        nl.addSpacing(8)
        nl.addWidget(self.iface_type_lbl)
        nl.addSpacing(6)
        nl.addWidget(self.iface_lbl)
        nl.addSpacing(4)
        nl.addWidget(self.iface_toggle)

        parent.addWidget(nav)

    def _build_stats_strip(self, parent: QVBoxLayout) -> None:
        """Four-tile stats bar showing total, blocked, and online device counts plus the gateway IP."""
        stats_bar = QFrame()
        stats_bar.setFixedHeight(78)
        stats_bar.setStyleSheet(f"background:{CANVAS}; border-bottom:1px solid {BORDER};")
        sl = QHBoxLayout(stats_bar)
        sl.setContentsMargins(0, 0, 0, 0)
        sl.setSpacing(0)

        self.stat_total_val   = label("0", FG3, 22, bold=True)
        self.stat_blocked_val = label("0", FG3, 22, bold=True)
        self.stat_online_val  = label("0", FG3, 22, bold=True)

        self.stat_total_val.setToolTip("Total devices found in the last scan")
        self.stat_blocked_val.setToolTip("Devices currently cut off from the internet")
        self.stat_online_val.setToolTip("Devices with active internet access")

        for val_lbl in (self.stat_total_val, self.stat_blocked_val, self.stat_online_val):
            val_lbl.setAlignment(Qt.AlignCenter)

        def _tile(val_widget: QLabel, caption: str, last: bool = False) -> None:
            tip = val_widget.toolTip()
            tile = QFrame()
            tile.setToolTip(tip)
            tile.setStyleSheet(f"QFrame {{ background:transparent; border:none; }} " + TOOLTIP_CSS)
            tl = QVBoxLayout(tile)
            tl.setContentsMargins(32, 12, 32, 12)
            tl.setSpacing(3)
            tl.addWidget(val_widget, alignment=Qt.AlignCenter)
            cap = label(caption.upper(), FG3, 9)
            cap.setAlignment(Qt.AlignCenter)
            cap.setToolTip(tip)
            cap.setStyleSheet(
                f"QLabel {{ color:{FG3}; font-size:9px; letter-spacing:1px; background:transparent; }} "
                + TOOLTIP_CSS)
            tl.addWidget(cap)
            sl.addWidget(tile, 1)
            if not last:
                sl.addWidget(vdivider())

        _tile(self.stat_total_val,   "Devices")
        _tile(self.stat_blocked_val, "Blocked")
        _tile(self.stat_online_val,  "Online", last=True)

        parent.addWidget(stats_bar)

    def _build_toolbar(self, parent: QVBoxLayout) -> None:
        """Gateway IP input, scan trigger button, and gateway MAC display."""
        tb = QFrame()
        tb.setFixedHeight(52)
        tb.setStyleSheet(f"background:{SURFACE}; border-bottom:1px solid {BORDER};")
        tl = QHBoxLayout(tb)
        tl.setContentsMargins(20, 0, 20, 0)
        tl.setSpacing(10)

        tl.addWidget(label("Gateway IP", FG2, 11))
        tl.addSpacing(4)

        self.gw_entry = QLineEdit(self.gateway_ip)
        self.gw_entry.setFixedWidth(160)
        self.gw_entry.setFixedHeight(32)
        self.gw_entry.setFocusPolicy(Qt.ClickFocus)
        self.gw_entry.setAttribute(Qt.WA_MacShowFocusRect, False)
        self.gw_entry.setPlaceholderText("e.g. 192.168.0.1")
        # Flat underline style: no box border, just a bottom line that brightens on focus
        self.gw_entry.setStyleSheet(f"""
            QLineEdit {{
                background: {SURFACE};
                color: {FG};
                border: none;
                border-bottom: 1px solid {BORDER};
                border-radius: 0;
                padding: 5px 10px;
                font-family: 'SF Mono', Menlo, Courier;
                selection-background-color: {ACCENT};
            }}
            QLineEdit:focus {{ border-bottom-color: {FG2}; }}
        """ + TOOLTIP_CSS)
        self.gw_entry.textChanged.connect(lambda t: setattr(self, "gateway_ip", t))
        self.gw_entry.setToolTip("Your router's IP address (e.g. 192.168.0.1 or 192.168.1.1)")
        tl.addWidget(self.gw_entry)
        tl.addSpacing(20)

        self.gw_mac_lbl = label("", FG3, 11)
        self.gw_mac_lbl.setToolTip("Your router's hardware (MAC) address")
        self.gw_mac_lbl.setVisible(False)   # appears only after the first scan
        self.gw_mac_toggle = self._visibility_btn()
        self.gw_mac_toggle.setVisible(False)   # appears only after the first scan
        self.gw_mac_toggle.setToolTip("Show gateway MAC address")
        self.gw_mac_toggle.clicked.connect(self._toggle_gw_mac)
        _ToggleIconHover(self.gw_mac_toggle,
                          lambda: self._set_eye_icon(self.gw_mac_toggle, self._gw_mac_visible))
        tl.addWidget(self.gw_mac_lbl)
        tl.addSpacing(4)
        tl.addWidget(self.gw_mac_toggle)
        tl.addStretch()

        parent.addWidget(tb)

    def _build_content(self, parent: QVBoxLayout) -> None:
        """Stacked content area with three pages:
          index 0: welcome screen shown on first launch and after clearing the table
          index 1: scanning screen shown while an ARP sweep is in progress
          index 2: device table shown after a successful scan

        The stack advances automatically as the app state changes.
        """
        self.stack = QStackedWidget()

        # --- Welcome page (index 0, shown on launch and after clear) ---
        welcome_page = QWidget()
        welcome_page.setStyleSheet(f"background:{CANVAS};")
        ep = QVBoxLayout(welcome_page)
        ep.setContentsMargins(0, 0, 0, 80)
        ep.addStretch()

        ico = QLabel("⬡")
        ico.setAlignment(Qt.AlignCenter)
        ico.setStyleSheet(f"color:{ACCENT}; font-size:52px; background:transparent;")
        ep.addWidget(ico)
        ep.addSpacing(20)

        welcome_title = QLabel("Welcome to Warden")
        welcome_title.setAlignment(Qt.AlignCenter)
        welcome_title.setStyleSheet(
            f"color:{FG}; font-size:15px; font-weight:600; background:transparent;")
        ep.addWidget(welcome_title)
        ep.addSpacing(8)

        welcome_sub = QLabel("Enter your gateway IP in the toolbar above, then scan to discover connected devices.")
        welcome_sub.setAlignment(Qt.AlignCenter)
        welcome_sub.setStyleSheet(f"color:{FG2}; font-size:12px; background:transparent;")
        ep.addWidget(welcome_sub)
        ep.addSpacing(6)

        welcome_hint = QLabel("Run with  sudo  so the app has permission to send ARP packets.")
        welcome_hint.setAlignment(Qt.AlignCenter)
        welcome_hint.setStyleSheet(f"color:{FG3}; font-size:11px; background:transparent;")
        ep.addWidget(welcome_hint)
        ep.addSpacing(28)

        self.scan_btn = button("Scan Network", ACCENT, ACCENT_H, radius=20, height=38)
        self.scan_btn.setToolTip("Discover all devices connected to this network via ARP")
        self.scan_btn.clicked.connect(self._start_scan)
        ep.addWidget(self.scan_btn, 0, Qt.AlignCenter)
        ep.addStretch()
        self.stack.addWidget(welcome_page)   # index 0

        # --- Scanning page (index 1, shown while ARP sweep is running) ---
        scanning_page = QWidget()
        scanning_page.setStyleSheet(f"background:{CANVAS};")
        sp = QVBoxLayout(scanning_page)
        sp.setContentsMargins(0, 0, 0, 80)
        sp.addStretch()

        scan_ico = QLabel("⬡")
        scan_ico.setAlignment(Qt.AlignCenter)
        scan_ico.setStyleSheet(f"color:{WARNING}; font-size:52px; background:transparent;")
        sp.addWidget(scan_ico)
        sp.addSpacing(20)

        scan_title = QLabel("Scanning network...")
        scan_title.setAlignment(Qt.AlignCenter)
        scan_title.setStyleSheet(
            f"color:{FG}; font-size:15px; font-weight:600; background:transparent;")
        sp.addWidget(scan_title)
        sp.addSpacing(8)

        self.scanning_sub = QLabel("Sending ARP requests across the network...")
        self.scanning_sub.setAlignment(Qt.AlignCenter)
        self.scanning_sub.setStyleSheet(f"color:{FG2}; font-size:12px; background:transparent;")
        sp.addWidget(self.scanning_sub)
        sp.addSpacing(6)

        scan_hint = QLabel("Devices will appear as they respond. This may take a few seconds.")
        scan_hint.setAlignment(Qt.AlignCenter)
        scan_hint.setStyleSheet(f"color:{FG3}; font-size:11px; background:transparent;")
        sp.addWidget(scan_hint)
        sp.addStretch()
        self.stack.addWidget(scanning_page)   # index 1

        # --- Device table (index 2, shown after a successful scan) ---
        # Column layout: 0=checkbox, 1=IP, 2=MAC, 3=Device, 4=Latency, 5=Status
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["", "IP ADDRESS", "MAC ADDRESS", "DEVICE", "LATENCY", "STATUS"])
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.Fixed)
        hh.setSectionResizeMode(1, QHeaderView.Fixed)
        hh.setSectionResizeMode(2, QHeaderView.Fixed)
        hh.setSectionResizeMode(3, QHeaderView.Stretch)
        hh.setSectionResizeMode(4, QHeaderView.Fixed)
        hh.setSectionResizeMode(5, QHeaderView.Fixed)
        self.table.setColumnWidth(0, 36)
        self.table.setColumnWidth(1, 140)
        self.table.setColumnWidth(2, 165)
        self.table.setColumnWidth(4, 105)
        self.table.setColumnWidth(5, 120)
        self.table.verticalHeader().setVisible(False)
        # NoSelection + NoFocus: row clicks produce no highlight or focus rectangle.
        # Interaction is driven entirely by checkboxes in column 0.
        self.table.setSelectionMode(QAbstractItemView.NoSelection)
        self.table.setFocusPolicy(Qt.NoFocus)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setStyleSheet(f"""
            QTableWidget {{ alternate-background-color: {ROW_B}; }}
            QTableWidget::indicator {{
                width: 14px;
                height: 14px;
                border-radius: 3px;
            }}
            QTableWidget::indicator:unchecked {{
                background: {SURFACE2};
                border: 1px solid {FG3};
            }}
            QTableWidget::indicator:unchecked:hover {{
                border-color: {FG2};
            }}
            QTableWidget::indicator:checked {{
                background: {ACCENT};
                border: 1px solid {ACCENT_H};
            }}
        """)
        self.table.verticalHeader().setDefaultSectionSize(42)
        # Row sorting is disabled: enabling it causes Qt to reorder rows physically,
        # which desynchronises ip_to_row and routes cell updates to the wrong row.
        # itemChanged fires when a checkbox is ticked; filtered to col 0 in handler.
        self.table.itemChanged.connect(self._on_item_changed)
        self.stack.addWidget(self.table)   # index 2

        parent.addWidget(self.stack)

    def _build_controls(self, parent: QVBoxLayout) -> None:
        """Bottom control bar with per-device actions and bulk actions.

        Group labels (SELECTION, ALL) show their scope description as a hover tooltip
        rather than as always-visible subtitle text.
        """
        ctrl = QFrame()
        ctrl.setFixedHeight(54)
        ctrl.setStyleSheet(f"background:{SURFACE}; border-top:1px solid {BORDER};")
        cl = QHBoxLayout(ctrl)
        cl.setContentsMargins(20, 0, 20, 0)
        cl.setSpacing(8)

        def _group(title: str, tooltip: str) -> QLabel:
            """Create a group-scope caption label with a tooltip.

            Not clickable, so — same as the stat tiles and the nav status
            indicator — it carries no hover color/background change of its
            own. Only actual buttons react visually to hover; a plain label
            changing appearance on hover implies clickability it doesn't have.
            """
            lbl = QLabel(title)
            lbl.setStyleSheet(f"""
                QLabel {{
                    color: {FG2};
                    font-size: 10px;
                    font-weight: 700;
                    letter-spacing: 1px;
                    background: transparent;
                    padding: 2px 5px;
                }}
            """ + TOOLTIP_CSS)
            lbl.setToolTip(tooltip)
            return lbl

        self.block_btn   = button("Block",   DANGER,  "#c0392b", vanish_disabled=True, radius=20, height=34)
        self.unblock_btn = button("Unblock", SUCCESS, "#2ea043", vanish_disabled=True, radius=20, height=34)
        self.block_btn.setToolTip("Cut internet access for the selected device(s) via ARP spoofing")
        self.unblock_btn.setToolTip("Restore internet access for the selected device(s)")

        cl.addWidget(_group("SELECTION", "Block / Unblock only the rows you have ticked in the table"))
        cl.addSpacing(10)
        cl.addWidget(self.block_btn)
        cl.addWidget(self.unblock_btn)
        cl.addSpacing(16)
        cl.addWidget(vdivider())
        cl.addSpacing(16)

        self.block_all_btn   = button("Block All",   DANGER,  "#c0392b", vanish_disabled=True, radius=20, height=34)
        self.unblock_all_btn = button("Unblock All", SUCCESS, "#2ea043", vanish_disabled=True, radius=20, height=34)
        self.block_all_btn.setToolTip("Block every listed device simultaneously")
        self.unblock_all_btn.setToolTip("Restore access for all currently blocked devices")

        cl.addWidget(_group("ALL", "Block / Unblock every device in the list at once"))
        cl.addSpacing(10)
        cl.addWidget(self.block_all_btn)
        cl.addWidget(self.unblock_all_btn)

        self.block_btn.clicked.connect(self._block_selected)
        self.unblock_btn.clicked.connect(self._unblock_selected)
        self.block_all_btn.clicked.connect(self._block_all)
        self.unblock_all_btn.clicked.connect(self._unblock_all)

        cl.addStretch()

        self.reload_btn = icon_button(RELOAD_SVG, size=36, icon_size=18)
        self.reload_btn.setToolTip("Rescan the network to refresh the device list")
        _IconHover(self.reload_btn, svg_icon(RELOAD_SVG, 18, FG), svg_icon(RELOAD_SVG, 18, FG3))
        self.reload_btn.clicked.connect(self._start_scan)
        # Only meaningful once at least one scan has actually run — nothing to
        # refresh at initial launch or right after Reset clears the table.
        self.reload_btn.setEnabled(False)
        cl.addWidget(self.reload_btn)
        cl.addSpacing(6)

        self.clear_btn = QPushButton("Reset")
        self.clear_btn.setToolTip("Unblock all devices and clear the table")
        self.clear_btn.setAttribute(Qt.WA_StyledBackground, True)
        self.clear_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {DANGER};
                border: none;
                border-radius: 8px;
                font-size: 12px;
                font-weight: 500;
                padding: 6px 12px;
                min-height: 34px;
                max-height: 34px;
            }}
            QPushButton:hover    {{ background: transparent; color: #c0392b; }}
            QPushButton:pressed  {{ background: transparent; color: #922b21; }}
            QPushButton:disabled {{ background: transparent; color: {FG3}; }}
        """ + TOOLTIP_CSS)
        self.clear_btn.setCursor(Qt.PointingHandCursor)
        self.clear_btn.clicked.connect(self._clear_table)
        cl.addWidget(self.clear_btn)

        parent.addWidget(ctrl)

    def _build_status_bar(self, parent: QVBoxLayout) -> None:
        """Thin status bar at the bottom with an activity dot and a last-action message."""
        sb = QFrame()
        sb.setFixedHeight(28)
        sb.setStyleSheet(f"background:{BG}; border-top:1px solid {BORDER};")
        sbl = QHBoxLayout(sb)
        sbl.setContentsMargins(16, 0, 16, 0)
        sbl.setSpacing(6)

        self.dot_lbl    = label("●", FG3, 8)
        self.status_lbl = label("Ready — click Scan Network to begin", FG2, 11)
        sbl.addWidget(self.dot_lbl)
        sbl.addWidget(self.status_lbl)
        sbl.addStretch()

        ver_lbl = label(f"v{VERSION}", FG3, 10)
        ver_lbl.setStyleSheet(
            f"QLabel {{ color:{FG3}; font-size:10px; letter-spacing:0.5px; background:transparent; }} "
            + TOOLTIP_CSS
        )
        sbl.addWidget(ver_lbl)

        parent.addWidget(sb)

    # ---------------------------------------------------------------------------
    # Visibility toggles
    # ---------------------------------------------------------------------------

    def _visibility_btn(self) -> QPushButton:
        """Create an icon-only eye toggle for revealing or concealing a sensitive field.

        Starts with the eye (show) icon since fields are hidden by default.
        The icon swaps to eye-slash when the field is revealed. No background
        fill on hover — same rule as Reload and Reset — only the icon color
        shifts from FG3 (idle) to FG2 (hover), handled by _ToggleIconHover.
        """
        btn = icon_button(EYE_SVG, size=20, icon_size=13, idle_color=FG3)
        return btn

    def _set_eye_icon(self, btn: QPushButton, visible: bool) -> None:
        """Render an eye/eye-slash icon reflecting both toggle state and hover state."""
        svg = EYE_SLASH_SVG if visible else EYE_SVG
        color = FG2 if btn.underMouse() else FG3
        btn.setIcon(svg_icon(svg, 13, color))

    def _toggle_gw_mac(self) -> None:
        """Toggle visibility of the gateway MAC address in the toolbar."""
        self._gw_mac_visible = not self._gw_mac_visible
        self._refresh_gw_mac_label()

    def _refresh_gw_mac_label(self) -> None:
        """Redraw the GW MAC label to match the current scan state and visibility setting.

        Three states are handled:
          - No scan yet: label and toggle remain hidden entirely.
          - Scan ran but MAC not resolved: label shows 'not found' with no toggle.
          - MAC found: label shows masked placeholder or actual value based on toggle state.
        """
        if self._gw_mac_actual == "—":
            # No scan has happened yet
            self.gw_mac_lbl.setVisible(False)
            self.gw_mac_toggle.setVisible(False)
            return

        if self._gw_mac_actual == "(not found)":
            # Scan completed but gateway MAC could not be resolved
            self.gw_mac_lbl.setVisible(True)
            self.gw_mac_lbl.setText("Gateway MAC: not found")
            self.gw_mac_toggle.setVisible(False)
            return

        # MAC resolved successfully: show with toggle
        self.gw_mac_lbl.setVisible(True)
        self.gw_mac_toggle.setVisible(True)
        self._set_eye_icon(self.gw_mac_toggle, self._gw_mac_visible)
        if self._gw_mac_visible:
            self.gw_mac_lbl.setText(f"Gateway MAC:  {self._gw_mac_actual}")
            self.gw_mac_toggle.setToolTip("Hide gateway MAC address")
        else:
            self.gw_mac_lbl.setText("Gateway MAC:  xx:xx:xx:xx:xx:xx")
            self.gw_mac_toggle.setToolTip("Show gateway MAC address")

    def _toggle_iface(self) -> None:
        """Toggle visibility of the network interface name and local IP in the nav bar."""
        self._iface_visible = not self._iface_visible
        self._refresh_iface_label()

    def _refresh_iface_label(self) -> None:
        """Redraw the interface/IP label and reveal the MY IP prefix and toggle on first scan.

        Before any scan the label area is completely empty. Once scan data is available
        the 'MY IP' prefix and eye toggle appear. The IP is either shown as the real value
        or replaced with a masked placeholder when hidden.
        """
        has_data = bool(self._iface_actual)
        self.iface_name_lbl.setVisible(has_data)
        self.iface_type_lbl.setVisible(has_data)
        self.iface_toggle.setVisible(has_data)
        if not has_data:
            self.iface_lbl.setText("")
            return
        # Interface name (e.g. "en0") is always shown; only the IP is toggleable
        self.iface_name_lbl.setText(self._iface_name_actual)
        self._set_eye_icon(self.iface_toggle, self._iface_visible)
        if self._iface_visible:
            self.iface_lbl.setText(self._iface_actual)
            self.iface_toggle.setToolTip("Hide local IP address")
        else:
            self.iface_lbl.setText("xxx.xxx.xxx.xxx")
            self.iface_toggle.setToolTip("Show local IP address")

    # ---------------------------------------------------------------------------
    # Stats strip
    # ---------------------------------------------------------------------------

    def _update_stats(self) -> None:
        """Recompute device counts and push updated values to the stats strip tiles."""
        total   = len(self.devices)
        blocked = sum(1 for d in self.devices.values() if d.get("status") == "Blocked")
        online  = total - blocked

        def _apply(t=total, b=blocked, o=online):
            self.stat_total_val.setText(str(t))
            self.stat_total_val.setStyleSheet(
                f"QLabel {{ color:{'#8b5cf6' if t > 0 else FG3}; font-size:22px; "
                f"font-weight:bold; background:transparent; }} " + TOOLTIP_CSS)
            self.stat_blocked_val.setText(str(b))
            self.stat_blocked_val.setStyleSheet(
                f"QLabel {{ color:{DANGER if b > 0 else FG3}; font-size:22px; "
                f"font-weight:bold; background:transparent; }} " + TOOLTIP_CSS)
            self.stat_online_val.setText(str(o))
            self.stat_online_val.setStyleSheet(
                f"QLabel {{ color:{SUCCESS if o > 0 else FG3}; font-size:22px; "
                f"font-weight:bold; background:transparent; }} " + TOOLTIP_CSS)

        self._ui(_apply)

    # ---------------------------------------------------------------------------
    # Selection and button state
    # ---------------------------------------------------------------------------

    def _on_selection_changed(self) -> None:
        """Update button enabled states to reflect the current selection and device statuses."""
        ips           = self._selected_ips()
        has_sel       = bool(ips)
        any_blocked   = any(self.devices.get(ip, {}).get("status") == "Blocked" for ip in ips)
        any_unblocked = any(self.devices.get(ip, {}).get("status") != "Blocked" for ip in ips)
        gw_known      = bool(self.gateway_mac)

        self.block_btn.setEnabled(has_sel and any_unblocked and gw_known)
        self.unblock_btn.setEnabled(has_sel and any_blocked)

        any_dev_blocked   = any(d.get("status") == "Blocked"  for d in self.devices.values())
        any_dev_unblocked = any(d.get("status") != "Blocked"  for d in self.devices.values())
        self.block_all_btn.setEnabled(bool(self.devices) and any_dev_unblocked and gw_known)
        self.unblock_all_btn.setEnabled(any_dev_blocked)
        self.clear_btn.setEnabled(bool(self.devices))

    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        """Update button states when a checkbox in column 0 is ticked or unticked."""
        if item.column() == 0:
            self._on_selection_changed()

    def _set_status(self, msg: str, color: str = FG2) -> None:
        self._ui(lambda: (
            self.status_lbl.setText(msg),
            self.dot_lbl.setStyleSheet(
                f"color:{color}; font-size:8px; background:transparent;")
        ))

    # ---------------------------------------------------------------------------
    # Table cell helpers
    # ---------------------------------------------------------------------------

    def _cell(self, text: str, fg: str = None, bg: str = None,
               center: bool = False) -> QTableWidgetItem:
        item = QTableWidgetItem(text)
        item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
        item.setTextAlignment(
            (Qt.AlignCenter if center else Qt.AlignLeft) | Qt.AlignVCenter)
        if fg:
            item.setForeground(QColor(fg))
        if bg:
            item.setBackground(QColor(bg))
        return item

    def _set_row_bg(self, row: int, color: str = None) -> None:
        bg = color or (ROW_A if row % 2 == 0 else ROW_B)
        for col in range(self.table.columnCount()):
            item = self.table.item(row, col)
            if item:
                item.setBackground(QColor(bg))

    # ---------------------------------------------------------------------------
    # Scanning
    # ---------------------------------------------------------------------------

    def _start_scan(self) -> None:
        if self.scan_running:
            return
        self.scan_running = True
        self.scan_btn.setEnabled(False)
        self.reload_btn.setEnabled(False)
        self._set_status("Scanning network...", WARNING)
        self.scanning_sub.setText(
            f"Sending ARP requests to {self.gateway_ip.strip()}/24...")
        self.stack.setCurrentIndex(1)   # show scanning page while sweep runs
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self) -> None:
        """Main scan routine executed in a background thread.

        Steps:
          1. Resolve the interface, local IP, and local MAC for the configured gateway.
          2. Look up the gateway MAC address via live ARP then OS cache fallback.
          3. Broadcast an ARP request across the /24 subnet to discover devices.
          4. Fall back to the OS ARP cache if the live sweep returns nothing.
          5. Spawn a ping thread and a name resolution thread for each new device.
          6. Schedule a second-pass name lookup for hostnames that mDNS resolves late.
        """
        gw = self.gateway_ip.strip()

        iface, local_ip, local_mac = network.select_interface(gw)
        self.iface  = iface
        self.my_mac = local_mac

        self._iface_name_actual = iface
        self._iface_actual = local_ip
        self._ui(lambda: (
            self._refresh_iface_label(),
            self.nav_dot.setStyleSheet(
                f"color:{SUCCESS}; font-size:9px; background:transparent;"),
            self.nav_status.setStyleSheet(
                f"QLabel {{ color:{FG2}; font-size:11px; background:transparent; }} " + TOOLTIP_CSS),
            self.nav_status.setText("Active"),
        ))

        self.gateway_mac = network.resolve_gateway_mac(gw)
        mac_txt = self.gateway_mac if self.gateway_mac else "(not found)"
        self._gw_mac_actual = mac_txt
        self._ui(self._refresh_gw_mac_label)

        found = []
        try:
            found = network.scan_subnet(gw, iface, local_ip)
        except PermissionError:
            self._set_status("Permission denied — run with sudo", DANGER)
            self._ui(lambda: (
                self.scan_btn.setEnabled(True),
                self.reload_btn.setEnabled(True),
                setattr(self, "scan_running", False)
            ))
            return
        except Exception:
            pass

        if not found:
            found = network.arp_cache_fallback(gw)

        self._arp_names = network.bulk_hostnames()

        for ip, mac in found:
            if ip not in self.ip_to_row:
                self.devices[ip] = {
                    "mac": mac, "hn": "resolving...",
                    "status": "Online", "running": False,
                    "thread": None, "ping_ms": "—"
                }
                self._ui(lambda i=ip, m=mac: self._insert_row(i, m, "resolving..."))
                threading.Thread(
                    target=self._ping_loop,    args=(ip,),     daemon=True).start()
                threading.Thread(
                    target=self._resolve_name, args=(ip, mac), daemon=True).start()

        threading.Thread(target=self._delayed_name_refresh, daemon=True).start()

        # _finish reads rowCount() after all queued _insert_row calls have executed,
        # so the displayed count always matches the actual number of rows in the table.
        def _finish():
            n = self.table.rowCount()
            self.scan_btn.setEnabled(True)
            self.reload_btn.setEnabled(True)
            self.scan_running = False
            # Always set the correct page; a re-scan stays on page 1 (scanning) until _finish
            # runs here, so this explicit switch is needed whether n > 0 or n == 0.
            self.stack.setCurrentIndex(2 if n > 0 else 0)
            self.status_lbl.setText(
                f"Scan complete — {n} device{'s' if n != 1 else ''} found")
            self.dot_lbl.setStyleSheet(
                f"color:{SUCCESS}; font-size:8px; background:transparent;")
            self._update_stats()
            self._on_selection_changed()

        self._ui(_finish)

    def _insert_row(self, ip: str, mac: str, hn: str) -> None:
        """Insert a device row into the table. Must only be called from the Qt main thread."""
        if ip in self.ip_to_row:
            return
        if self.table.rowCount() == 0:
            self.stack.setCurrentIndex(2)   # switch from scanning page to table view
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.ip_to_row[ip] = row

        # Col 0: checkbox for selection; ticking this row enables block/unblock buttons
        chk = QTableWidgetItem()
        chk.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
        chk.setCheckState(Qt.Unchecked)
        chk.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
        self.table.setItem(row, 0, chk)

        self.table.setItem(row, 1, self._cell(ip,  FG2))
        self.table.setItem(row, 2, self._cell(mac, FG3))
        self.table.setItem(row, 3, self._cell(hn,  FG3))
        self.table.setItem(row, 4, self._cell("—", FG3, center=True))
        self.table.setItem(row, 5, self._cell("● Online", SUCCESS, center=True))

    # ---------------------------------------------------------------------------
    # Name resolution
    # ---------------------------------------------------------------------------

    def _resolve_name(self, ip: str, mac: str) -> None:
        """Resolve a human-readable name for the given device. Runs in a background thread.

        Resolution order:
          1. Bulk ARP cache populated right after the scan. macOS includes Bonjour/mDNS
             hostnames here without any extra network requests (e.g. "Muhammads-iPhone").
          2. Direct socket.gethostbyaddr lookup for names not yet in the ARP cache.
          3. OUI vendor database as a last resort to at least show the manufacturer name.

        The resolved name is written back to the table via the UI bridge.
        """
        name = self._arp_names.get(ip, "")

        if not name:
            name = network.resolve_hostname(ip)

        vendor = oui.vendor(mac)
        if name:
            if vendor:
                name = f"{name}  [{vendor}]"
            elif oui.is_randomized(mac):
                name = f"{name}  [Private MAC]"
        else:
            if vendor:
                name = f"[{vendor}]"
            elif oui.is_randomized(mac):
                name = "[Private MAC]"
            else:
                name = "—"

        if ip in self.devices:
            self.devices[ip]["hn"] = name
        self._ui(lambda i=ip, n=name: self._update_name(i, n))

    def _update_name(self, ip: str, name: str) -> None:
        """Update the Device cell for the given IP. Must be called from the main thread."""
        row = self.ip_to_row.get(ip)
        if row is None:
            return
        item = self.table.item(row, 3)
        if item:
            item.setText(name)
            # Dim tag-only labels. Use full brightness for real hostnames.
            is_tag_only = name.startswith("[") or name == "—"
            item.setForeground(QColor(FG3 if is_tag_only else FG))

    def _delayed_name_refresh(self) -> None:
        """Re-run the bulk ARP hostname lookup after a short delay and update stale rows.

        mDNSResponder sometimes takes a few seconds to resolve names for newly discovered
        devices. This second pass runs 4 seconds after the scan completes to catch
        hostnames that were not yet available immediately after discovery.
        """
        time.sleep(4)
        fresh = network.bulk_hostnames()
        for ip, d in list(self.devices.items()):
            if ip in fresh and d.get("hn") in ("—", "[Private MAC]", "", "resolving..."):
                name = fresh[ip]
                d["hn"] = name
                self._ui(lambda i=ip, n=name: self._update_name(i, n))

    # ---------------------------------------------------------------------------
    # Latency measurement
    # ---------------------------------------------------------------------------

    def _ping_loop(self, ip: str) -> None:
        """Continuously ping the given IP every 2 seconds and update the Latency column.

        Pauses while the device is blocked because the spoof loop owns the Latency column
        during that time to display the ARP packet counter.
        """
        while ip in self.devices:
            if self.devices.get(ip, {}).get("status") == "Blocked":
                time.sleep(2)
                continue
            ms = network.ping(ip)
            if ip not in self.devices:
                break
            self.devices[ip]["ping_ms"] = ms if ms is not None else "timeout"
            self._ui(lambda i=ip, p=self.devices[ip]["ping_ms"]: self._update_ping(i, p))
            time.sleep(2)

    def _update_ping(self, ip: str, ping) -> None:
        row = self.ip_to_row.get(ip)
        if row is None:
            return
        if isinstance(ping, int):
            ping_s = f"{ping} ms"
            color  = SUCCESS if ping < 50 else (WARNING if ping < 200 else DANGER)
        elif ping == "timeout":
            ping_s, color = "timeout", DANGER
        else:
            ping_s, color = str(ping), FG3
        item = self.table.item(row, 4)
        if item:
            item.setText(ping_s)
            item.setForeground(QColor(color))

    def _show_spoof_count(self, ip: str, count: int) -> None:
        """Display the running ARP packet count in the Latency column while blocking is active."""
        row = self.ip_to_row.get(ip)
        if row is None:
            return
        item = self.table.item(row, 4)
        if item:
            item.setText(f"ARP x{count}")
            item.setForeground(QColor(DANGER))

    # ---------------------------------------------------------------------------
    # Block and unblock
    # ---------------------------------------------------------------------------

    def _selected_ips(self) -> list[str]:
        """Return the IP addresses of all rows whose checkbox is currently checked."""
        row_to_ip = {v: k for k, v in self.ip_to_row.items()}
        return [
            row_to_ip[row] for row in sorted(row_to_ip)
            if self.table.item(row, 0) is not None
            and self.table.item(row, 0).checkState() == Qt.Checked
        ]

    def _block_selected(self) -> None:
        ips = self._selected_ips()
        if not ips:
            alert(self, "Select a device from the list first.")
            return
        if not self.gateway_mac:
            alert(self, "Gateway MAC not found. Run Scan Network first.")
            return
        to_block = [ip for ip in ips
                    if self.devices.get(ip, {}).get("status") != "Blocked"]
        if not to_block:
            alert(self, "Selected device(s) are already blocked.")
            return
        for ip in to_block:
            self._block(ip, self.devices[ip]["mac"])
        self._on_selection_changed()
        n = len(to_block)
        self._set_status(f"{to_block[0]} blocked" if n == 1 else f"{n} devices blocked", DANGER)

    def _unblock_selected(self) -> None:
        ips = self._selected_ips()
        if not ips:
            alert(self, "Select a device from the list first.")
            return
        to_unblock = [ip for ip in ips
                      if self.devices.get(ip, {}).get("status") == "Blocked"]
        if not to_unblock:
            alert(self, "Selected device(s) are not currently blocked.")
            return
        for ip in to_unblock:
            self._unblock(ip, self.devices[ip]["mac"])
        self._on_selection_changed()
        n = len(to_unblock)
        self._set_status(f"{to_unblock[0]} unblocked" if n == 1 else f"{n} devices unblocked", SUCCESS)

    def _block_all(self) -> None:
        if not self.gateway_mac:
            alert(self, "Gateway MAC not found. Run Scan Network first.")
            return
        to_block = [ip for ip, d in self.devices.items()
                    if d.get("status") != "Blocked"]
        if not to_block:
            alert(self, "All devices are already blocked.")
            return
        for ip in to_block:
            self._block(ip, self.devices[ip]["mac"])
        self._on_selection_changed()
        n = len(to_block)
        self._set_status(f"{to_block[0]} blocked" if n == 1 else f"All {n} devices blocked", DANGER)

    def _unblock_all(self) -> None:
        to_unblock = [ip for ip, d in self.devices.items()
                      if d.get("status") == "Blocked"]
        if not to_unblock:
            alert(self, "No devices are currently blocked.")
            return
        for ip in to_unblock:
            self._unblock(ip, self.devices[ip]["mac"])
        self._on_selection_changed()
        n = len(to_unblock)
        self._set_status(f"{to_unblock[0]} unblocked" if n == 1 else f"All {n} devices unblocked", SUCCESS)

    def _clear_table(self) -> None:
        for ip, d in list(self.devices.items()):
            if d.get("status") == "Blocked":
                self._unblock(ip, d["mac"])
        self.table.setRowCount(0)
        self.ip_to_row.clear()
        self.devices.clear()
        self.stack.setCurrentIndex(0)   # return to the empty state page
        self._update_stats()
        self._set_status("Table cleared — click Scan Network to discover devices", FG3)
        self._on_selection_changed()
        self.reload_btn.setEnabled(False)   # back to initial state — nothing scanned yet

    def _block(self, ip: str, mac: str) -> None:
        """Start the ARP spoof loop for the given device and reflect blocked state in the UI."""
        d = self.devices.get(ip)
        if not d or d.get("running"):
            return
        d["running"] = True
        d["status"]  = "Blocked"
        t = threading.Thread(target=self._spoof_loop, args=(ip, mac), daemon=True)
        d["thread"] = t
        t.start()
        self._ui(lambda i=ip: self._update_row_status(i, "Blocked"))
        self._ui(lambda: self._on_selection_changed())
        self._update_stats()

    def _unblock(self, ip: str, mac: str) -> None:
        """Stop the ARP spoof loop and restore the device's internet access.

        Corrective ARP replies are sent to both the target and the gateway to overwrite
        the poisoned cache entries before either side issues new ARP requests.
        """
        d = self.devices.get(ip)
        if not d or not d.get("running"):
            return
        d["running"] = False
        d["status"]  = "Online"
        network.restore_pair(
            ip, mac,
            self.gateway_ip.strip(), self.gateway_mac,
            self.iface
        )
        self._ui(lambda i=ip: self._update_row_status(i, "Online"))
        self._ui(lambda i=ip: self._update_ping(i, "—"))
        self._ui(lambda: self._on_selection_changed())
        self._update_stats()

    def _update_row_status(self, ip: str, status: str) -> None:
        row = self.ip_to_row.get(ip)
        if row is None:
            return
        blocked = status == "Blocked"
        item = self.table.item(row, 5)
        if item:
            item.setText(f"● {status}")
            item.setForeground(QColor(DANGER if blocked else SUCCESS))
        self._set_row_bg(row, ROW_BLK if blocked else None)

    def _spoof_loop(self, target_ip: str, target_mac: str) -> None:
        """Continuously send spoofed ARP replies to cut the target device's internet access.

        One iteration sends two packets:
          1. To the target: claims the attacker's MAC is the gateway so all outbound
             traffic from the target is routed through this machine instead.
          2. To the gateway: claims the attacker's MAC is the target so all inbound
             traffic for the target is routed through this machine instead.
        Poisoning both sides simultaneously produces a complete connection cut.
        The loop runs at one-second intervals until device["running"] is set to False.
        """
        gw     = self.gateway_ip.strip()
        gw_mac = self.gateway_mac
        my_mac = self.my_mac
        count  = 0
        while self.devices.get(target_ip, {}).get("running"):
            try:
                network.send_spoof_pair(
                    target_ip, target_mac, gw, gw_mac, self.iface, my_mac)
                count += 1
            except Exception:
                pass   # ignore send errors and retry on the next iteration
            self._ui(lambda i=target_ip, c=count: self._show_spoof_count(i, c))
            time.sleep(1)

    # ---------------------------------------------------------------------------
    # Window lifecycle
    # ---------------------------------------------------------------------------

    def closeEvent(self, event) -> None:
        """Unblock all active devices before the window closes to restore their internet access."""
        for ip, d in list(self.devices.items()):
            if d.get("running"):
                self._unblock(ip, d["mac"])
        time.sleep(0.4)
        event.accept()
