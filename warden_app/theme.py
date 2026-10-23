"""
Visual design system: color palette, global Qt stylesheet, and reusable widget factories.

All UI modules import colors and factory functions from here so visual changes
can be made in one place without touching application logic.
"""

from PyQt5.QtWidgets import QLabel, QPushButton, QFrame, QMessageBox
from PyQt5.QtCore import Qt, QByteArray, QRectF, QSize
from PyQt5.QtGui import QPixmap, QPainter, QIcon, QColor, QPainterPath, QFont
from PyQt5.QtSvg import QSvgRenderer

# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------

BG       = "#0d1117"   # Application background
CANVAS   = "#161b22"   # Navigation bar and panel surfaces
SURFACE  = "#21262d"   # Cards, toolbar, control bar
SURFACE2 = "#2d333b"   # Hover and active states
BORDER   = "#30363d"   # Subtle borders and dividers
ACCENT   = "#8b5cf6"   # Primary action color (purple)
ACCENT_H = "#7c3aed"   # Accent hover state
SUCCESS  = "#3fb950"   # Online / positive state (green)
DANGER   = "#f85149"   # Blocked / error state (red)
WARNING  = "#d29922"   # Scanning / caution state (amber)
FG       = "#e6edf3"   # Primary foreground text
FG2      = "#8b949e"   # Secondary / muted text
FG3      = "#6e7681"   # Subtle / placeholder text
ROW_A    = "#161b22"   # Table row even background
ROW_B    = "#1a1f27"   # Table row odd background
ROW_BLK  = "#2d1a1a"   # Blocked device row background tint

# ---------------------------------------------------------------------------
# SVG icon strings  (stroke="currentColor" is replaced at render time)
# ---------------------------------------------------------------------------

EYE_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" '
    'stroke-width="1.5" stroke="currentColor">'
    '<path stroke-linecap="round" stroke-linejoin="round" '
    'd="M2.036 12.322a1.012 1.012 0 0 1 0-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 '
    '8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5'
    'c-4.638 0-8.573-3.007-9.963-7.178Z"/>'
    '<path stroke-linecap="round" stroke-linejoin="round" '
    'd="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z"/>'
    '</svg>'
)

EYE_SLASH_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" '
    'stroke-width="1.5" stroke="currentColor">'
    '<path stroke-linecap="round" stroke-linejoin="round" '
    'd="M3.98 8.223A10.477 10.477 0 0 0 1.934 12C3.226 16.338 7.244 19.5 12 19.5'
    'c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.451 10.451 0 0 1 12 4.5'
    'c4.756 0 8.773 3.162 10.065 7.498a10.522 10.522 0 0 1-4.293 5.774'
    'M6.228 6.228 3 3m3.228 3.228 3.65 3.65m7.894 7.894L21 21'
    'm-3.228-3.228-3.65-3.65m0 0a3 3 0 1 0-4.243-4.243m4.242 4.242L9.88 9.88"/>'
    '</svg>'
)

RELOAD_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" '
    'stroke-width="1.5" stroke="currentColor">'
    '<path stroke-linecap="round" stroke-linejoin="round" '
    'd="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0 '
    '3.181 3.183a8.25 8.25 0 0 0 13.803-3.7M4.031 9.865a8.25 8.25 0 0 1 '
    '13.803-3.7l3.181 3.182m0-4.991v4.99"/>'
    '</svg>'
)

# ---------------------------------------------------------------------------
# Tooltip stylesheet snippet
# ---------------------------------------------------------------------------
# Qt applies a widget's OWN stylesheet as the tooltip style context.  Any widget
# that calls setStyleSheet() stops inheriting the global QToolTip rule from APP_STYLE.
# Append TOOLTIP_CSS to every per-widget stylesheet that also carries a tooltip so
# the popup is always styled consistently. APP_STYLE embeds this same constant
# for its own global QToolTip rule rather than repeating the values, so the two
# can never drift out of sync.
TOOLTIP_CSS = (
    f"QToolTip {{ background: {SURFACE}; color: {FG}; "
    f"border: 1px solid {BORDER}; padding: 5px 10px; "
    f"border-radius: 6px; font-size: 12px; }}"
)

# ---------------------------------------------------------------------------
# Global stylesheet
# ---------------------------------------------------------------------------

# QTableWidget::item intentionally has no 'color' declaration so individual
# cells can use setForeground() without being overridden by the stylesheet.
# 'selection-background-color' is also omitted from QTableWidget to prevent
# Qt from forcing HighlightedText palette color (white) onto selected cells.
APP_STYLE = f"""
QMainWindow, QWidget {{
    background: {BG};
    color: {FG};
    font-family: -apple-system, 'Helvetica Neue', Arial;
    font-size: 13px;
}}
QFrame {{ background: {BG}; }}
QLineEdit {{
    background: {SURFACE};
    color: {FG};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 6px 10px;
    font-family: 'SF Mono', Menlo, Courier;
    selection-background-color: {ACCENT};
}}
QLineEdit:focus {{ border-color: {FG3}; }}
QTableWidget {{
    background: {CANVAS};
    color: {FG};
    gridline-color: {SURFACE};
    border: none;
    font-family: 'SF Mono', Menlo, Courier;
    font-size: 12px;
}}
QTableWidget::item {{ padding: 0 14px; border: none; }}
QTableWidget::item:selected {{ background: transparent; }}
QHeaderView::section {{
    background: {BG};
    color: {FG3};
    font-weight: 600;
    font-size: 10px;
    letter-spacing: 1px;
    border: none;
    border-bottom: 1px solid {SURFACE};
    padding: 10px 14px;
}}
QScrollBar:vertical {{
    background: {CANVAS};
    width: 5px;
    margin: 0;
    border: none;
}}
QScrollBar::handle:vertical {{
    background: {BORDER};
    border-radius: 2px;
    min-height: 20px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QMessageBox {{ background: {SURFACE}; }}
{TOOLTIP_CSS}
"""

# ---------------------------------------------------------------------------
# Widget factories
# ---------------------------------------------------------------------------

def _rgba(hex_color: str, alpha: float) -> str:
    """Convert a #rrggbb hex color to a CSS rgba() string with the given alpha (0–1)."""
    h = hex_color.lstrip('#')
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"


class _RoundButton(QPushButton):
    """A QPushButton that paints its own rounded background instead of using
    QSS border-radius.

    QSS border-radius on QPushButton was found to render inconsistently
    under Qt/Fusion on macOS: two buttons built from byte-for-byte identical
    stylesheet strings, enabled and painted together in the same window,
    rendered with different corner treatment (one sharp, one rounded) —
    100% reproducible across repeated runs, not a timing fluke. Painting the
    shape directly in paintEvent removes the dependency on Qt's stylesheet
    cache/style-engine behaviour for this critical a piece of the design
    system. Tooltips are unaffected — those still go through setStyleSheet
    with TOOLTIP_CSS, a wholly separate rendering path.
    """

    def __init__(self, text: str = "", bg: str = ACCENT, hover: str = None,
                 pressed: str = None, fg: str = "#ffffff",
                 radius: int = 10, vanish_disabled: bool = False,
                 icon_only: bool = False, bold: bool = True,
                 font_size: int = 12, parent=None) -> None:
        super().__init__(text, parent)
        self._bg = bg
        self._hover_bg = hover or bg
        self._pressed_bg = pressed or self._hover_bg
        self._fg = fg
        self._radius = radius
        self._vanish_disabled = vanish_disabled
        self._icon_only = icon_only
        self._bold = bold
        self._font_size = font_size
        self.setCursor(Qt.PointingHandCursor)
        self.setFlat(True)

    def enterEvent(self, event) -> None:
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        self.update()
        super().leaveEvent(event)

    def _current_bg(self) -> str:
        if not self.isEnabled():
            return "transparent" if (self._vanish_disabled or self._icon_only) else SURFACE
        if self.isDown():
            return self._pressed_bg
        if self.underMouse():
            return self._hover_bg
        return self._bg

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        rect = QRectF(self.rect())
        path = QPainterPath()
        path.addRoundedRect(rect, self._radius, self._radius)
        painter.fillPath(path, QColor(self._current_bg()))

        if self._icon_only:
            icon = self.icon()
            if not icon.isNull():
                sz = self.iconSize()
                x = (self.width() - sz.width()) // 2
                y = (self.height() - sz.height()) // 2
                if not self.isEnabled():
                    painter.setOpacity(0.35)
                icon.paint(painter, x, y, sz.width(), sz.height())
        else:
            font = QFont(self.font())
            font.setPixelSize(self._font_size)
            font.setBold(self._bold)
            font.setLetterSpacing(QFont.AbsoluteSpacing, 0.2)
            painter.setFont(font)
            fg = self._fg if self.isEnabled() else FG3
            painter.setPen(QColor(fg))
            painter.drawText(self.rect(), Qt.AlignCenter, self.text())

        painter.end()

    def sizeHint(self):
        from PyQt5.QtCore import QSize
        from PyQt5.QtGui import QFontMetrics
        if self._icon_only:
            sz = self.iconSize()
            return QSize(max(sz.width(), 20) + 16, max(sz.height(), 20) + 16)
        font = QFont(self.font())
        font.setPixelSize(self._font_size)
        font.setBold(self._bold)
        fm = QFontMetrics(font)
        w = fm.horizontalAdvance(self.text()) + 32
        h = fm.height() + 14
        return QSize(w, h)


def button(text: str, bg: str = ACCENT, hover: str = None,
           ghost: bool = False, color: str = None,
           vanish_disabled: bool = False, radius: int = 10,
           height: int = None) -> QPushButton:
    """Create a styled button matching the application design system.

    ghost=True           — secondary outline-style button (QSS-rendered QPushButton).
    color=<hex>          — for ghost buttons, tints border and label with the given color.
    vanish_disabled=True — filled buttons only: disabled state dissolves to faint text
                           with no shape so the button vanishes when it cannot be used.
    radius=<int>         — corner radius in px. Use 8–10 for compact/inline controls
                           and 18–20 for main action buttons (Scan/Block/Unblock use
                           20, which exceeds half their height and renders as a full
                           pill/stadium shape — the house style for primary actions).
    height=<int>         — fixed row height in px.

    Non-ghost (filled) buttons return a _RoundButton, which paints its own
    background instead of using QSS border-radius — see that class's
    docstring for why. Ghost buttons are unused elsewhere in the app today
    and still use plain QSS.
    """
    hover = hover or bg
    height_css = f"min-height:{height}px; max-height:{height}px;" if height else ""
    # Qt's box model adds padding on top of min-height/max-height rather than
    # inside it (content-box behaviour) — a button with height=34 and 6px
    # vertical padding renders at 46px, not 34px. When an explicit height is
    # given, vertical padding must be 0 and min/max-height does all the work;
    # Qt still centers the label vertically within that box on its own.
    v_pad = "0" if height else "6px"
    if ghost:
        if color:
            bord   = _rgba(color, 0.35)
            hov_bg = _rgba(color, 0.08)
            pre_bg = _rgba(color, 0.14)
            style = f"""
                QPushButton {{
                    background: transparent;
                    color: {color};
                    border: 1px solid {bord};
                    border-radius: {radius}px;
                    padding: {v_pad} 16px;
                    font-size: 12px;
                    font-weight: 500;
                    {height_css}
                }}
                QPushButton:hover   {{ background: {hov_bg}; border-color: {color}; }}
                QPushButton:pressed {{ background: {pre_bg}; border-color: {color}; }}
                QPushButton:disabled {{
                    background: transparent;
                    color: {FG3};
                    border: 1px solid {SURFACE};
                }}
            """
        else:
            style = f"""
                QPushButton {{
                    background: transparent;
                    color: {FG2};
                    border: 1px solid {BORDER};
                    border-radius: {radius}px;
                    padding: {v_pad} 16px;
                    font-size: 12px;
                    font-weight: 500;
                    {height_css}
                }}
                QPushButton:hover   {{ background: {SURFACE}; color: {FG}; border-color: {FG3}; }}
                QPushButton:pressed {{ background: {SURFACE2}; color: {FG}; }}
                QPushButton:disabled {{
                    background: transparent;
                    color: {FG3};
                    border: 1px solid {SURFACE};
                }}
            """
        btn = QPushButton(text)
        btn.setCursor(Qt.PointingHandCursor)
        btn.setStyleSheet(style + "\n" + TOOLTIP_CSS)
        return btn

    # Filled/primary buttons (Scan, Block, Unblock, Block All, Unblock All):
    # painted by _RoundButton rather than QSS, see its docstring for why.
    btn = _RoundButton(
        text, bg=bg, hover=hover, pressed=hover,
        radius=radius, vanish_disabled=vanish_disabled,
    )
    if height:
        btn.setFixedHeight(height)
    btn.setStyleSheet(TOOLTIP_CSS)   # tooltip popup styling only — paintEvent owns the body
    return btn


def icon_button(icon_svg: str, size: int = 36, icon_size: int = 18,
                 idle_color: str = FG, radius: int = None,
                 hover_bg: str = "transparent", pressed_bg: str = SURFACE2) -> QPushButton:
    """Create a circular icon-only button (reload, eye/visibility toggle, etc).

    Built on _RoundButton for the same reason as button() — QSS border-radius
    proved unreliable on QPushButton under Qt/Fusion/macOS, so the circle is
    painted directly instead. hover_bg="transparent" (the default) means no
    fill at all on hover — only whatever icon-color change the caller wires
    up separately (see _IconHover) provides feedback; pass an actual color
    for hover_bg if a filled circle on hover is wanted instead.
    """
    radius = radius if radius is not None else size // 2
    btn = _RoundButton(bg="transparent", hover=hover_bg, pressed=pressed_bg,
                        radius=radius, icon_only=True)
    btn.setIcon(svg_icon(icon_svg, icon_size, idle_color))
    btn.setIconSize(QSize(icon_size, icon_size))
    btn.setFixedSize(size, size)
    btn.setStyleSheet(TOOLTIP_CSS)
    return btn


def label(text: str, color: str = FG, size: int = 12,
          bold: bool = False, bg: str = "transparent") -> QLabel:
    """Create a styled QLabel with the given text color, font size, and weight."""
    lbl = QLabel(text)
    weight = "bold" if bold else "normal"
    lbl.setStyleSheet(
        f"QLabel {{ color:{color}; font-size:{size}px; font-weight:{weight}; background:{bg}; }} "
        + TOOLTIP_CSS
    )
    return lbl


def alert(parent, text: str) -> None:
    """Display a modal message dialog with a single OK button and no icon."""
    d = QMessageBox(parent)
    d.setWindowTitle("Warden")
    d.setText(text)
    d.setIcon(QMessageBox.NoIcon)
    d.setStandardButtons(QMessageBox.Ok)
    d.setStyleSheet(f"""
        QMessageBox {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 8px; }}
        QLabel       {{ color: {FG}; font-size: 13px; background: transparent; }}
        QPushButton  {{
            background: {SURFACE2}; color: {FG}; border: 1px solid {BORDER};
            border-radius: 6px; padding: 5px 20px; font-size: 12px; min-width: 60px;
        }}
        QPushButton:hover {{ background: {BORDER}; }}
    """)
    d.exec_()


def vdivider() -> QFrame:
    """Create a 1px vertical divider line for use in horizontal layouts."""
    div = QFrame()
    div.setFrameShape(QFrame.VLine)
    div.setFixedWidth(1)
    div.setStyleSheet(f"background: {BORDER}; border: none;")
    return div


def svg_icon(svg_str: str, size: int = 14, color: str = FG3) -> QIcon:
    """Render an SVG string as a QIcon at 2× resolution for Retina/HiDPI displays.

    currentColor in the SVG is replaced with the given hex color before rendering.
    size is the logical pixel size; the pixmap is created at size*2 and its
    devicePixelRatio set to 2.0 so Qt displays it at the correct logical size.
    """
    filled = svg_str.replace("currentColor", color)
    renderer = QSvgRenderer(QByteArray(filled.encode("utf-8")))
    px = QPixmap(size * 2, size * 2)
    px.fill(Qt.transparent)
    painter = QPainter(px)
    renderer.render(painter)
    painter.end()
    px.setDevicePixelRatio(2.0)
    return QIcon(px)
