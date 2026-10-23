#!/bin/bash
#
# Warden one-line installer.
#
#   curl -fsSL https://raw.githubusercontent.com/farhanadii/warden/main/install.sh | bash
#
# On a Mac with nothing set up, this will:
#   1. find a compatible Python (3.9-3.13), or install one from python.org
#   2. create an isolated environment and install warden-net + its deps
#   3. put a `warden` command on your PATH
#   4. launch Warden
#
# You'll be asked for your Mac password when Python needs installing and when
# Warden launches (sending raw network packets requires administrator rights).

set -euo pipefail

APP="warden-net"
CMD="warden"
VENV_DIR="$HOME/.local/share/warden/venv"
BIN_DIR="$HOME/.local/bin"
PY_MIN=9          # 3.9  (lowest PyQt5 supports)
PY_MAX=13         # 3.13 (highest with PyQt5 wheels today)
PY_PKG_VERSION="3.12.7"   # python.org installer used only if no good Python exists

say()  { printf '\033[1;34m[warden]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[warden]\033[0m %s\n' "$*" >&2; }

# ---- 1. locate a compatible Python -----------------------------------------
find_python() {
    local c ver major minor
    for c in python3.12 python3.13 python3.11 python3.10 python3.9 python3; do
        command -v "$c" >/dev/null 2>&1 || continue
        ver="$("$c" -c 'import sys; print("%d %d" % sys.version_info[:2])' 2>/dev/null)" || continue
        major="${ver% *}"; minor="${ver#* }"
        if [ "$major" = "3" ] && [ "$minor" -ge "$PY_MIN" ] && [ "$minor" -le "$PY_MAX" ]; then
            printf '%s\n' "$c"; return 0
        fi
    done
    return 1
}

install_python_macos() {
    local url tmp pkg
    url="https://www.python.org/ftp/python/${PY_PKG_VERSION}/python-${PY_PKG_VERSION}-macos11.pkg"
    tmp="$(mktemp -d)"; pkg="$tmp/python.pkg"
    say "No compatible Python found — downloading Python ${PY_PKG_VERSION} from python.org ..."
    curl -fsSL "$url" -o "$pkg"
    say "Installing Python (enter your Mac password if asked) ..."
    sudo installer -pkg "$pkg" -target /
    rm -rf "$tmp"
    # python.org drops binaries here:
    export PATH="/Library/Frameworks/Python.framework/Versions/3.12/bin:/usr/local/bin:$PATH"
}

PY="$(find_python || true)"
if [ -z "${PY:-}" ]; then
    case "$(uname -s)" in
        Darwin) install_python_macos; PY="$(find_python || true)" ;;
        *) err "Please install Python ${PY_MIN}-${PY_MAX} (3.x) first, then re-run."; exit 1 ;;
    esac
fi
[ -n "${PY:-}" ] || { err "Could not obtain a compatible Python. Aborting."; exit 1; }
say "Using $("$PY" --version 2>&1)  ($PY)"

# ---- 2. isolated environment + install -------------------------------------
say "Installing Warden and its dependencies (downloads PyQt5 + scapy) ..."
rm -rf "$VENV_DIR"
"$PY" -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --quiet --upgrade pip
"$VENV_DIR/bin/python" -m pip install --quiet "$APP"

# ---- 3. expose the `warden` command ----------------------------------------
mkdir -p "$BIN_DIR"
ln -sf "$VENV_DIR/bin/$CMD" "$BIN_DIR/$CMD"
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)  printf '\nexport PATH="%s:$PATH"\n' "$BIN_DIR" >> "$HOME/.zshrc"
        export PATH="$BIN_DIR:$PATH"
        say "Added $BIN_DIR to your PATH (in ~/.zshrc)." ;;
esac

say "Warden installed. You can run it any time by typing:  $CMD"

# ---- 4. launch (self-elevates via sudo for raw packets) --------------------
if [ -t 1 ]; then
    say "Launching Warden — enter your Mac password when prompted ..."
    exec "$BIN_DIR/$CMD"
else
    say "Open a new terminal and type:  $CMD"
fi
