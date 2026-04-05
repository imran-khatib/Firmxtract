#!/usr/bin/env bash
# ==============================================================================
#  FirmXtract v0.1.0 — Automated Installer
#  Supports: Ubuntu, Debian, Kali Linux, macOS
# ==============================================================================

set -e  # exit on any error

# ------------------------------------------------------------------------------
# Colors
# ------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*"; }
step()    { echo -e "\n${BOLD}==> $*${RESET}"; }
die()     { error "$*"; exit 1; }

# ------------------------------------------------------------------------------
# Banner
# ------------------------------------------------------------------------------
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║${RESET}   ${BOLD}FirmXtract v0.1.0 — Installer${RESET}              ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}   IoT Firmware Extraction Framework           ${CYAN}║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════════╝${RESET}"
echo ""

# ------------------------------------------------------------------------------
# Sudo check — warn if running as root (pip + venv should NOT be run as root)
# ------------------------------------------------------------------------------
if [[ "$EUID" -eq 0 ]]; then
    warn "You are running as root (sudo)."
    warn "This is NOT recommended for pip/venv operations."
    warn "The installer will use sudo only for system package installs (apt/brew)."
    warn "If you ran: sudo ./install.sh — consider running: ./install.sh instead."
    echo ""
    read -r -p "  Continue anyway as root? [y/N] " ROOT_REPLY
    ROOT_REPLY=${ROOT_REPLY:-N}
    if [[ ! "$ROOT_REPLY" =~ ^[Yy]$ ]]; then
        echo ""
        echo "  Run without sudo:"
        echo "    ./install.sh"
        echo "  or:"
        echo "    bash install.sh"
        exit 0
    fi
fi

# ------------------------------------------------------------------------------
# Detect OS
# ------------------------------------------------------------------------------
step "Detecting operating system..."

OS=""
PKG_MANAGER=""

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if command -v apt-get &>/dev/null; then
        OS="debian"
        PKG_MANAGER="apt-get"
        success "Detected: Debian/Ubuntu/Kali Linux (apt)"
    elif command -v dnf &>/dev/null; then
        OS="fedora"
        PKG_MANAGER="dnf"
        success "Detected: Fedora/RHEL (dnf)"
    elif command -v pacman &>/dev/null; then
        OS="arch"
        PKG_MANAGER="pacman"
        success "Detected: Arch Linux (pacman)"
    else
        warn "Unknown Linux distro. Will skip system package install."
        OS="linux_unknown"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    if command -v brew &>/dev/null; then
        PKG_MANAGER="brew"
        success "Detected: macOS with Homebrew"
    else
        warn "macOS detected but Homebrew not found."
        warn "Install Homebrew from https://brew.sh then re-run this script."
        PKG_MANAGER=""
    fi
else
    die "Unsupported OS: $OSTYPE. Please install manually (see README.txt)."
fi

# ------------------------------------------------------------------------------
# Check Python version
# ------------------------------------------------------------------------------
step "Checking Python version..."

PYTHON=""
# Try specific version commands first, then fall back to generic python3
for cmd in python3.13 python3.12 python3.11 python3.10 python3 python; do
    if command -v "$cmd" &>/dev/null; then
        # Get exact version numbers
        PY_MAJOR=$("$cmd" -c "import sys; print(sys.version_info.major)" 2>/dev/null) || continue
        PY_MINOR=$("$cmd" -c "import sys; print(sys.version_info.minor)" 2>/dev/null) || continue
        PY_VER="${PY_MAJOR}.${PY_MINOR}"
        # Require Python 3.10+
        if [[ "$PY_MAJOR" -ge 3 && "$PY_MINOR" -ge 10 ]]; then
            PYTHON="$cmd"
            success "Found: $cmd ($PY_VER)"
            break
        else
            info "Skipping $cmd ($PY_VER) — need 3.10+"
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    error "Python 3.10 or higher is required but not found."
    echo ""
    echo "  Your options:"
    if [[ "$OS" == "debian" ]]; then
        echo "    sudo apt install python3"
        echo "    sudo apt install python3.10"
        echo "    sudo apt install python3.11"
        echo ""
        echo "  If those fail, add the deadsnakes PPA:"
        echo "    sudo add-apt-repository ppa:deadsnakes/ppa"
        echo "    sudo apt update"
        echo "    sudo apt install python3.11"
    elif [[ "$OS" == "macos" ]]; then
        echo "    brew install python3"
    fi
    exit 1
fi

# ------------------------------------------------------------------------------
# Install system dependencies (flashrom, binwalk)
# ------------------------------------------------------------------------------
step "Installing system tools (flashrom, binwalk)..."

install_system_pkg() {
    local pkg="$1"
    if command -v "$pkg" &>/dev/null; then
        success "$pkg already installed: $(command -v $pkg)"
        return
    fi

    info "Installing $pkg..."

    case "$OS" in
        debian)
            sudo apt-get install -y "$pkg" 2>/dev/null && success "$pkg installed" \
                || warn "Could not install $pkg via apt. You can install it manually later."
            ;;
        fedora)
            sudo dnf install -y "$pkg" 2>/dev/null && success "$pkg installed" \
                || warn "Could not install $pkg via dnf."
            ;;
        arch)
            sudo pacman -S --noconfirm "$pkg" 2>/dev/null && success "$pkg installed" \
                || warn "Could not install $pkg via pacman."
            ;;
        macos)
            if [[ -n "$PKG_MANAGER" ]]; then
                brew install "$pkg" 2>/dev/null && success "$pkg installed" \
                    || warn "Could not install $pkg via brew."
            else
                warn "Homebrew not available. Install $pkg manually."
            fi
            ;;
        *)
            warn "Cannot auto-install $pkg on this system. Install it manually."
            ;;
    esac
}

install_system_pkg flashrom
install_system_pkg binwalk

# ------------------------------------------------------------------------------
# Check we are in the firmxtract project directory
# ------------------------------------------------------------------------------
step "Verifying project directory..."

if [[ ! -f "pyproject.toml" ]]; then
    die "pyproject.toml not found. Please run this script from the firmxtract/ directory.
  Example:
    cd firmxtract
    bash install.sh"
fi

if [[ ! -f "src/firmxtract/__init__.py" ]]; then
    die "src/firmxtract/__init__.py not found. The project structure looks incomplete."
fi

success "Project directory looks correct: $(pwd)"

# ------------------------------------------------------------------------------
# Create virtual environment
# ------------------------------------------------------------------------------
step "Setting up Python virtual environment..."

VENV_DIR=".venv"

if [[ -d "$VENV_DIR" ]]; then
    warn "Virtual environment already exists at $VENV_DIR. Reusing it."
else
    "$PYTHON" -m venv "$VENV_DIR"
    success "Virtual environment created at $VENV_DIR"
fi

# Activate
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
success "Virtual environment activated"

# Upgrade pip silently
pip install --upgrade pip --quiet
success "pip upgraded"

# ------------------------------------------------------------------------------
# Install FirmXtract
# ------------------------------------------------------------------------------
step "Installing FirmXtract and dependencies..."

# Check if dev install requested
INSTALL_DEV=false
for arg in "$@"; do
    if [[ "$arg" == "--dev" || "$arg" == "-d" ]]; then
        INSTALL_DEV=true
    fi
done

if $INSTALL_DEV; then
    info "Installing with development dependencies (--dev flag)..."
    pip install -e ".[dev]" --quiet
    success "FirmXtract installed with dev dependencies"
else
    info "Installing runtime dependencies..."
    pip install -e "." --quiet
    success "FirmXtract installed (runtime only)"
    info "  Tip: run 'bash install.sh --dev' to also install pytest, mypy, ruff, black"
fi

# ------------------------------------------------------------------------------
# Fix serial port permissions (Linux only)
# ------------------------------------------------------------------------------
if [[ "$OS" == "debian" || "$OS" == "fedora" || "$OS" == "arch" ]]; then
    step "Checking serial port permissions..."

    if groups "$USER" | grep -qw "dialout"; then
        success "User '$USER' is already in the 'dialout' group"
    else
        warn "User '$USER' is NOT in the 'dialout' group."
        warn "You will get 'Permission denied' errors on serial ports."
        echo ""
        read -r -p "  Add '$USER' to dialout group now? [Y/n] " REPLY
        REPLY=${REPLY:-Y}
        if [[ "$REPLY" =~ ^[Yy]$ ]]; then
            sudo usermod -aG dialout "$USER"
            success "Added '$USER' to dialout group."
            warn "You must LOG OUT and LOG BACK IN for this to take effect."
        else
            warn "Skipped. Run manually: sudo usermod -aG dialout $USER"
        fi
    fi
fi

# ------------------------------------------------------------------------------
# Create default config directory
# ------------------------------------------------------------------------------
step "Creating config directory..."

CONFIG_DIR="$HOME/.firmxtract"
mkdir -p "$CONFIG_DIR"
success "Config directory: $CONFIG_DIR"

# Write a starter config if none exists
CONFIG_FILE="$CONFIG_DIR/config.toml"
if [[ ! -f "$CONFIG_FILE" ]]; then
    cat > "$CONFIG_FILE" << 'TOML'
# FirmXtract configuration file
# All values shown are defaults — edit as needed.
# Full documentation: README.txt

[uart]
default_baudrate = 115200
baudrates = [9600, 38400, 57600, 115200, 230400, 921600]
read_timeout = 2.0
detection_timeout = 5.0

[spi]
default_programmer = "ch341a_spi"
verify_after_dump = true
dump_retries = 3

[binwalk]
extract = true
matryoshka = true

[output]
base_dir = "~/.firmxtract/sessions"
TOML
    success "Default config written to $CONFIG_FILE"
else
    success "Config file already exists: $CONFIG_FILE"
fi

# ------------------------------------------------------------------------------
# Verify installation
# ------------------------------------------------------------------------------
step "Verifying installation..."

if firmxtract version &>/dev/null; then
    VERSION_STR=$(firmxtract version 2>/dev/null || echo "unknown")
    success "firmxtract is working: $VERSION_STR"
else
    die "firmxtract command failed after install. Something went wrong."
fi

# Quick tool check
echo ""
info "Tool availability check:"
for tool in flashrom binwalk; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✓${RESET} $tool: $(command -v $tool)"
    else
        echo -e "  ${YELLOW}✗${RESET} $tool: not found (optional — install manually)"
    fi
done

# ------------------------------------------------------------------------------
# Done
# ------------------------------------------------------------------------------
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║   Installation complete!                     ║${RESET}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${BOLD}To activate FirmXtract in a new terminal:${RESET}"
echo -e "  ${CYAN}source $(pwd)/.venv/bin/activate${RESET}"
echo ""
echo -e "${BOLD}Quick start:${RESET}"
echo -e "  ${CYAN}firmxtract info${RESET}               # check system status"
echo -e "  ${CYAN}firmxtract extract${RESET}            # auto-detect and extract"
echo -e "  ${CYAN}firmxtract analyze firmware.bin${RESET}   # analyze existing file"
echo -e "  ${CYAN}firmxtract console --port /dev/ttyUSB0${RESET}  # open UART terminal"
echo ""
echo -e "${BOLD}Read the full guide:${RESET}"
echo -e "  cat README.txt"
echo ""

# Remind about dialout if needed
if [[ "$OS" != "macos" ]] && ! groups "$USER" | grep -qw "dialout" 2>/dev/null; then
    echo -e "${YELLOW}REMINDER:${RESET} Log out and log back in for serial port permissions to take effect."
    echo ""
fi
