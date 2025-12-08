#!/bin/bash
#
# Recon-Superpowers Linux Installation Script
# Comprehensive installation script for setting up all dependencies and tools
# required by Recon-Superpowers on Linux systems.
#
# Supported: Debian/Ubuntu, Fedora/RHEL/CentOS, Arch Linux, Kali Linux
# Version: 1.0
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Installation paths
INSTALL_PATH="${HOME}/ReconTools"
WORDLIST_PATH="${INSTALL_PATH}/wordlists"
CONFIG_PATH="${HOME}/.recon_superpower"

# Flags
SKIP_APT=false
SKIP_TOOLS=false
SKIP_GIT_REPOS=false
SKIP_WORDLISTS=false
VERBOSE=false

print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'

╔══════════════════════════════════════════════════════════════════╗
║                    RECON-SUPERPOWERS INSTALLER                    ║
║                      Linux Installation Script                    ║
║                           Version 1.0                             ║
╚══════════════════════════════════════════════════════════════════╝

EOF
    echo -e "${NC}"
}

print_section() {
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  $1${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

print_error() {
    echo -e "${RED}[✗] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

print_info() {
    echo -e "${CYAN}[*] $1${NC}"
}

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_VERSION=$VERSION_ID
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        DISTRO=$DISTRIB_ID
        DISTRO_VERSION=$DISTRIB_RELEASE
    else
        DISTRO="unknown"
        DISTRO_VERSION="unknown"
    fi

    # Check for Kali Linux specifically
    if [ -f /etc/os-release ] && grep -qi "kali" /etc/os-release; then
        DISTRO="kali"
    fi

    echo -e "${CYAN}Detected Distribution: ${WHITE}$DISTRO $DISTRO_VERSION${NC}"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_warning "Not running as root. Some installations may require sudo password."
        SUDO="sudo"
    else
        SUDO=""
    fi
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install package based on distro
install_package() {
    local package=$1
    local alt_package=${2:-$1}

    case $DISTRO in
        ubuntu|debian|kali|linuxmint|pop)
            $SUDO apt-get install -y "$package" 2>/dev/null || $SUDO apt-get install -y "$alt_package" 2>/dev/null
            ;;
        fedora)
            $SUDO dnf install -y "$package" 2>/dev/null || $SUDO dnf install -y "$alt_package" 2>/dev/null
            ;;
        centos|rhel|rocky|almalinux)
            $SUDO yum install -y "$package" 2>/dev/null || $SUDO yum install -y "$alt_package" 2>/dev/null
            ;;
        arch|manjaro|endeavouros)
            $SUDO pacman -S --noconfirm "$package" 2>/dev/null || $SUDO pacman -S --noconfirm "$alt_package" 2>/dev/null
            ;;
        opensuse*)
            $SUDO zypper install -y "$package" 2>/dev/null || $SUDO zypper install -y "$alt_package" 2>/dev/null
            ;;
        *)
            print_warning "Unknown distro. Trying apt-get..."
            $SUDO apt-get install -y "$package" 2>/dev/null || return 1
            ;;
    esac
}

# Update package manager
update_packages() {
    print_section "Updating Package Manager"

    case $DISTRO in
        ubuntu|debian|kali|linuxmint|pop)
            print_info "Running apt update..."
            $SUDO apt-get update -qq
            ;;
        fedora)
            print_info "Running dnf update..."
            $SUDO dnf check-update -q || true
            ;;
        centos|rhel|rocky|almalinux)
            print_info "Running yum update..."
            $SUDO yum check-update -q || true
            ;;
        arch|manjaro|endeavouros)
            print_info "Running pacman -Sy..."
            $SUDO pacman -Sy --noconfirm
            ;;
        opensuse*)
            print_info "Running zypper refresh..."
            $SUDO zypper refresh -q
            ;;
    esac

    print_success "Package manager updated"
}

# Install essential build tools
install_essentials() {
    print_section "Installing Essential Tools"

    local packages=(
        "git"
        "curl"
        "wget"
        "python3"
        "python3-pip"
        "python3-venv"
        "python3-tk"
    )

    for pkg in "${packages[@]}"; do
        if ! command_exists "$pkg" 2>/dev/null; then
            print_info "Installing $pkg..."
            install_package "$pkg" || print_warning "Could not install $pkg"
        else
            print_success "$pkg already installed"
        fi
    done

    # Ensure pip is up to date
    print_info "Upgrading pip..."
    python3 -m pip install --upgrade pip --quiet 2>/dev/null || true

    print_success "Essential tools installed"
}

# Install Python packages
install_python_packages() {
    print_section "Installing Python Packages"

    local packages=(
        "shodan"
        "pillow"
        "requests"
        "dnspython"
        "netaddr"
        "lxml"
    )

    for pkg in "${packages[@]}"; do
        print_info "Installing Python package: $pkg..."
        python3 -m pip install "$pkg" --quiet --user 2>/dev/null || print_warning "Could not install $pkg"
    done

    print_success "Python packages installed"
}

# Install Nmap
install_nmap() {
    print_section "Installing Nmap"

    if command_exists nmap; then
        print_success "Nmap is already installed"
        nmap --version | head -n 2
        return 0
    fi

    print_info "Installing Nmap..."
    install_package "nmap"

    if command_exists nmap; then
        print_success "Nmap installed successfully"
        nmap --version | head -n 2
    else
        print_error "Failed to install Nmap"
        return 1
    fi
}

# Install Gobuster
install_gobuster() {
    print_section "Installing Gobuster"

    if command_exists gobuster; then
        print_success "Gobuster is already installed"
        gobuster version 2>/dev/null || true
        return 0
    fi

    print_info "Installing Gobuster..."

    # Try package manager first
    install_package "gobuster" 2>/dev/null

    if ! command_exists gobuster; then
        # Try Go installation
        if command_exists go; then
            print_info "Installing Gobuster via Go..."
            go install github.com/OJ/gobuster/v3@latest 2>/dev/null
        else
            # Manual download
            print_info "Downloading Gobuster binary..."
            local arch=$(uname -m)
            local gobuster_url=""

            case $arch in
                x86_64|amd64)
                    gobuster_url="https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz"
                    ;;
                aarch64|arm64)
                    gobuster_url="https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_arm64.tar.gz"
                    ;;
                *)
                    print_warning "Unknown architecture: $arch"
                    return 1
                    ;;
            esac

            mkdir -p "$INSTALL_PATH/gobuster"
            wget -q "$gobuster_url" -O /tmp/gobuster.tar.gz
            tar -xzf /tmp/gobuster.tar.gz -C "$INSTALL_PATH/gobuster"
            rm /tmp/gobuster.tar.gz

            # Create symlink
            $SUDO ln -sf "$INSTALL_PATH/gobuster/gobuster" /usr/local/bin/gobuster 2>/dev/null || true
        fi
    fi

    if command_exists gobuster || [ -f "$INSTALL_PATH/gobuster/gobuster" ]; then
        print_success "Gobuster installed successfully"
    else
        print_warning "Gobuster installation may have issues"
    fi
}

# Install Nikto
install_nikto() {
    print_section "Installing Nikto"

    if command_exists nikto; then
        print_success "Nikto is already installed"
        nikto -Version 2>/dev/null || true
        return 0
    fi

    print_info "Installing Nikto..."

    # Try package manager
    install_package "nikto" 2>/dev/null

    if ! command_exists nikto; then
        # Clone from GitHub
        print_info "Cloning Nikto from GitHub..."
        mkdir -p "$INSTALL_PATH"
        git clone --depth 1 https://github.com/sullo/nikto.git "$INSTALL_PATH/nikto" 2>/dev/null

        # Create symlink
        $SUDO ln -sf "$INSTALL_PATH/nikto/program/nikto.pl" /usr/local/bin/nikto 2>/dev/null || true

        # Install Perl dependencies
        install_package "libnet-ssleay-perl" 2>/dev/null || true
        install_package "perl-Net-SSLeay" 2>/dev/null || true
    fi

    print_success "Nikto installed"
}

# Install SQLMap
install_sqlmap() {
    print_section "Installing SQLMap"

    if command_exists sqlmap; then
        print_success "SQLMap is already installed"
        sqlmap --version 2>/dev/null || true
        return 0
    fi

    print_info "Installing SQLMap..."

    # Try package manager
    install_package "sqlmap" 2>/dev/null

    if ! command_exists sqlmap; then
        # Clone from GitHub
        print_info "Cloning SQLMap from GitHub..."
        mkdir -p "$INSTALL_PATH"
        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$INSTALL_PATH/sqlmap" 2>/dev/null

        # Create symlink
        $SUDO ln -sf "$INSTALL_PATH/sqlmap/sqlmap.py" /usr/local/bin/sqlmap 2>/dev/null || true
    fi

    print_success "SQLMap installed"
}

# Install Feroxbuster
install_feroxbuster() {
    print_section "Installing Feroxbuster"

    if command_exists feroxbuster; then
        print_success "Feroxbuster is already installed"
        feroxbuster --version 2>/dev/null || true
        return 0
    fi

    print_info "Installing Feroxbuster..."

    # Try package manager (Kali has it)
    install_package "feroxbuster" 2>/dev/null

    if ! command_exists feroxbuster; then
        # Download binary
        print_info "Downloading Feroxbuster..."
        local arch=$(uname -m)

        case $arch in
            x86_64|amd64)
                # Try deb package first
                if [[ "$DISTRO" =~ ^(ubuntu|debian|kali|linuxmint|pop)$ ]]; then
                    wget -q "https://github.com/epi052/feroxbuster/releases/download/v2.10.4/feroxbuster_amd64.deb" -O /tmp/feroxbuster.deb
                    $SUDO dpkg -i /tmp/feroxbuster.deb 2>/dev/null || true
                    rm /tmp/feroxbuster.deb
                else
                    # Download binary
                    mkdir -p "$INSTALL_PATH/feroxbuster"
                    wget -q "https://github.com/epi052/feroxbuster/releases/download/v2.10.4/x86_64-linux-feroxbuster.tar.gz" -O /tmp/feroxbuster.tar.gz
                    tar -xzf /tmp/feroxbuster.tar.gz -C "$INSTALL_PATH/feroxbuster"
                    rm /tmp/feroxbuster.tar.gz
                    $SUDO ln -sf "$INSTALL_PATH/feroxbuster/feroxbuster" /usr/local/bin/feroxbuster 2>/dev/null || true
                fi
                ;;
            aarch64|arm64)
                mkdir -p "$INSTALL_PATH/feroxbuster"
                wget -q "https://github.com/epi052/feroxbuster/releases/download/v2.10.4/aarch64-linux-feroxbuster.tar.gz" -O /tmp/feroxbuster.tar.gz
                tar -xzf /tmp/feroxbuster.tar.gz -C "$INSTALL_PATH/feroxbuster"
                rm /tmp/feroxbuster.tar.gz
                $SUDO ln -sf "$INSTALL_PATH/feroxbuster/feroxbuster" /usr/local/bin/feroxbuster 2>/dev/null || true
                ;;
        esac
    fi

    print_success "Feroxbuster installed"
}

# Install DNSRecon
install_dnsrecon() {
    print_section "Installing DNSRecon"

    if command_exists dnsrecon; then
        print_success "DNSRecon is already installed"
        return 0
    fi

    print_info "Installing DNSRecon..."

    # Try package manager
    install_package "dnsrecon" 2>/dev/null

    if ! command_exists dnsrecon; then
        # Clone from GitHub
        print_info "Cloning DNSRecon from GitHub..."
        mkdir -p "$INSTALL_PATH"
        git clone --depth 1 https://github.com/darkoperator/dnsrecon.git "$INSTALL_PATH/dnsrecon" 2>/dev/null

        # Install dependencies
        if [ -f "$INSTALL_PATH/dnsrecon/requirements.txt" ]; then
            python3 -m pip install -r "$INSTALL_PATH/dnsrecon/requirements.txt" --quiet --user 2>/dev/null || true
        fi

        # Create wrapper script
        cat > "$INSTALL_PATH/dnsrecon/dnsrecon" << 'WRAPPER'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$SCRIPT_DIR/dnsrecon.py" "$@"
WRAPPER
        chmod +x "$INSTALL_PATH/dnsrecon/dnsrecon"
        $SUDO ln -sf "$INSTALL_PATH/dnsrecon/dnsrecon" /usr/local/bin/dnsrecon 2>/dev/null || true
    fi

    print_success "DNSRecon installed"
}

# Install enum4linux
install_enum4linux() {
    print_section "Installing enum4linux"

    if command_exists enum4linux || command_exists enum4linux-ng; then
        print_success "enum4linux is already installed"
        return 0
    fi

    print_info "Installing enum4linux..."

    # Try package manager
    install_package "enum4linux" 2>/dev/null

    if ! command_exists enum4linux; then
        # Install enum4linux-ng (Python version)
        print_info "Installing enum4linux-ng..."
        mkdir -p "$INSTALL_PATH"
        git clone --depth 1 https://github.com/cddmp/enum4linux-ng.git "$INSTALL_PATH/enum4linux-ng" 2>/dev/null

        # Install dependencies
        if [ -f "$INSTALL_PATH/enum4linux-ng/requirements.txt" ]; then
            python3 -m pip install -r "$INSTALL_PATH/enum4linux-ng/requirements.txt" --quiet --user 2>/dev/null || true
        fi

        # Create symlink
        chmod +x "$INSTALL_PATH/enum4linux-ng/enum4linux-ng.py"
        $SUDO ln -sf "$INSTALL_PATH/enum4linux-ng/enum4linux-ng.py" /usr/local/bin/enum4linux 2>/dev/null || true

        # Install smbclient for full functionality
        install_package "smbclient" 2>/dev/null || true
    fi

    print_success "enum4linux installed"
}

# Install Metasploit Framework
install_metasploit() {
    print_section "Installing Metasploit Framework"

    if command_exists msfconsole; then
        print_success "Metasploit is already installed"
        return 0
    fi

    print_info "Installing Metasploit Framework..."
    print_warning "This may take several minutes..."

    # Kali and some distros have it in repos
    install_package "metasploit-framework" 2>/dev/null

    if ! command_exists msfconsole; then
        # Use the official installer script
        print_info "Using Rapid7 installer..."
        curl -s https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
        chmod 755 /tmp/msfinstall
        $SUDO /tmp/msfinstall 2>/dev/null || print_warning "Metasploit installation may require manual setup"
        rm -f /tmp/msfinstall
    fi

    if command_exists msfconsole; then
        print_success "Metasploit installed successfully"
    else
        print_warning "Metasploit may need manual installation"
        print_info "Visit: https://www.metasploit.com/download"
    fi
}

# Install TCPDump
install_tcpdump() {
    print_section "Installing TCPDump"

    if command_exists tcpdump; then
        print_success "TCPDump is already installed"
        tcpdump --version 2>&1 | head -n 1
        return 0
    fi

    print_info "Installing TCPDump..."
    install_package "tcpdump"

    if command_exists tcpdump; then
        print_success "TCPDump installed successfully"
    else
        print_error "Failed to install TCPDump"
    fi
}

# Install GitHarvester
install_githarvester() {
    print_section "Installing GitHarvester"

    if [ -d "$INSTALL_PATH/GitHarvester" ]; then
        print_success "GitHarvester is already installed at $INSTALL_PATH/GitHarvester"
        return 0
    fi

    print_info "Cloning GitHarvester..."
    mkdir -p "$INSTALL_PATH"
    git clone --depth 1 https://github.com/metac0rtex/GitHarvester.git "$INSTALL_PATH/GitHarvester" 2>/dev/null

    if [ -f "$INSTALL_PATH/GitHarvester/gitHarvester.py" ]; then
        # Create wrapper script
        cat > "$INSTALL_PATH/GitHarvester/githarvester" << 'WRAPPER'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$SCRIPT_DIR/gitHarvester.py" "$@"
WRAPPER
        chmod +x "$INSTALL_PATH/GitHarvester/githarvester"
        $SUDO ln -sf "$INSTALL_PATH/GitHarvester/githarvester" /usr/local/bin/githarvester 2>/dev/null || true
        print_success "GitHarvester installed at $INSTALL_PATH/GitHarvester"
    else
        print_error "Failed to install GitHarvester"
    fi
}

# Install AWSBucketDump
install_awsbucketdump() {
    print_section "Installing AWSBucketDump"

    if [ -d "$INSTALL_PATH/AWSBucketDump" ]; then
        print_success "AWSBucketDump is already installed at $INSTALL_PATH/AWSBucketDump"
        return 0
    fi

    print_info "Cloning AWSBucketDump..."
    mkdir -p "$INSTALL_PATH"
    git clone --depth 1 https://github.com/jordanpotti/AWSBucketDump.git "$INSTALL_PATH/AWSBucketDump" 2>/dev/null

    # Install boto3
    python3 -m pip install boto3 --quiet --user 2>/dev/null || true

    if [ -f "$INSTALL_PATH/AWSBucketDump/AWSBucketDump.py" ]; then
        # Create wrapper script
        cat > "$INSTALL_PATH/AWSBucketDump/awsbucketdump" << 'WRAPPER'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$SCRIPT_DIR/AWSBucketDump.py" "$@"
WRAPPER
        chmod +x "$INSTALL_PATH/AWSBucketDump/awsbucketdump"
        $SUDO ln -sf "$INSTALL_PATH/AWSBucketDump/awsbucketdump" /usr/local/bin/awsbucketdump 2>/dev/null || true
        print_success "AWSBucketDump installed at $INSTALL_PATH/AWSBucketDump"
    else
        print_error "Failed to install AWSBucketDump"
    fi
}

# Install Wordlists
install_wordlists() {
    print_section "Installing Wordlists"

    mkdir -p "$WORDLIST_PATH"

    # Check if SecLists is available
    if [ -d "/usr/share/seclists" ]; then
        print_success "SecLists found at /usr/share/seclists"
        ln -sf /usr/share/seclists "$WORDLIST_PATH/seclists" 2>/dev/null || true
        return 0
    fi

    if [ -d "/usr/share/wordlists" ]; then
        print_success "Wordlists found at /usr/share/wordlists"
        ln -sf /usr/share/wordlists "$WORDLIST_PATH/system-wordlists" 2>/dev/null || true
    fi

    # Download common wordlists
    print_info "Downloading common wordlists..."

    local wordlists=(
        "common.txt|https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
        "directory-list-2.3-medium.txt|https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt"
        "subdomains-top1million-5000.txt|https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
        "big.txt|https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt"
    )

    for item in "${wordlists[@]}"; do
        IFS='|' read -r filename url <<< "$item"
        if [ ! -f "$WORDLIST_PATH/$filename" ]; then
            print_info "Downloading $filename..."
            wget -q "$url" -O "$WORDLIST_PATH/$filename" 2>/dev/null || print_warning "Failed to download $filename"
        else
            print_success "$filename already exists"
        fi
    done

    print_success "Wordlists installed at $WORDLIST_PATH"
}

# Create configuration directory
setup_config() {
    print_section "Setting Up Configuration"

    mkdir -p "$CONFIG_PATH"

    # Create default config if it doesn't exist
    if [ ! -f "$CONFIG_PATH/config.json" ]; then
        cat > "$CONFIG_PATH/config.json" << EOF
{
    "wordlist_path": "$WORDLIST_PATH",
    "tools_path": "$INSTALL_PATH",
    "output_path": "$HOME/recon_output",
    "shodan_api_key": "",
    "theme": "monokai"
}
EOF
        print_success "Created default configuration at $CONFIG_PATH/config.json"
    else
        print_success "Configuration already exists"
    fi

    # Create output directory
    mkdir -p "$HOME/recon_output"
}

# Add to PATH
setup_path() {
    print_section "Configuring PATH"

    local paths_to_add=(
        "$INSTALL_PATH"
        "$HOME/.local/bin"
    )

    local shell_rc=""
    if [ -f "$HOME/.zshrc" ]; then
        shell_rc="$HOME/.zshrc"
    elif [ -f "$HOME/.bashrc" ]; then
        shell_rc="$HOME/.bashrc"
    fi

    if [ -n "$shell_rc" ]; then
        for path_to_add in "${paths_to_add[@]}"; do
            if ! grep -q "$path_to_add" "$shell_rc" 2>/dev/null; then
                echo "export PATH=\"\$PATH:$path_to_add\"" >> "$shell_rc"
                print_info "Added $path_to_add to PATH in $shell_rc"
            fi
        done
        print_success "PATH configured. Run 'source $shell_rc' or restart terminal."
    fi
}

# Print post-installation info
print_post_install() {
    print_section "Installation Complete!"

    echo -e "${GREEN}"
    cat << EOF

╔══════════════════════════════════════════════════════════════════╗
║                     INSTALLATION SUMMARY                          ║
╚══════════════════════════════════════════════════════════════════╝

Tool Installation Path: $INSTALL_PATH
Wordlists Path: $WORDLIST_PATH
Configuration Path: $CONFIG_PATH

INSTALLED TOOLS:
  ✓ Python 3 + pip packages (shodan, pillow, requests)
  ✓ Nmap - Network scanner
  ✓ SQLMap - SQL injection testing
  ✓ Gobuster - Directory brute-forcing
  ✓ Feroxbuster - Content discovery
  ✓ Nikto - Web vulnerability scanner
  ✓ DNSRecon - DNS enumeration
  ✓ enum4linux - Windows/SMB enumeration
  ✓ TCPDump - Packet capture
  ✓ Metasploit Framework - Penetration testing
  ✓ GitHarvester - GitHub OSINT
  ✓ AWSBucketDump - S3 bucket enumeration
  ✓ Wordlists - Common security wordlists

NEXT STEPS:
  1. Restart your terminal or run: source ~/.bashrc (or ~/.zshrc)
  2. Configure Shodan API key in the app (Settings tab)
  3. Launch Recon-Superpowers:
     python3 recon_superpower.py

SHODAN API KEY:
  Get your free API key from: https://account.shodan.io/
  Configure it in Settings tab after launching the app.

For issues, visit: https://github.com/aingram702/Recon-Superpowers

EOF
    echo -e "${NC}"
}

# Verify installations
verify_installations() {
    print_section "Verifying Installations"

    local tools=(
        "python3"
        "git"
        "nmap"
        "sqlmap"
        "nikto"
        "gobuster"
        "feroxbuster"
        "dnsrecon"
        "enum4linux"
        "tcpdump"
    )

    local installed=0
    local total=${#tools[@]}

    for tool in "${tools[@]}"; do
        if command_exists "$tool"; then
            print_success "$tool"
            ((installed++))
        else
            print_warning "$tool not found in PATH (may still be installed locally)"
        fi
    done

    echo ""
    print_info "Verified $installed/$total tools in PATH"

    # Check optional tools
    if command_exists msfconsole; then
        print_success "Metasploit Framework"
    else
        print_warning "Metasploit not in PATH (optional)"
    fi
}

# Main function
main() {
    print_banner

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-apt)
                SKIP_APT=true
                shift
                ;;
            --skip-tools)
                SKIP_TOOLS=true
                shift
                ;;
            --skip-git-repos)
                SKIP_GIT_REPOS=true
                shift
                ;;
            --skip-wordlists)
                SKIP_WORDLISTS=true
                shift
                ;;
            --install-path)
                INSTALL_PATH="$2"
                shift 2
                ;;
            --verbose|-v)
                VERBOSE=true
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --skip-apt         Skip package manager updates"
                echo "  --skip-tools       Skip tool installations"
                echo "  --skip-git-repos   Skip GitHub repository clones"
                echo "  --skip-wordlists   Skip wordlist downloads"
                echo "  --install-path     Set custom install path (default: ~/ReconTools)"
                echo "  --verbose, -v      Enable verbose output"
                echo "  --help, -h         Show this help message"
                exit 0
                ;;
            *)
                print_warning "Unknown option: $1"
                shift
                ;;
        esac
    done

    check_root
    detect_distro

    echo ""
    print_info "This script will install:"
    echo "  • Python 3 + essential packages"
    echo "  • Nmap, Gobuster, Feroxbuster, Nikto"
    echo "  • SQLMap, DNSRecon, enum4linux"
    echo "  • TCPDump, Metasploit Framework"
    echo "  • GitHarvester, AWSBucketDump"
    echo "  • Security wordlists"
    echo ""
    print_info "Install path: $INSTALL_PATH"
    echo ""

    read -p "Continue with installation? (Y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        print_warning "Installation cancelled."
        exit 0
    fi

    # Create install directory
    mkdir -p "$INSTALL_PATH"

    # Run installation steps
    if [ "$SKIP_APT" = false ]; then
        update_packages
    fi

    install_essentials
    install_python_packages

    if [ "$SKIP_TOOLS" = false ]; then
        install_nmap
        install_sqlmap
        install_gobuster
        install_feroxbuster
        install_nikto
        install_dnsrecon
        install_enum4linux
        install_tcpdump
        install_metasploit
    fi

    if [ "$SKIP_GIT_REPOS" = false ]; then
        install_githarvester
        install_awsbucketdump
    fi

    if [ "$SKIP_WORDLISTS" = false ]; then
        install_wordlists
    fi

    setup_config
    setup_path
    verify_installations
    print_post_install
}

# Run main function
main "$@"
