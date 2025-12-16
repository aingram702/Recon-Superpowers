"""
Default configuration values for Recon Superpower.
All hardcoded values should be defined here for centralized management.
"""

from typing import Dict, Any, Set, Tuple

# =============================================================================
# SECURITY DEFAULTS
# =============================================================================

# Process timeout in seconds (1 hour)
DEFAULT_PROCESS_TIMEOUT: int = 3600

# Maximum workflow timeout in seconds (2 hours)
DEFAULT_WORKFLOW_TIMEOUT: int = 7200

# Maximum step timeout in seconds (30 minutes)
DEFAULT_STEP_TIMEOUT: int = 1800

# Maximum output lines before truncation
DEFAULT_MAX_OUTPUT_LINES: int = 10000

# Maximum wordlist file size in bytes (100MB)
MAX_WORDLIST_SIZE: int = 100 * 1024 * 1024

# Maximum extra options length
MAX_EXTRA_OPTIONS_LENGTH: int = 500

# Maximum target length (per RFC hostname limit)
MAX_TARGET_LENGTH: int = 253

# Maximum URL length
MAX_URL_LENGTH: int = 2048

# Maximum thread count for tools
MAX_THREAD_COUNT: int = 1000

# Maximum packet count for tcpdump
MAX_PACKET_COUNT: int = 10000

# Maximum BPF filter length
MAX_BPF_FILTER_LENGTH: int = 100

# =============================================================================
# NETWORK DEFAULTS
# =============================================================================

DEFAULT_PORT: int = 4444
DEFAULT_LHOST: str = ""
DEFAULT_NMAP_PORTS: str = "1-1000"
DEFAULT_TIMING: str = "T4"

# =============================================================================
# HISTORY LIMITS
# =============================================================================

MAX_RECENT_TARGETS: int = 20
MAX_RECENT_URLS: int = 20
MAX_COMMAND_HISTORY: int = 50

# =============================================================================
# UI DEFAULTS
# =============================================================================

DEFAULT_WINDOW_WIDTH: int = 1400
DEFAULT_WINDOW_HEIGHT: int = 900
DEFAULT_FONT_FAMILY: str = "Courier"
DEFAULT_MONO_FONT: str = "Consolas"
DEFAULT_FONT_SIZE: int = 10

# =============================================================================
# THEME COLORS (Monokai Terminal Theme)
# =============================================================================

THEME_COLORS: Dict[str, str] = {
    "bg_primary": "#272822",      # Main background (dark greenish-gray)
    "bg_secondary": "#3E3D32",    # Panel background (lighter)
    "bg_tertiary": "#49483E",     # Sidebar/accent background
    "accent_green": "#A6E22E",    # Monokai green (strings/success)
    "accent_cyan": "#66D9EF",     # Monokai cyan (functions/info)
    "accent_red": "#F92672",      # Monokai pink/red (keywords/errors)
    "accent_orange": "#FD971F",   # Monokai orange (numbers/warnings)
    "accent_yellow": "#E6DB74",   # Monokai yellow (classes/highlights)
    "accent_purple": "#AE81FF",   # Monokai purple (constants)
    "text_color": "#F8F8F2",      # Monokai foreground (off-white)
    "text_muted": "#75715E",      # Monokai comments (muted text)
    "border_color": "#A6E22E",    # Green border
    "output_bg": "#1E1E1E",       # Output text area background
}

# =============================================================================
# VALIDATION PATTERNS
# =============================================================================

# Characters not allowed in targets/hostnames
DANGEROUS_CHARS: Tuple[str, ...] = (';', '|', '&', '$', '`', '\n', '\r', '$(', '${', '&&', '||')

# Dangerous regex patterns for extra options
DANGEROUS_PATTERNS: Tuple[str, ...] = (
    r'.*[;&|`$\n\r].*',   # Shell metacharacters
    r'.*\$\(.*\).*',      # Command substitution
    r'.*`.*`.*',          # Backtick substitution
    r'.*\{.*\}.*',        # Brace expansion
    r'.*>.*',             # Redirects
    r'.*<.*',             # Redirects
)

# Allowed BPF keywords for tcpdump
ALLOWED_BPF_KEYWORDS: Tuple[str, ...] = (
    'port', 'host', 'net', 'src', 'dst', 'tcp', 'udp', 'icmp',
    'ip', 'ip6', 'arp', 'rarp', 'and', 'or', 'not'
)

# =============================================================================
# SCAN PROFILES
# =============================================================================

# Note: Each profile value is a tuple with tool-specific settings
# Using tuples instead of sets to preserve ordering
SCAN_PROFILES: Dict[str, Dict[str, Any]] = {
    "nmap": {
        # (scan_type, timing, ports, extra_options)
        "Quick Scan": ("-sS", "T4", "1-1000", ""),
        "Deep Scan": ("-sS -sV -sC", "T3", "1-65535", "-A"),
        "Stealth Scan": ("-sS", "T1", "1-1000", "-f"),
        "UDP Scan": ("-sU", "T3", "53,161,500", "")
    },
    "gobuster": {
        # (mode, threads, extensions, extra_options)
        "Quick Dir": ("dir", "10", "php,html,txt", "-k"),
        "Deep Dir": ("dir", "50", "php,html,txt,asp,aspx,jsp,js,json,xml", "-k"),
        "DNS Enum": ("dns", "20", "", ""),
        "VHost Scan": ("vhost", "10", "", "-k")
    },
    "nikto": {
        # (port, ssl, tuning, extra_options)
        "Quick": ("80", False, "x", ""),
        "SSL Scan": ("443", True, "x", ""),
        "Targeted": ("80", False, "4,6,9", "")
    },
    "sqlmap": {
        # (base_options, level_risk, threads)
        "Basic": ("--batch", "--smart", "1"),
        "Full Scan": ("--batch --forms --crawl=3", "--level=5 --risk=3", "5"),
        "Quick Test": ("--batch", "--level=1 --risk=1", "1"),
        "Database Enum": ("--batch --dbs", "--level=3 --risk=2", "3"),
        "Table Dump": ("--batch --tables", "--level=3 --risk=2", "3")
    },
    "metasploit": {
        # (module, target_option, extra_options)
        "Port Scanner": ("auxiliary/scanner/portscan/tcp", "RHOSTS", "PORTS=1-1000"),
        "SMB Version": ("auxiliary/scanner/smb/smb_version", "RHOSTS", ""),
        "SSH Version": ("auxiliary/scanner/ssh/ssh_version", "RHOSTS", ""),
        "HTTP Version": ("auxiliary/scanner/http/http_version", "RHOSTS", ""),
        "FTP Version": ("auxiliary/scanner/ftp/ftp_version", "RHOSTS", ""),
        "SNMP Enum": ("auxiliary/scanner/snmp/snmp_enum", "RHOSTS", "")
    }
}

# =============================================================================
# FILE PATHS
# =============================================================================

CONFIG_DIR_NAME: str = ".recon_superpower"
CONFIG_FILE_NAME: str = "config.json"
HISTORY_FILE_NAME: str = "history.json"
LOG_FILE_NAME: str = "recon_superpower.log"

# =============================================================================
# LOGGING DEFAULTS
# =============================================================================

LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"
LOG_MAX_BYTES: int = 5 * 1024 * 1024  # 5MB
LOG_BACKUP_COUNT: int = 3
