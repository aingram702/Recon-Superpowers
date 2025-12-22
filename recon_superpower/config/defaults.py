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
# THEME DEFINITIONS
# =============================================================================

# Available themes with their color palettes
AVAILABLE_THEMES: Dict[str, Dict[str, str]] = {
    "Monokai": {
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
    },
    "One Dark": {
        "bg_primary": "#282C34",      # Main background
        "bg_secondary": "#21252B",    # Panel background
        "bg_tertiary": "#2C313A",     # Sidebar/accent background
        "accent_green": "#98C379",    # Green (strings/success)
        "accent_cyan": "#56B6C2",     # Cyan (functions/info)
        "accent_red": "#E06C75",      # Red (keywords/errors)
        "accent_orange": "#D19A66",   # Orange (numbers/warnings)
        "accent_yellow": "#E5C07B",   # Yellow (classes/highlights)
        "accent_purple": "#C678DD",   # Purple (constants)
        "text_color": "#ABB2BF",      # Foreground
        "text_muted": "#5C6370",      # Comments (muted text)
        "border_color": "#61AFEF",    # Blue border
        "output_bg": "#1E2127",       # Output text area background
    },
    "Nord": {
        "bg_primary": "#2E3440",      # Polar Night
        "bg_secondary": "#3B4252",    # Polar Night lighter
        "bg_tertiary": "#434C5E",     # Polar Night lightest
        "accent_green": "#A3BE8C",    # Aurora Green
        "accent_cyan": "#88C0D0",     # Frost
        "accent_red": "#BF616A",      # Aurora Red
        "accent_orange": "#D08770",   # Aurora Orange
        "accent_yellow": "#EBCB8B",   # Aurora Yellow
        "accent_purple": "#B48EAD",   # Aurora Purple
        "text_color": "#ECEFF4",      # Snow Storm
        "text_muted": "#4C566A",      # Polar Night comment
        "border_color": "#81A1C1",    # Frost border
        "output_bg": "#242933",       # Darker background
    },
    "Dracula": {
        "bg_primary": "#282A36",      # Background
        "bg_secondary": "#44475A",    # Current Line
        "bg_tertiary": "#343746",     # Selection
        "accent_green": "#50FA7B",    # Green
        "accent_cyan": "#8BE9FD",     # Cyan
        "accent_red": "#FF5555",      # Red
        "accent_orange": "#FFB86C",   # Orange
        "accent_yellow": "#F1FA8C",   # Yellow
        "accent_purple": "#BD93F9",   # Purple
        "text_color": "#F8F8F2",      # Foreground
        "text_muted": "#6272A4",      # Comment
        "border_color": "#FF79C6",    # Pink border
        "output_bg": "#21222C",       # Darker background
    },
    "Darcula": {
        "bg_primary": "#2B2B2B",      # Main background (IntelliJ)
        "bg_secondary": "#3C3F41",    # Panel background
        "bg_tertiary": "#313335",     # Sidebar background
        "accent_green": "#6A8759",    # String green
        "accent_cyan": "#6897BB",     # Number/constant
        "accent_red": "#CC7832",      # Keyword orange-red
        "accent_orange": "#FFC66D",   # Function yellow
        "accent_yellow": "#A9B7C6",   # Variable
        "accent_purple": "#9876AA",   # Metadata/annotation
        "text_color": "#A9B7C6",      # Default text
        "text_muted": "#808080",      # Comment gray
        "border_color": "#629755",    # Doc comment green
        "output_bg": "#1E1E1E",       # Console background
    },
    "Material": {
        "bg_primary": "#263238",      # Blue Grey 900
        "bg_secondary": "#37474F",    # Blue Grey 800
        "bg_tertiary": "#455A64",     # Blue Grey 700
        "accent_green": "#C3E88D",    # Light Green
        "accent_cyan": "#89DDFF",     # Cyan
        "accent_red": "#F07178",      # Red
        "accent_orange": "#F78C6C",   # Orange
        "accent_yellow": "#FFCB6B",   # Yellow
        "accent_purple": "#C792EA",   # Purple
        "text_color": "#EEFFFF",      # White
        "text_muted": "#546E7A",      # Blue Grey 600
        "border_color": "#82AAFF",    # Blue
        "output_bg": "#1A2327",       # Darker background
    },
    "Solarized Dark": {
        "bg_primary": "#002B36",      # Base03
        "bg_secondary": "#073642",    # Base02
        "bg_tertiary": "#094959",     # Slightly lighter
        "accent_green": "#859900",    # Green
        "accent_cyan": "#2AA198",     # Cyan
        "accent_red": "#DC322F",      # Red
        "accent_orange": "#CB4B16",   # Orange
        "accent_yellow": "#B58900",   # Yellow
        "accent_purple": "#6C71C4",   # Violet
        "text_color": "#839496",      # Base0
        "text_muted": "#586E75",      # Base01
        "border_color": "#268BD2",    # Blue border
        "output_bg": "#001F27",       # Darker background
    },
    "Gruvbox Dark": {
        "bg_primary": "#282828",      # Dark0
        "bg_secondary": "#3C3836",    # Dark1
        "bg_tertiary": "#504945",     # Dark2
        "accent_green": "#B8BB26",    # Bright Green
        "accent_cyan": "#8EC07C",     # Aqua
        "accent_red": "#FB4934",      # Bright Red
        "accent_orange": "#FE8019",   # Bright Orange
        "accent_yellow": "#FABD2F",   # Bright Yellow
        "accent_purple": "#D3869B",   # Bright Purple
        "text_color": "#EBDBB2",      # Light0
        "text_muted": "#928374",      # Gray
        "border_color": "#83A598",    # Bright Blue
        "output_bg": "#1D2021",       # Dark0_hard
    },
    "Obsidian": {
        "bg_primary": "#1E1E1E",      # Dark background
        "bg_secondary": "#2D2D30",    # Panel background
        "bg_tertiary": "#3E3E42",     # Accent background
        "accent_green": "#6A9955",    # Comment green
        "accent_cyan": "#4EC9B0",     # Type cyan
        "accent_red": "#F44747",      # Error red
        "accent_orange": "#CE9178",   # String orange
        "accent_yellow": "#DCDCAA",   # Function yellow
        "accent_purple": "#C586C0",   # Keyword purple
        "text_color": "#D4D4D4",      # Default text
        "text_muted": "#6A6A6A",      # Comment gray
        "border_color": "#569CD6",    # Keyword blue
        "output_bg": "#1A1A1A",       # Darker background
    },
}

# Default theme name
DEFAULT_THEME: str = "Monokai"

# Current theme colors (defaults to Monokai for backward compatibility)
THEME_COLORS: Dict[str, str] = AVAILABLE_THEMES[DEFAULT_THEME].copy()

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
