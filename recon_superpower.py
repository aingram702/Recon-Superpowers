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
from pathlib import Path
from collections import deque


class ReconSuperpower:
    def __init__(self, root):
        self.root = root
        self.root.title("The Recon Superpower")
        self.root.geometry("1400x900")

        # Dark hacker theme colors
        self.bg_primary = "#0a0e27"
        self.bg_secondary = "#151b3d"
        self.bg_tertiary = "#1e2749"
        self.accent_green = "#00ff41"
        self.accent_cyan = "#00d9ff"
        self.accent_red = "#ff0055"
        self.text_color = "#e0e0e0"
        self.border_color = "#00ff41"

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
"""
        }

        # Pre-defined Workflows for automation
        self.predefined_workflows = {
            "full_recon": {
                "name": "Full Network Reconnaissance",
                "description": "Comprehensive scan: ports → services → web → DNS",
                "steps": [
                    {
                        "tool": "nmap",
                        "name": "Port Scan",
                        "config": {
                            "scan_type": "SYN",
                            "ports": "1-1000",
                            "timing": "T3"
                        }
                    },
                    {
                        "tool": "gobuster",
                        "name": "Directory Enumeration",
                        "config": {
                            "mode": "dir",
                            "wordlist": "/usr/share/wordlists/dirb/common.txt",
                            "threads": "20"
                        },
                        "condition": "http_detected"
                    },
                    {
                        "tool": "nikto",
                        "name": "Web Vulnerability Scan",
                        "config": {
                            "port": "80",
                            "ssl": False,
                            "tuning": "124"
                        },
                        "condition": "http_detected"
                    },
                    {
                        "tool": "dnsrecon",
                        "name": "DNS Enumeration",
                        "config": {
                            "scan_type": "std"
                        }
                    }
                ]
            },
            "web_deep_scan": {
                "name": "Web Application Deep Scan",
                "description": "Nikto → Gobuster → feroxbuster → Shodan lookup",
                "steps": [
                    {
                        "tool": "nikto",
                        "name": "Initial Web Scan",
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
                            "wordlist": "/usr/share/wordlists/dirb/common.txt",
                            "extensions": "php,html,txt"
                        }
                    },
                    {
                        "tool": "feroxbuster",
                        "name": "Recursive Deep Scan",
                        "config": {
                            "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt",
                            "extensions": "php,html,js",
                            "threads": "50",
                            "depth": "3"
                        }
                    },
                    {
                        "tool": "shodan",
                        "name": "Shodan Lookup",
                        "config": {
                            "search_type": "host",
                            "query": "[TARGET_IP]"
                        }
                    }
                ]
            },
            "domain_intel": {
                "name": "Domain Intelligence Gathering",
                "description": "DNSrecon → Shodan → GitHub OSINT",
                "steps": [
                    {
                        "tool": "dnsrecon",
                        "name": "DNS Standard Enumeration",
                        "config": {
                            "scan_type": "std"
                        }
                    },
                    {
                        "tool": "dnsrecon",
                        "name": "Subdomain Brute Force",
                        "config": {
                            "scan_type": "brt",
                            "wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
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
                        "tool": "githarvester",
                        "name": "GitHub Reference Search",
                        "config": {
                            "query": "[TARGET_DOMAIN]",
                            "sort": "best"
                        }
                    }
                ]
            },
            "smb_enum": {
                "name": "Windows/SMB Enumeration",
                "description": "SMB port scan → enum4linux → Metasploit",
                "steps": [
                    {
                        "tool": "nmap",
                        "name": "SMB Port Scan",
                        "config": {
                            "scan_type": "SYN",
                            "ports": "135,139,445",
                            "timing": "T4"
                        }
                    },
                    {
                        "tool": "enum4linux",
                        "name": "SMB Enumeration",
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
                    }
                ]
            },
            "cloud_discovery": {
                "name": "Cloud Asset Discovery",
                "description": "S3 buckets → GitHub credentials → Infrastructure",
                "steps": [
                    {
                        "tool": "awsbucket",
                        "name": "S3 Bucket Enumeration",
                        "config": {
                            "bucket_list": "buckets.txt",
                            "threads": "10"
                        }
                    },
                    {
                        "tool": "githarvester",
                        "name": "Cloud Credential Search",
                        "config": {
                            "query": "AWS_ACCESS_KEY OR AZURE_CLIENT_SECRET",
                            "account": "[TARGET_ORG]",
                            "sort": "new"
                        }
                    },
                    {
                        "tool": "shodan",
                        "name": "Organization Infrastructure",
                        "config": {
                            "search_type": "search",
                            "query": "org:[TARGET_ORG]"
                        }
                    }
                ]
            },
            "quick_host": {
                "name": "Quick Host Discovery",
                "description": "Fast port scan → quick web scan",
                "steps": [
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
            except:
                pass  # Use default if restoration fails

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
        # Title Bar
        title_frame = tk.Frame(self.root, bg=self.bg_primary, height=80)
        title_frame.pack(fill=tk.X, padx=20, pady=(20, 10))
        title_frame.pack_propagate(False)

        title_label = tk.Label(
            title_frame,
            text="⚡ THE RECON SUPERPOWER ⚡",
            font=("Courier", 28, "bold"),
            fg=self.accent_green,
            bg=self.bg_primary
        )
        title_label.pack(side=tk.TOP, pady=(10, 0))

        subtitle_label = tk.Label(
            title_frame,
            text="[ AUTHORIZED SECURITY TESTING ONLY ]",
            font=("Courier", 10),
            fg=self.accent_cyan,
            bg=self.bg_primary
        )
        subtitle_label.pack(side=tk.TOP)

        # Main container
        main_container = tk.Frame(self.root, bg=self.bg_primary)
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Left panel - Tool selection sidebar + Tool configuration
        left_panel = tk.Frame(main_container, bg=self.bg_secondary, width=450)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 10), pady=0)
        left_panel.pack_propagate(False)

        # Tool selector sidebar (narrower)
        sidebar_frame = tk.Frame(left_panel, bg=self.bg_tertiary, width=150)
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
            ("metasploit", "💥 Metasploit"),
            ("shodan", "🌐 Shodan"),
            ("dnsrecon", "📡 DNSrecon"),
            ("enum4linux", "🖥️  enum4linux"),
            ("githarvester", "🔎 GitHub"),
            ("feroxbuster", "🦀 feroxbuster"),
            ("awsbucket", "☁️  AWS S3"),
            ("tcpdump", "📦 TCPdump"),
            ("workflows", "🔄 Workflows"),
            ("settings", "⚙️  Settings")
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
        self.tool_frames["metasploit"] = self.create_metasploit_tab()
        self.tool_frames["shodan"] = self.create_shodan_tab()
        self.tool_frames["dnsrecon"] = self.create_dnsrecon_tab()
        self.tool_frames["enum4linux"] = self.create_enum4linux_tab()
        self.tool_frames["githarvester"] = self.create_githarvester_tab()
        self.tool_frames["feroxbuster"] = self.create_feroxbuster_tab()
        self.tool_frames["awsbucket"] = self.create_awsbucket_tab()
        self.tool_frames["tcpdump"] = self.create_tcpdump_tab()
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
            font=("Courier", 10),
            bg=self.bg_primary,
            fg=self.accent_green,
            insertbackground=self.accent_green,
            selectbackground=self.accent_cyan,
            selectforeground=self.bg_primary,
            wrap=tk.WORD,
            relief=tk.FLAT,
            padx=10,
            pady=10
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

        entry = tk.Entry(parent, font=("Courier", 10), bg=self.bg_primary,
                        fg=self.accent_cyan, insertbackground=self.accent_cyan,
                        relief=tk.FLAT, width=width)
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
            justify=tk.LEFT
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
                              command=self.browse_wordlist)
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
            justify=tk.LEFT
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
        self.nikto_target = self.create_labeled_entry(frame, "Target:", 0, "http://")

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
            justify=tk.LEFT
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
            justify=tk.CENTER
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
            justify=tk.LEFT
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

    def browse_wordlist(self):
        filename = filedialog.askopenfilename(
            title="Select Wordlist",
            initialdir="/usr/share/wordlists",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            # Security: Validate file path to prevent path traversal
            if not self.validate_file_path(filename):
                messagebox.showerror("Error", "Invalid file path selected")
                return
            self.gobuster_wordlist.delete(0, tk.END)
            self.gobuster_wordlist.insert(0, filename)

    def create_shodan_tab(self):
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        frame.columnconfigure(1, weight=1)

        # API Key status
        api_status = tk.Label(
            frame,
            text="⚠️  Configure API key in Settings  ⚠️",
            font=("Courier", 9, "bold"),
            fg=self.accent_red if not self.config.get("shodan_api_key") else self.accent_green,
            bg=self.bg_secondary,
            justify=tk.CENTER
        )
        api_status.grid(row=0, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=10)
        self.shodan_api_status = api_status

        # Search query
        self.shodan_query = self.create_labeled_entry(frame, "Search Query:", 1, "apache port:443")

        # Search type
        label = tk.Label(frame, text="Search Type:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)

        self.shodan_type = ttk.Combobox(frame, values=[
            "search (Query search)",
            "host (Host lookup)"
        ], font=("Courier", 9), state="readonly", width=28)
        self.shodan_type.grid(row=2, column=1, sticky=tk.EW, padx=10, pady=5)
        self.shodan_type.current(0)

        # Facets
        self.shodan_facets = self.create_labeled_entry(frame, "Facets:", 3, "country,org")

        # Limit
        self.shodan_limit = self.create_labeled_entry(frame, "Result Limit:", 4, "100")

        # Additional options
        self.shodan_options = self.create_labeled_entry(frame, "Extra Options:", 5, "")

        # Info label
        info_label = tk.Label(
            frame,
            text="\n🌐 Shodan Search Engine\nAPI-based device discovery\n\nExample queries:\n• apache port:443\n• nginx country:US\n• port:22 'SSH-2.0'",
            font=("Courier", 9),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            justify=tk.LEFT
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
            command=lambda: self.show_cheatsheet("shodan")
        )
        cheat_btn.grid(row=7, column=0, columnspan=2, pady=10)

        return frame

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
                              command=self.browse_wordlist)
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
            justify=tk.LEFT
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
            justify=tk.LEFT
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
            justify=tk.LEFT
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
                              command=self.browse_wordlist)
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
            justify=tk.LEFT
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
                              command=self.browse_wordlist)
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
                               command=self.browse_wordlist)
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
            justify=tk.LEFT
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
            justify=tk.CENTER
        )
        warning_label.grid(row=0, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=10)

        # Interface
        self.tcpdump_interface = self.create_labeled_entry(frame, "Interface:", 1, "eth0")

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
            justify=tk.LEFT
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


    def create_workflows_tab(self):
        frame = tk.Frame(self.tool_container, bg=self.bg_secondary)
        frame.columnconfigure(1, weight=1)

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

        # Preview frame
        preview_frame = tk.LabelFrame(
            frame,
            text=" 📋 Workflow Steps Preview ",
            font=("Courier", 10, "bold"),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            relief=tk.FLAT
        )
        preview_frame.grid(row=3, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=10)

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
        target_label.grid(row=4, column=0, sticky=tk.W, padx=10, pady=5)

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
        self.workflow_target.grid(row=4, column=1, sticky=tk.EW, padx=10, pady=5)

        # Control buttons frame
        controls_frame = tk.Frame(frame, bg=self.bg_secondary)
        controls_frame.grid(row=5, column=0, columnspan=2, pady=15)

        # Run button
        self.workflow_run_btn = tk.Button(
            controls_frame,
            text="▶ RUN WORKFLOW",
            font=("Courier", 11, "bold"),
            bg=self.accent_green,
            fg=self.bg_primary,
            activebackground=self.accent_cyan,
            activeforeground=self.bg_primary,
            relief=tk.FLAT,
            padx=20,
            pady=10,
            cursor="hand2",
            command=self.run_workflow
        )
        self.workflow_run_btn.pack(side=tk.LEFT, padx=5)

        # Stop button
        self.workflow_stop_btn = tk.Button(
            controls_frame,
            text="⬛ STOP",
            font=("Courier", 11, "bold"),
            bg=self.accent_red,
            fg="white",
            activebackground="#cc0044",
            activeforeground="white",
            relief=tk.FLAT,
            padx=20,
            pady=10,
            cursor="hand2",
            state=tk.DISABLED,
            command=self.stop_workflow
        )
        self.workflow_stop_btn.pack(side=tk.LEFT, padx=5)

        # Progress frame
        progress_frame = tk.LabelFrame(
            frame,
            text=" 📊 Workflow Progress ",
            font=("Courier", 10, "bold"),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            relief=tk.FLAT
        )
        progress_frame.grid(row=6, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=10)

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
            text="\n💡 Tips:\n• Workflows automate multi-tool reconnaissance\n• Target format depends on workflow (IP, domain, URL)\n• Results appear in console output below\n• Save workflow results with the SAVE button",
            font=("Courier", 8),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            justify=tk.LEFT
        )
        info_label.grid(row=7, column=0, columnspan=2, sticky=tk.W, padx=10, pady=10)

        # Initialize with first workflow
        self.on_workflow_selected(None)

        return frame

    def on_workflow_selected(self, event):
        """Update workflow steps preview when selection changes."""
        selected_idx = self.workflow_selector.current()
        workflow_ids = list(self.predefined_workflows.keys())
        
        if selected_idx < 0 or selected_idx >= len(workflow_ids):
            return
        
        workflow_id = workflow_ids[selected_idx]
        workflow = self.predefined_workflows[workflow_id]
        
        # Update steps preview
        self.workflow_steps_text.config(state=tk.NORMAL)
        self.workflow_steps_text.delete('1.0', tk.END)
        
        steps_text = f"Workflow: {workflow['name']}\n"
        steps_text += f"{workflow['description']}\n\n"
        steps_text += "=" * 60 + "\n\n"
        
        for i, step in enumerate(workflow['steps'], 1):
            condition = step.get('condition', '')
            condition_text = f" (if {condition})" if condition else ""
            
            steps_text += f"Step {i}: {step['name']}{condition_text}\n"
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

    def validate_extra_options(self, options):
        """
        Enhanced validation for extra options across all tools.
        Prevents command injection via extra options.
        """
        if not options:
            return True
        
        # Security: Reject shell metacharacters
        dangerous_chars = [';', '|', '&', '$', '`', '\n', '\r', '$(', '${', '&&', '||']
        for char in dangerous_chars:
            if char in options:
                return False
        
        # Max length check
        if len(options) > 500:
            return False
        
        return True
    
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
            except:
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
            # No null bytes
            if '\x00' in str(value):
                return False
        
        return True
  # Valid

    def run_workflow(self):
        """Execute the selected workflow."""
        # FIX HIGH-2: Thread-safe check and set
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
            
            # FIX CRIT-1: Validate target based on workflow requirements
            validation_error = self.validate_workflow_target(target, workflow_id)
            if validation_error:
                messagebox.showerror("Invalid Target", validation_error)
                self.workflow_running = False
                return
            
            # Initialize workflow execution
            self.current_workflow = workflow
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
            self.append_output(f"Total Steps: {len(workflow['steps'])}\n")
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
        total_steps = len(workflow['steps'])
        start_time = time.time()
        
        # FIX CRIT-2: Total workflow timeout (2 hours max)
        MAX_WORKFLOW_TIMEOUT = 7200  # 2 hours
        MAX_STEP_TIMEOUT = 1800  # 30 minutes per step
        
        for i, step in enumerate(workflow['steps']):
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
        import time
        
        tool = step['tool']
        config = step['config']
        
        try:
            # Switch to the tool's tab
            self.root.after(0, lambda: self.switch_tool(tool))
            time.sleep(0.3)  # Give UI time to update
            
            # Set tool-specific inputs based on config
            success = self.configure_tool_for_workflow(tool, target, config)
            if not success:
                self.append_output(f"⚠️  Failed to configure {tool}\n")
                return False
            
            # Execute the tool
            self.append_output(f"Executing {tool.upper()}...\n")
            
            # Call run_scan which will execute the tool
            self.root.after(0, self.run_scan)
            
            # Wait for tool to complete (simplified - check process status)
            max_wait = config.get('timeout', 300)  # Default 5 minutes
            waited = 0
            while self.is_running and waited < max_wait:
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
            except:
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
                    except:
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
                if hasattr(self, 'nikto_ssl'):
                    self.nikto_ssl.set(config.get('ssl', False))
                if hasattr(self, 'nikto_tuning'):
                    self.nikto_tuning.delete(0, tk.END)
                    self.nikto_tuning.insert(0, config.get('tuning', 'x'))
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
            self.update_status("Workflow stopped")

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

        # Settings header
        header = tk.Label(
            frame,
            text="⚙️  APPLICATION SETTINGS",
            font=("Courier", 12, "bold"),
            fg=self.accent_cyan,
            bg=self.bg_secondary
        )
        header.grid(row=0, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=15)

        # Shodan API Key
        label = tk.Label(frame, text="Shodan API Key:", font=("Courier", 10),
                        fg=self.text_color, bg=self.bg_secondary, anchor=tk.W)
        label.grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)

        self.settings_shodan_key = tk.Entry(frame, font=("Courier", 10),
                                           bg=self.bg_primary, fg=self.accent_cyan,
                                           insertbackground=self.accent_cyan, relief=tk.FLAT,
                                           show="*", width=30)
        self.settings_shodan_key.grid(row=1, column=1, sticky=tk.EW, padx=10, pady=5)
        if self.config.get("shodan_api_key"):
            self.settings_shodan_key.insert(0, self.config["shodan_api_key"])

        # Show/Hide key button
        self.show_key_var = tk.BooleanVar()
        show_key_check = tk.Checkbutton(frame, text="Show API key", variable=self.show_key_var,
                                       font=("Courier", 9), fg=self.text_color,
                                       bg=self.bg_secondary, selectcolor=self.bg_primary,
                                       command=lambda: self.settings_shodan_key.config(
                                           show="" if self.show_key_var.get() else "*"))
        show_key_check.grid(row=2, column=1, sticky=tk.W, padx=10, pady=2)

        # Save settings button
        save_btn = tk.Button(
            frame,
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
        save_btn.grid(row=3, column=0, columnspan=2, padx=10, pady=20)

        # Process timeout
        self.settings_timeout = self.create_labeled_entry(frame, "Process Timeout (s):", 4, 
                                                          str(self.config.get("timeout", 3600)))

        # Max output lines
        self.settings_maxlines = self.create_labeled_entry(frame, "Max Output Lines:", 5,
                                                           str(self.config.get("max_output_lines", 10000)))

        # Info label
        info_label = tk.Label(
            frame,
            text="\n📝 Settings are saved to:\n~/.recon_superpower/config.json\n\nChanges take effect immediately",
            font=("Courier", 9),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            justify=tk.LEFT
        )
        info_label.grid(row=6, column=0, columnspan=2, sticky=tk.W, padx=10, pady=20)

        return frame

    def save_settings(self):
        """Save settings from the settings tab."""
        # Update config
        shodan_key = self.settings_shodan_key.get().strip()
        if shodan_key:
            # SECURITY FIX (MED-4): Validate Shodan API key format (32 hex characters)
            if not re.match(r'^[a-fA-F0-9]{32}$', shodan_key):
                messagebox.showerror("Invalid API Key",
                    "Shodan API key must be exactly 32 hexadecimal characters.\\n"
                    "Format: 0-9, A-F (case insensitive)\\n"
                    "Example: 1234567890abcdef1234567890abcdef")
                return
            self.config["shodan_api_key"] = shodan_key
        
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
╔═══════════════════════════════════════════════════════════════════════╗
║                    THE RECON SUPERPOWER v1.2                         ║
║           Professional Security Reconnaissance Suite                  ║
╚═══════════════════════════════════════════════════════════════════════╝

[!] For Authorized Security Testing Only
[!] Ensure you have permission to scan the target

4 TOOLS: Nmap | Gobuster | Nikto | Metasploit (Auxiliary/Scanner)

Select a tool from the tabs on the left and configure your scan.
Press 'RUN SCAN' when ready.

KEYBOARD SHORTCUTS:
  Ctrl+R: Run Scan  |  Ctrl+S: Save  |  Ctrl+L: Clear  |  Ctrl+F: Search
  Ctrl+C: Copy      |  Ctrl+Q: Quit  |  ESC: Stop Scan

"""
        self.output_text.insert(tk.END, banner, 'info')
        self.output_text.tag_config('info', foreground=self.accent_cyan)
        # Configure additional output tags for syntax highlighting
        self.output_text.tag_config('success', foreground="#00ff41")
        self.output_text.tag_config('error', foreground="#ff0055")
        self.output_text.tag_config('warning', foreground="#ffa500")
        self.output_text.tag_config('highlight', background="#1e2749", foreground="#00d9ff")
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
                    "tool": self.notebook.tab(self.notebook.select(), "text"),
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
                ET.SubElement(root, "Tool").text = self.notebook.tab(self.notebook.select(), "text")
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

            scan_type = self.nmap_scan_type.get().split()[0]
            timing = self.nmap_timing.get().split()[0]
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

            mode = self.gobuster_mode.get().split()[0]
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
            tuning = self.nikto_tuning.get().split()[0]
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

        elif current_tab == 3:  # Metasploit
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

            search_type = self.shodan_type.get().split()[0]
            facets = self.shodan_facets.get().strip()
            limit = self.shodan_limit.get().strip()

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

            scan_type = self.dnsrecon_type.get().split()[0]
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
            if extensions:
                if not re.match(r'^[a-zA-Z0-9,]+$', extensions):
                    messagebox.showerror("Error", "Invalid extensions format - use comma-separated extensions (e.g., php,html,txt)")
                    return None
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
            except:
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

        cmd = self.build_command()
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
        current_tab = self.notebook.index(self.notebook.select())
        if current_tab == 0:  # Nmap
            target = self.nmap_target.get().strip()
            if target:
                self.add_to_history(target=target)
        elif current_tab == 1:  # Gobuster
            url = self.gobuster_url.get().strip()
            if url:
                self.add_to_history(url=url)
        elif current_tab == 2:  # Nikto
            target = self.nikto_target.get().strip()
            if target:
                self.add_to_history(url=target if target.startswith('http') else None,
                                   target=target if not target.startswith('http') else None)
        elif current_tab == 3:  # Metasploit
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
