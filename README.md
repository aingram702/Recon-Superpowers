# ⚡ The Recon Superpower v3.1

A professional **Monokai-themed** GUI wrapper for **12 essential security reconnaissance tools** with **30 automated workflows**, advanced features, API integrations, and comprehensive security hardening.

![Version](https://img.shields.io/badge/version-3.1-brightgreen)
![Python](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-orange)
![Security](https://img.shields.io/badge/security-hardened-brightgreen)
![Tools](https://img.shields.io/badge/tools-12-blue)
![Workflows](https://img.shields.io/badge/workflows-30-purple)
![Theme](https://img.shields.io/badge/theme-Monokai-yellow)

## ⚠️ Legal Disclaimer

**This tool is for AUTHORIZED security testing, penetration testing, CTF challenges, and educational purposes ONLY.**

- ✅ Only scan systems you own or have explicit written permission to test
- ✅ Use in authorized penetration testing engagements
- ✅ CTF competitions and security research
- ❌ Unauthorized scanning is illegal and unethical

By using this tool, you agree to use it responsibly and legally.

---

## 🚀 What's New in v3.0

### 🔄 Automated Workflows ⭐
- ✅ **30 Pre-defined Workflows** - Basic, advanced, and specialized attack patterns automated
- ✅ **Sequential Execution** - Multi-tool chains with progress tracking
- ✅ **Smart Conditions** - Steps execute based on previous results
- ✅ **Target Validation** - Workflow-specific format checking
- ✅ **Interactive Progress** - Real-time status updates and step tracking

### 🆕 New Feature Tabs
- ✅ **SQLmap Tab** - Full SQL injection testing with level/risk controls, tamper scripts, and database enumeration
- ✅ **Shellz** - Reverse shell generator for 16+ languages (Bash, Python, PowerShell, PHP, etc.)
- ✅ **Encoders** - Base64, URL, Hex, Binary, ROT13, Unicode encoding + MD5/SHA hashing
- ✅ **Decoders** - Decode Base64, URL, Hex, Binary, ROT13, Unicode, and JWT tokens
- ✅ **LOLOL** - Living Off The Land reference with GTFOBins (Linux), LOLBAS (Windows), and LOLAD (Active Directory)
- ✅ **Help** - Comprehensive application guide and cheat sheets

### Enhanced Settings ⚙️
- ✅ **Wordlist Path Configuration** - Set default wordlist directory
- ✅ **Custom Tools Path** - Configure paths to custom tools
- ✅ **Output Directory** - Set default output location
- ✅ **UI Preferences** - Auto-save, timestamps, confirm exit options

### UI Improvements 🎨
- ✅ **TCPDump Interface Dropdown** - Auto-detect and select network interfaces
- ✅ **Improved Cheat Sheets** - Better formatting and readability
- ✅ **Scrollable Settings** - All settings in organized sections

### 🔒 Security & Bug Fixes
- ✅ **Fixed Shodan API Key Validation** - Now accepts valid alphanumeric API keys
- ✅ **Fixed Browse Wordlist Buttons** - Correctly update the target entry field
- ✅ **Improved Input Validation** - Enhanced security across all inputs
- ✅ **Command Injection Prevention** - Comprehensive protection
- ✅ **Timeout Controls** - Total and per-step timeout enforcement
- ✅ **Secure Execution** - All subprocess calls use shell=False

**Basic Workflows:**
1. 🎯 **Full Network Reconnaissance** - Nmap (full port + vuln) → DNS → Gobuster → Nikto → SQLmap → Shodan
2. 🌐 **Web Application Deep Scan** - Nmap (web scripts) → Nikto → Gobuster → feroxbuster → SQLmap → Shodan
3. 📡 **Domain Intelligence Gathering** - DNSrecon (std + brt) → Shodan → GitHarvester
4. 🖥️ **Windows/SMB Enumeration** - Nmap (SMB scripts + vuln) → enum4linux → MSF Version → MSF Shares → MS17-010
5. ☁️ **Cloud Asset Discovery** - AWSBucketDump → GitHarvester → Shodan
6. ⚡ **Quick Host Discovery** - Nmap (fast) → Nikto (quick)

**Advanced Attack Workflows:**
7. 🏢 **AD Reconnaissance** - Nmap (AD ports) → enum4linux → MSF LDAP → Kerberos
8. 🌍 **Web Application Pentesting** - Nmap → Nikto → Gobuster → feroxbuster → Vhost → SQLmap
9. 🔴 **External Perimeter Assessment** - DNS → Subdomain → Shodan → Nmap → GitHarvester
10. 🔄 **Internal Network Sweep** - Host Discovery → Service Enum → Windows → MSF
11. 🔌 **API Security Assessment** - Nmap → Gobuster (API) → feroxbuster → Nikto
12. 🔑 **Credential Hunting** - GitHarvester → Shodan → Nmap → MSF FTP
13. 🔒 **SSL/TLS Assessment** - Nmap (SSL scripts) → Nikto HTTPS → Shodan
14. 📊 **Network Services Audit** - Full Port Scan → Version Detection → Nikto → SMB → SSH
15. 🥷 **Stealth Reconnaissance** - Slow Nmap → DNS → Shodan → GitHub
16. 📦 **Full Stack Assessment** - DNS → Nmap → Nikto → Gobuster → enum4linux → Shodan → Git
17. 🔓 **Vulnerability Assessment** - Nmap (vuln) → Nikto → MSF SMB → Shodan
18. 🗄️ **Database Discovery** - Nmap (DB ports) → MySQL → MSSQL → Shodan
19. 📧 **Mail Server Reconnaissance** - DNS MX → Nmap (mail) → SMTP Enum → Shodan
20. 💉 **SQL Injection Assessment** - Nmap → Nikto → Gobuster → SQLmap

---

## 🛠️ Integrated Tools (12 Total)

### Core Network Tools
1. **🔍 Nmap** - Network mapper with NSE script support
2. **📡 DNSrecon** - DNS enumeration and reconnaissance
3. **📦 TCPdump** - Packet capture and network analysis

### Web Application Tools
4. **📁 Gobuster** - Directory/DNS brute-forcing
5. **🔐 Nikto** - Web server vulnerability scanning
6. **💉 SQLmap** - Automatic SQL injection detection and exploitation
7. **🦀 feroxbuster** - Fast recursive web content discovery

### Cloud & OSINT
8. **🌐 Shodan** - Internet-connected device search (API required)
9. **🔎 GitHarvester** - GitHub repository OSINT
10. **☁️ AWSBucketDump** - AWS S3 bucket enumeration

### System Enumeration
11. **🖥️ enum4linux** - SMB/Windows enumeration
12. **💥 Metasploit** - Framework auxiliary/scanner modules

---

## 📋 Prerequisites

### Required Tools

```bash
# Core tools (Included in most pentesting distros)
sudo apt update
sudo apt install nmap gobuster nikto metasploit-framework sqlmap

# Additional tools for v3.0
sudo apt install dnsrecon enum4linux tcpdump

# feroxbuster (Rust-based, may need manual installation)
# Download from: https://github.com/epi052/feroxbuster/releases
wget https://github.com/epi052/feroxbuster/releases/download/v2.10.1/feroxbuster_amd64.deb
sudo dpkg -i feroxbuster_amd64.deb

# Shodan CLI (Python package)
pip3 install shodan

# GitHarvester (Clone from GitHub)
git clone https://github.com/metac0rtex/GitHarvester
# Update path in code: line ~2187

# AWSBucketDump (Clone from GitHub)
git clone https://github.com/jordanpotti/AWSBucketDump
# Update path in code: line ~2260
```

### Python Requirements
- Python 3.6 or higher
- tkinter (usually included with Python)

```bash
# Verify Python installation
python3 --version

# If tkinter is missing (Ubuntu/Debian)
sudo apt install python3-tk
```

### API Keys
- **Shodan API Key**: Required for Shodan tool
  - Get key from: https://account.shodan.io/
  - Configure in Settings tab after launch

---

## 🚀 Installation

1. **Clone the repository**
```bash
git clone https://github.com/aingram702/Recon-Superpowers.git
cd Recon-Superpowers
```

2. **Make the script executable**
```bash
chmod +x recon_superpower.py
```

3. **Verify tool installations**
```bash
nmap --version
gobuster version
nikto -Version
dnsrecon --version
enum4linux --version
feroxbuster --version
shodan info  # Requires API key
```

---

## 💻 Usage

### Launch the Application
```bash
python3 recon_superpower.py
```

### Interface Overview
- **Left Sidebar**: 12 tools + Settings (click to switch)
- **Center Panel**: Tool-specific configuration options
- **Right Panel**: Real-time command output
- **Bottom Bar**: Status indicator

---

## 🔧 Tool Usage Guide

---

## 🔄 Using Workflows (Automated Multi-Tool Reconnaissance)

**Workflows** automate multi-tool reconnaissance by chaining tools together in intelligent sequences. Perfect for comprehensive assessments without manual intervention.

### Quick Start

1. Click **🔄 Workflows** in the sidebar
2. Select a workflow from the dropdown
3. Review the workflow steps in the preview pane
4. Enter your target (format depends on workflow)
5. Click **▶ RUN WORKFLOW**
6. Monitor progress in real-time
7. Review consolidated results in console output

### Workflow Descriptions

#### 🎯 Full Network Reconnaissance
**Best for:** Unknown networks, comprehensive assessment  
**Target:** IP address or network range  
**Duration:** ~20-40 minutes  

**Steps:**
1. Nmap port scan (ports 1-1000, SYN scan)
2. Gobuster directory enum (if HTTP detected)
3. Nikto vulnerability scan (if HTTP detected)
4. DNSrecon DNS enumeration

**Example Targets:**
- `192.168.1.1`
- `10.0.0.0/24`
- `scanme.nmap.org`

---

#### 🌐 Web Application Deep Scan
**Best for:** Web applications, API endpoints  
**Target:** URL  
**Duration:** ~30-60 minutes  

**Steps:**
1. Nikto web scan (all checks)
2. Gobuster directory brute force
3. feroxbuster recursive deep scan
4. Shodan lookup for domain/IP

**Example Targets:**
- `http://example.com`
- `https://192.168.1.100`

---

#### 📡 Domain Intelligence Gathering
**Best for:** Domain reconnaissance,OSINT  
**Target:** Domain name  
**Duration:** ~15-30 minutes  

**Steps:**
1. DNSrecon standard enumeration
2. DNSrecon subdomain brute force
3. Shodan infrastructure search
4. GitHarvester GitHub references

**Example Targets:**
- `example.com`
- `subdomain.example.org`

---

#### 🖥️ Windows/SMB Enumeration
**Best for:** Windows hosts, Active Directory  
**Target:** IP address  
**Duration:** ~10-20 minutes  

**Steps:**
1. Nmap SMB port scan (135,139,445)
2. enum4linux comprehensive enumeration
3. Metasploit SMB version detection

**Example Targets:**
- `192.168.1.10`
- `dc01.domain.local`

---

#### ☁️ Cloud Asset Discovery
**Best for:** Cloud security assessment  
**Target:** Organization name  
**Duration:** ~15-25 minutes  

**Steps:**
1. AWS S3 bucket enumeration
2. GitHarvester credential search
3. Shodan organization infrastructure

**Example Targets:**
- `MyCompany`
- `example-corp`

---

#### ⚡ Quick Host Discovery
**Best for:** Fast initial reconnaissance  
**Target:** IP address or hostname  
**Duration:** ~5-10 minutes  

**Steps:**
1. Nmap fast port scan (T5 timing)
2. Nikto quick web scan (if HTTP detected)

**Example Targets:**
- `192.168.1.1`
- `webserver.local`

---

### Workflow Features

**🔒 Security:**
- Target validation before execution
- Command injection prevention
- Workflow timeout: 2 hours max
- Step timeout: 30 minutes max

**📊 Progress Tracking:**
- Real-time step counter
- Progress bar with percentage
- Elapsed time display
- Current tool indicator

**🎯 Smart Execution:**
- Conditional steps (e.g., "if HTTP detected")
- Previous result parsing
- Error handling with continue/stop options
- Thread-safe execution

**💾 Results:**
- Consolidated output in console
- Step-by-step results
- Export to file available
- Copy to clipboard

---

### 🔍 Nmap - Network Scanner
**Enhanced with NSE Script Support**

1. Select **Nmap** from sidebar
2. Enter target (IP, hostname, or CIDR)
3. Choose scan type (SYN scan recommended)
4. Set port range (e.g., `1-1000`, `80,443,8080`)
5. Select timing template (T3 Normal is default)
6. **NEW:** Choose NSE script category or enter custom script
7. Click **RUN SCAN**

**NSE Script Categories:**
- `default` - Default scripts
- `vuln` - Vulnerability detection
- `discovery` - Network discovery
- `auth` - Authentication testing
- `exploit` - Exploit checks
- `safe` - Safe scripts only
- Custom - Enter your own script name

**Example Targets:**
- `scanme.nmap.org` - Nmap's official test server
- `192.168.1.0/24` - Network range
- `10.0.0.1` - Single host

---

### 🌐 Shodan - Device Search Engine **[NEW]**
**Requires API Key**

1. Configure API key in **Settings** tab first
2. Select **Shodan** from sidebar
3. Choose search type:
   - `search` - Query-based search
   - `host` - Specific IP lookup
4. Enter search query
5. Optional: Add facets (e.g., `country,org,port`)
6. Set result limit
7. Click **RUN SCAN**

**Example Queries:**
- `apache port:443` - Apache servers on port 443
- `nginx country:US` - Nginx servers in United States
- `port:22 'SSH-2.0'` - SSH servers
- `product:MySQL` - MySQL databases

**Security:** Private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x) are blocked

---

### 📡 DNSrecon - DNS Enumeration **[NEW]**

1. Select **DNSrecon** from sidebar
2. Enter domain name
3. Choose scan type:
   - `std` - Standard enumeration
   - `axfr` - Zone transfer attempt
   - `brt` - Brute force subdomains
   - `rvl` - Reverse lookup
   - `srv` - SRV record enumeration
   - `crt` - crt.sh search
   - `zonewalk` - DNSSEC zone walk
4. For brute force: Select wordlist
5. Optional: Specify custom nameserver
6. Click **RUN SCAN**

---

### 🖥️ enum4linux - SMB Enumeration **[NEW]**

1. Select **enum4linux** from sidebar
2. Enter target IP address
3. Choose enumeration options:
   - **All Enumeration (-a)** - Comprehensive scan (recommended)
   - OR select specific: Users, Shares, Groups, Password Policy
4. Optional: Provide credentials for authenticated scan
5. Click **RUN SCAN**

**What it enumerates:**
- User lists
- Share lists
- Group information
- Password policies
- Domain information

---

### 🔎 GitHarvester - GitHub OSINT **[NEW]**

1. Select **GitHarvester** from sidebar
2. Enter GitHub search query
3. Optional: Custom regex pattern for filtering
4. Optional: Filter by user/organization
5. Optional: Filter by project
6. Choose sort order (best/new/old)
7. Click **RUN SCAN**

**Example Searches:**
- `filename:shadow path:etc` - Shadow files
- `extension:pem private` - Private keys
- `password filename:config` - Config files with passwords
- `AWS_ACCESS_KEY` - AWS credentials

**Security:** Regex patterns validated to prevent ReDoS attacks

---

### 🦀 feroxbuster - Web Content Discovery **[NEW]**
**Fast Rust-based Scanner**

1. Select **feroxbuster** from sidebar
2. Enter target URL (include `http://` or `https://`)
3. Select wordlist file
4. Specify extensions (e.g., `php,html,txt,asp,aspx`)
5. Set thread count (default 50, max 100)
6. Set recursion depth (default 4)
7. Click **RUN SCAN**

**Features:**
- Recursive scanning
- Fast multi-threading
- Extension filtering
- Auto-filtering 404s

---

### ☁️ AWSBucketDump - S3 Enumeration **[NEW]**

1. Select **AWS S3** from sidebar
2. Specify bucket list file
3. Optional: Grep keywords file for filtering
4. Optional: Enable "Download Files" (use responsibly)
5. Set thread count (default 5, max 20)
6. Click **RUN SCAN**

**Use Cases:**
- Bucket enumeration
- Permission testing
- Data discovery
- Security audits

**⚠️ Warning:** Only test authorized targets. Downloading files without permission is illegal.

---

### 📦 TCPdump - Packet Capture **[NEW]**
**Requires sudo/root privileges**

1. Select **TCPdump** from sidebar
2. Enter network interface (e.g., `eth0`, `wlan0`)
3. Enter BPF filter (e.g., `port 80`, `host 192.168.1.1`)
4. Set packet count limit
5. Optional: Specify output PCAP file
6. Enable verbose mode if desired
7. Click **RUN SCAN** (will prompt for sudo password)

**Example Filters:**
- `port 80` - HTTP traffic
- `tcp and port 443` - HTTPS traffic
- `host 192.168.1.1 and port 22` - SSH to specific host
- `icmp` - ICMP (ping) traffic

**Security:** Interface names and BPF filters are validated. Only simple filters allowed.

---

### 📁 Gobuster - Directory Brute-forcing

1. Select **Gobuster** from sidebar
2. Enter target URL (must include `http://` or `https://`)
3. Choose mode (Directory, DNS, or Virtual Host)
4. Select wordlist file
5. Set threads (default 10)
6. Specify file extensions
7. Click **RUN SCAN**

**Common Wordlists on Kali:**
- `/usr/share/wordlists/dirb/common.txt`
- `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
- `/usr/share/seclists/Discovery/Web-Content/common.txt`

---

### 🔐 Nikto - Web Vulnerability Scanner

1. Select **Nikto** from sidebar
2. Enter target URL or IP
3. Specify port (default 80)
4. Enable SSL for HTTPS targets
5. Choose scan tuning (x = all tests)
6. Click **RUN SCAN**

**Scan Tuning Options:**
- `1` - Interesting files
- `2` - Misconfiguration
- `3` - Information disclosure
- `4` - Injection vulnerabilities (XSS/SQLi)
- `6` - XSS vulnerabilities
- `9` - SQL injection
- `x` - All tests (comprehensive)

---

### 💥 Metasploit - Framework Scanner

1. Select **Metasploit** from sidebar
2. Choose auxiliary/scanner module
3. Enter target (RHOSTS)
4. Configure ports (for port scanners)
5. Set thread count
6. Add extra options (KEY=VALUE format)
7. Click **RUN SCAN**

**Available Module Categories:**
- Port Scanners (TCP/SYN)
- Service Detection (SMB, SSH, HTTP, FTP, MySQL, PostgreSQL)
- Service Enumeration (shares, users, SNMP)

**Security Note:** Only auxiliary/scanner modules allowed - no exploitation.

---

### ⚙️ Settings **[NEW]**

1. Select **Settings** from sidebar
2. **Shodan API Key**: Enter your 32-character alphanumeric API key
3. **Process Timeout**: Set max scan duration (default 3600s)
4. **Max Output Lines**: Memory management (default 10000)
5. Click **SAVE SETTINGS**

Settings are saved to: `~/.recon_superpower/config.json`

---

## ⌨️ Keyboard Shortcuts

- `Ctrl+R` - Run Scan
- `Ctrl+S` - Save Output
- `Ctrl+L` - Clear Console
- `Ctrl+F` - Search in Output
- `Ctrl+C` - Copy Selection/All
- `Ctrl+Q` - Quit Application
- `ESC` - Stop Running Scan

---

## 📖 Tips & Best Practices

### General Tips
- Always start with less aggressive scans
- Monitor target system load
- Respect rate limits
- Save results for documentation
- Use scan profiles for consistency

### Nmap Tips
- Use NSE scripts for deeper reconnaissance
- Combine `-sV` with `--script vuln` for vulnerability assessment
- Start with quick scan, then deep scan on interesting ports
- Use `-Pn` to skip ping if host seems down

### Shodan Tips
- Narrow searches with facets
- Use `net:` filter for specific networks
- Combine multiple filters (e.g., `product:nginx country:US`)
- Be aware of query credit limits

### DNSrecon Tips
- Try zone transfer (axfr) first - often reveals everything
- Use large wordlists for brute force (be patient)
- Combine with other OSINT for subdomain discovery

### Web Scanner Tips (Gobuster/feroxbuster)
- Start with smaller wordlists
- Adjust threads based on target capacity
- Use `-k` to skip SSL  verification
- Save results immediately - scans can be interrupted

### TCPdump Tips
- Run with minimal privileges when possible
- Use specific filters to reduce noise
- Limit packet count to avoid huge files
- Analyze PCAP files with Wireshark

---

## 🛠️ Troubleshooting

### Tool Not Found Errors
```bash
# Check if tool is installed
which nmap
which shodan
which dnsrecon

# Install missing tools
sudo apt install <tool-name>
```

### Permission Denied (TCPdump/Nmap)
```bash
# Run with sudo for packet capture
sudo python3 recon_superpower.py

# Or set capabilities (Nmap only)
sudo setcap cap_net_raw,cap_net_admin=eip $(which nmap)
```

### Shodan API Errors
- Verify API key is correct (32 hex characters)
- Check account has available query credits
- Ensure network connectivity to Shodan API

### GitHarvester/AWSBucketDump Not Found
- Clone repositories as shown in Prerequisites
- Update script paths in code (see comments in build_command method)

### GUI Not Launching
```bash
# Test tkinter
python3 -m tkinter

# Install if missing
sudo apt install python3-tk
```

---

## 🔒 Security & Privacy

### Built-in Security Features
- **Input Validation**: All user inputs validated
- **Command Injection Prevention**: Whitelisting and sanitization
- **Path Traversal Protection**: Restricted file operations
- **API Key Protection**: Environment variables (not command-line)
- **Private IP Blocking**: Prevents SSRF attacks
- **Resource Limits**: Thread counts, timeouts, output size
- **ReDoS Prevention**: Regex pattern validation

### Privacy Considerations
- API keys stored in `~/.recon_superpower/config.json` (plain text, local file)
- Scan history stored locally
- No telemetry or external reporting
- All tool data stays on your system

### Responsible Use
1. **Get authorization** - Always obtain written permission
2. **Rate limiting** - Don't overwhelm targets
3. **Legal compliance** - Know your jurisdiction's laws
4. **Data security** - Protect discovered information
5. **Responsible disclosure** - Report vulnerabilities properly

---

## 📦 Output & Export

### Saving Results
- Click **💾 SAVE** to save console output
- Default: `recon_output_YYYYMMDD_HHMMSS.txt`
- Contains full output including commands

### Export Formats
- **📤 EXPORT** button offers multiple formats:
  - Text (`.txt`)
  - JSON (`.json`)
  - XML (`.xml`)
  - HTML (`.html`) - Styled with dark theme

### Search & Copy
- **🔍 SEARCH** - Find text in output with highlighting
- **📋 COPY** - Copy selected text or all output

---

## 🎨 Customization

### Theme Colors
Edit these variables in the code to customize colors:

```python
self.bg_primary = "#0a0e27"      # Main background
self.bg_secondary = "#151b3d"    # Panel background
self.bg_tertiary = "#1e2749"     # Sidebar background
self.accent_green = "#00ff41"    # Primary accent (active elements)
self.accent_cyan = "#00d9ff"     # Secondary accent (headers)
self.accent_red = "#ff0055"      # Alert/stop color
```

---

## 📊 Project Stats

- **Lines of Code**: 8,500+
- **Methods**: 80+
- **Security Validations**: 30+
- **Integrated Tools**: 12 reconnaissance tools
- **Feature Tabs**: 6 (Shellz, Encoders, Decoders, LOLOL, Help, Workflows)
- **File Size**: ~300KB
- **Workflows**: 30 automated reconnaissance patterns

---

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional tool integrations
- More NSE script templates
- Enhanced UI features
- Additional export formats
- Automated testing

---

## 📄 License

MIT License - See LICENSE file for details.

Use this tool responsibly and legally.

---

## 🔗 Resources

### Tool Documentation
- [Nmap Reference](https://nmap.org/book/man.html)
- [Gobuster GitHub](https://github.com/OJ/gobuster)
- [Nikto Documentation](https://github.com/sullo/nikto/wiki)
- [Metasploit Unleashed](https://www.metasploitunleashed.com/)
- [Shodan Search Guide](https://www.shodan.io/search/filters)
- [DNSrecon GitHub](https://github.com/darkoperator/dnsrecon)
- [feroxbuster Docs](https://github.com/epi052/feroxbuster)

### Learning Resources
- [Nmap NSE Scripts](https://nmap.org/nsedoc/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackTheBox](https://www.hackthebox.eu/) - Legal practice environment
- [TryHackMe](https://tryhackme.com/) - Guided learning paths

### Wordlists & Data
- [SecLists](https://github.com/danielmiessler/SecLists) - Comprehensive collection
- [FuzzDB](https://github.com/fuzzdb-project/fuzzdb) - Fuzzing patterns
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

---

## 📝 Changelog

### v3.1 (2025-12-08)
- **Monokai Theme** - Complete UI overhaul with Monokai terminal color scheme
- **30 Workflows** - Added 10 new specialized workflows (network mapper, web vuln hunter, OSINT gather, password hunt, infrastructure map, API pentest, subdomain hunter, cloud pentest, red team initial, blue team audit)
- **Enhanced ASCII Banner** - New stylized banner with box-drawing characters
- **Improved Text Boxes** - All input/output areas use Consolas font with Monokai colors
- **Better Contrast** - Improved readability with proper syntax highlighting

### v3.0 (2025-12-07)
- Added 20 automated workflows (6 basic + 14 advanced attack patterns)
- New feature tabs: SQLmap, Shellz, Encoders, Decoders, LOLOL, Help
- Enhanced Settings with path configuration and UI preferences
- TCPDump interface dropdown with auto-detection
- Fixed Shodan API key validation (alphanumeric support)
- Fixed wordlist browse buttons across all tools
- Improved cheat sheet UI and formatting
- Added msfvenom payload generation to Metasploit tab

### v2.0 (2025-12-05)
- Complete UI redesign with sidebar navigation
- Added 7 new tools (Shodan, DNSrecon, enum4linux, GitHarvester, feroxbuster, AWSBucketDump, TCPdump)
- Nmap NSE script support
- Settings tab with API key management
- Comprehensive security audit and vulnerability remediation
- Enhanced input validation across all tools
- Improved UX with hover effects

### v1.2 (Previous)
- Metasploit Framework integration
- Scan profiles
- Enhanced security

### v1.1 (Previous)
- Security hardening
- Keyboard shortcuts
- Multi-format export
- Search functionality

### v1.0 (Initial)
- Core functionality with Nmap, Gobuster, Nikto

---

**Remember: With great power comes great responsibility. Scan ethically, scan legally, scan responsibly.**

⚡ **Happy (Authorized) Reconnaissance!** ⚡

---

**Project**: Recon-Superpowers
**Version**: 3.1
**Author**: aingram702
**Repository**: https://github.com/aingram702/Recon-Superpowers
**License**: MIT
