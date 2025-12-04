# ⚡ The Recon Superpower v1.2

A professional dark-themed GUI wrapper for essential security reconnaissance tools: **Nmap**, **Gobuster**, **Nikto**, and **Metasploit Framework** (Auxiliary/Scanner modules).

![Version](https://img.shields.io/badge/version-1.2-green)
![Python](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-orange)
![Security](https://img.shields.io/badge/security-hardened-brightgreen)
![Tools](https://img.shields.io/badge/tools-4-blue)

## ⚠️ Legal Disclaimer

**This tool is for AUTHORIZED security testing, penetration testing, CTF challenges, and educational purposes ONLY.**

- ✅ Only scan systems you own or have explicit written permission to test
- ✅ Use in authorized penetration testing engagements
- ✅ CTF competitions and security research
- ❌ Unauthorized scanning is illegal and unethical

By using this tool, you agree to use it responsibly and legally.

## 🆕 What's New in v1.2

### Metasploit Framework Integration 💥
- ✅ **Auxiliary/Scanner Modules** - 16+ reconnaissance modules
- ✅ **Port Scanning** - TCP/SYN port scanners
- ✅ **Service Detection** - SMB, SSH, HTTP, FTP, MySQL, PostgreSQL version detection
- ✅ **Enumeration** - SMB shares, SSH users, SNMP information
- ✅ **Security Restricted** - Only auxiliary/scanner modules allowed (no exploitation)
- ✅ **Full Validation** - Module path validation and input sanitization

### What's New in v1.1

### Security Enhancements 🔒
- ✅ **Comprehensive Security Hardening** - Fixed all critical vulnerabilities
- ✅ **Command Injection Prevention** - Input validation with whitelisting
- ✅ **Path Traversal Protection** - Secure file operations
- ✅ **Thread Safety** - Race condition prevention
- ✅ **Resource Exhaustion Prevention** - Timeouts and limits

### Usability Features ⚡
- ✅ **Keyboard Shortcuts** - `Ctrl+R` Run, `Ctrl+S` Save, `Ctrl+F` Search, `Ctrl+C` Copy
- ✅ **Search in Output** - Find and highlight text in scan results
- ✅ **Copy to Clipboard** - One-click copying of results
- ✅ **Multi-Format Export** - Save as Text, JSON, XML, or HTML
- ✅ **Configuration Persistence** - Remembers window size, position, and settings
- ✅ **Command History** - Quick access to recently used commands
- ✅ **Recent Targets** - Track last 20 scanned targets/URLs
- ✅ **Scan Profiles** - Pre-configured templates (Quick, Deep, Stealth scans)
- ✅ **Syntax Highlighting** - Color-coded output for better readability

See [FEATURE_ENHANCEMENTS.md](FEATURE_ENHANCEMENTS.md) for complete details.

See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for security improvements.

## 🎯 Features

### 🔍 Nmap Integration
- Multiple scan types (SYN, TCP Connect, UDP, Version Detection, OS Detection)
- Configurable timing templates
- Custom port ranges
- Additional command-line options support

### 📁 Gobuster Integration
- Directory/file brute-forcing
- DNS subdomain enumeration
- Virtual host discovery
- Custom wordlist support
- Configurable threads and file extensions

### 🔐 Nikto Integration
- Web server vulnerability scanning
- SSL/TLS support
- Tunable scan types (XSS, SQL Injection, Misconfigurations)
- Port specification

### 💥 Metasploit Integration
- Auxiliary/Scanner modules only (reconnaissance focused)
- Port scanning (TCP/SYN)
- Service version detection (SMB, SSH, HTTP, FTP, MySQL, PostgreSQL)
- Service enumeration (shares, users, SNMP data)
- Configurable threads and options
- **Security Note:** Exploitation modules are blocked - reconnaissance only

### 🎨 Interface Features
- Dark hacker-themed UI
- Real-time command output
- Multi-format export (Text, JSON, XML, HTML)
- Search and highlight in results
- Copy to clipboard
- Save scan results to file
- Stop running scans
- Clear output console
- Status indicators
- Configuration persistence

### ⌨️ Keyboard Shortcuts
- `Ctrl+R` - Run Scan
- `Ctrl+S` - Save Output
- `Ctrl+L` - Clear Console
- `Ctrl+F` - Search in Output
- `Ctrl+C` - Copy Selection/All
- `Ctrl+Q` - Quit Application
- `ESC` - Stop Running Scan

## 📋 Prerequisites

### Required Tools
These tools must be installed and accessible in your PATH:

```bash
# On Kali Linux / Debian / Ubuntu
sudo apt update
sudo apt install nmap gobuster nikto metasploit-framework

# On Arch Linux
sudo pacman -S nmap gobuster nikto metasploit

# On macOS (using Homebrew)
brew install nmap gobuster nikto metasploit

# Note: Metasploit Framework is large (~1.5GB) and may take time to install
# It is optional - the tool will work without it, just the Metasploit tab won't function
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

## 🚀 Installation

1. **Clone or download the repository**
```bash
cd ~/Software/StockTrader
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
```

## 💻 Usage

### Launch the Application
```bash
python3 recon_superpower.py
```

Or make it directly executable:
```bash
./recon_superpower.py
```

### Using Each Tool

#### 🔍 Nmap Scanner
1. Select the **NMAP** tab
2. Enter target IP or hostname (e.g., `192.168.1.1` or `scanme.nmap.org`)
3. Choose scan type (SYN scan recommended for speed)
4. Specify port range (e.g., `1-1000` or `80,443,8080`)
5. Select timing template (T3 Normal is default)
6. Add any extra Nmap options if needed
7. Click **RUN SCAN**

**Example Targets:**
- `scanme.nmap.org` - Nmap's official test server
- `192.168.1.0/24` - Local network range
- `10.0.0.1` - Single host

#### 📁 Gobuster Scanner
1. Select the **GOBUSTER** tab
2. Enter target URL (must include `http://` or `https://`)
3. Choose mode (Directory, DNS, or Virtual Host)
4. Select or browse for a wordlist file
5. Set number of threads (10 is default)
6. Specify file extensions to search for (e.g., `php,html,txt`)
7. Click **RUN SCAN**

**Common Wordlists on Kali:**
- `/usr/share/wordlists/dirb/common.txt`
- `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
- `/usr/share/seclists/Discovery/Web-Content/common.txt`

#### 🔐 Nikto Scanner
1. Select the **NIKTO** tab
2. Enter target URL or IP
3. Specify port (default 80)
4. Enable SSL if scanning HTTPS
5. Choose scan tuning option
6. Click **RUN SCAN**

**Scan Tuning Options:**
- `1` - Interesting files
- `2` - Misconfiguration
- `3` - Information disclosure
- `4` - Injection vulnerabilities
- `6` - XSS vulnerabilities
- `9` - SQL injection
- `x` - All tests (comprehensive)

#### 💥 Metasploit Scanner
1. Select the **METASPLOIT** tab
2. Choose an auxiliary/scanner module from dropdown
3. Enter target IP or hostname (RHOSTS)
4. Configure ports (for port scanner modules)
5. Set thread count (default 10)
6. Add any extra options (as KEY=VALUE)
7. Click **RUN SCAN**

**Available Modules:**
- Port Scanners: TCP, SYN
- Service Detection: SMB, SSH, HTTP, FTP, MySQL, PostgreSQL
- Enumeration: SMB shares, SSH users, SNMP data

**Example Modules:**
- `auxiliary/scanner/portscan/tcp` - TCP port scanner
- `auxiliary/scanner/smb/smb_version` - SMB version detection
- `auxiliary/scanner/ssh/ssh_version` - SSH banner grabbing
- `auxiliary/scanner/http/http_version` - HTTP server detection

**Security Note:** Only auxiliary/scanner modules are available. Exploitation modules are blocked for safety.

### Scan Controls
- **▶ RUN SCAN** - Start the configured scan
- **⬛ STOP** - Terminate the running scan
- **💾 SAVE** - Save console output to a text file
- **🗑 CLEAR** - Clear the console output

## 📖 Tips & Best Practices

### Nmap Tips
- Start with a basic scan (`-sS`) before running intensive scans
- Use `-Pn` in Extra Options to skip ping if host seems down
- For stealth, use slower timing templates (T0-T2)
- Combine with `-sV` for version detection

### Gobuster Tips
- Start with smaller wordlists for faster results
- Adjust thread count based on target capacity
- Use `-k` in Extra Options to skip SSL certificate verification
- Add `-b 404,403` to hide specific status codes

### Nikto Tips
- Nikto scans can be noisy and easily detected
- Use `-Pause` in Extra Options to slow down requests
- Save results with the SAVE button for reporting
- Review findings carefully - may include false positives

## 🛠️ Troubleshooting

### "Command not found" Error
- Ensure the tool is installed: `which nmap` / `which gobuster` / `which nikto`
- Install missing tools using your package manager

### Permission Denied
- Some Nmap scans require root/sudo privileges
- Run as root: `sudo python3 recon_superpower.py`
- Or use capability: `sudo setcap cap_net_raw,cap_net_admin=eip $(which nmap)`

### Wordlist Not Found (Gobuster)
- Verify the wordlist path exists
- Use the browse button to locate wordlists
- Install SecLists: `sudo apt install seclists`

### GUI Not Launching
- Ensure tkinter is installed: `python3 -m tkinter`
- Install if missing: `sudo apt install python3-tk`

## 🎨 Customization

The application uses a dark hacker theme with customizable colors. Edit these variables in the code:

```python
self.bg_primary = "#0a0e27"      # Main background
self.bg_secondary = "#151b3d"    # Panel background
self.accent_green = "#00ff41"    # Primary accent
self.accent_cyan = "#00d9ff"     # Secondary accent
self.accent_red = "#ff0055"      # Alert color
```

## 📝 Output Files

Scan results can be saved using the **SAVE** button:
- Default filename: `recon_output_YYYYMMDD_HHMMSS.txt`
- Contains full console output including commands run
- Suitable for reports and documentation

## 🔒 Security Considerations

1. **Always get written authorization** before scanning any target
2. **Rate limiting**: Be respectful of target systems
3. **Legal compliance**: Know your local laws regarding security testing
4. **Data handling**: Secure any sensitive information discovered
5. **Responsible disclosure**: Report vulnerabilities through proper channels

## 🤝 Contributing

This tool is designed for educational and authorized security testing. Feel free to:
- Report bugs and issues
- Suggest new features
- Submit improvements
- Share your use cases

## 📄 License

MIT License - Use responsibly and legally.

## 🔗 Resources

### Official Documentation
- [Nmap Official Site](https://nmap.org/)
- [Gobuster GitHub](https://github.com/OJ/gobuster)
- [Nikto GitHub](https://github.com/sullo/nikto)

### Learning Resources
- [Nmap Book](https://nmap.org/book/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackTheBox](https://www.hackthebox.eu/) - Practice your skills legally

### Wordlists
- [SecLists](https://github.com/danielmiessler/SecLists) - Comprehensive wordlist collection
- [FuzzDB](https://github.com/fuzzdb-project/fuzzdb) - Fuzzing patterns and payloads

---

**Remember: With great power comes great responsibility. Scan ethically, scan legally.**

⚡ Happy (Authorized) Hacking! ⚡
