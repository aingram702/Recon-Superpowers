#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Recon-Superpowers Windows Installation Script
.DESCRIPTION
    Comprehensive installation script for setting up all dependencies and tools
    required by Recon-Superpowers on Windows systems.
.NOTES
    Version: 1.0
    Author: Recon-Superpowers Team
    Requires: PowerShell 5.1+, Administrator privileges, Windows 10/11
#>

param(
    [switch]$SkipChocolatey,
    [switch]$SkipPython,
    [switch]$SkipTools,
    [switch]$SkipGitRepos,
    [string]$InstallPath = "$env:USERPROFILE\ReconTools"
)

# Colors for output
function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Write-Banner {
    $banner = @"

╔══════════════════════════════════════════════════════════════════╗
║                    RECON-SUPERPOWERS INSTALLER                    ║
║                     Windows Installation Script                   ║
║                           Version 1.0                             ║
╚══════════════════════════════════════════════════════════════════╝

"@
    Write-ColorOutput $banner "Cyan"
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-ColorOutput "═══════════════════════════════════════════════════════" "Yellow"
    Write-ColorOutput "  $Title" "Yellow"
    Write-ColorOutput "═══════════════════════════════════════════════════════" "Yellow"
    Write-Host ""
}

function Test-CommandExists {
    param([string]$Command)
    $exists = $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
    return $exists
}

function Install-Chocolatey {
    Write-Section "Installing Chocolatey Package Manager"

    if (Test-CommandExists "choco") {
        Write-ColorOutput "[✓] Chocolatey is already installed" "Green"
        choco --version
        return $true
    }

    Write-ColorOutput "[*] Installing Chocolatey..." "Cyan"
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

        # Refresh environment
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

        Write-ColorOutput "[✓] Chocolatey installed successfully" "Green"
        return $true
    }
    catch {
        Write-ColorOutput "[✗] Failed to install Chocolatey: $_" "Red"
        return $false
    }
}

function Install-Python {
    Write-Section "Installing Python 3"

    if (Test-CommandExists "python") {
        $version = python --version 2>&1
        Write-ColorOutput "[✓] Python is already installed: $version" "Green"
        return $true
    }

    Write-ColorOutput "[*] Installing Python 3.11..." "Cyan"
    try {
        choco install python311 -y --no-progress

        # Refresh environment
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

        Write-ColorOutput "[✓] Python installed successfully" "Green"
        return $true
    }
    catch {
        Write-ColorOutput "[✗] Failed to install Python: $_" "Red"
        return $false
    }
}

function Install-PythonPackages {
    Write-Section "Installing Python Packages"

    $packages = @(
        "shodan",
        "pillow",
        "requests"
    )

    foreach ($package in $packages) {
        Write-ColorOutput "[*] Installing $package..." "Cyan"
        try {
            python -m pip install $package --quiet --disable-pip-version-check
            Write-ColorOutput "[✓] $package installed" "Green"
        }
        catch {
            Write-ColorOutput "[!] Warning: Failed to install $package" "Yellow"
        }
    }
}

function Install-Git {
    Write-Section "Installing Git"

    if (Test-CommandExists "git") {
        Write-ColorOutput "[✓] Git is already installed" "Green"
        git --version
        return $true
    }

    Write-ColorOutput "[*] Installing Git..." "Cyan"
    try {
        choco install git -y --no-progress

        # Refresh environment
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

        Write-ColorOutput "[✓] Git installed successfully" "Green"
        return $true
    }
    catch {
        Write-ColorOutput "[✗] Failed to install Git: $_" "Red"
        return $false
    }
}

function Install-Nmap {
    Write-Section "Installing Nmap"

    if (Test-CommandExists "nmap") {
        Write-ColorOutput "[✓] Nmap is already installed" "Green"
        nmap --version | Select-Object -First 2
        return $true
    }

    Write-ColorOutput "[*] Installing Nmap..." "Cyan"
    try {
        choco install nmap -y --no-progress

        # Refresh environment
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

        Write-ColorOutput "[✓] Nmap installed successfully" "Green"
        return $true
    }
    catch {
        Write-ColorOutput "[✗] Failed to install Nmap: $_" "Red"
        return $false
    }
}

function Install-SQLMap {
    Write-Section "Installing SQLMap"

    $sqlmapPath = "$InstallPath\sqlmap"

    if (Test-Path "$sqlmapPath\sqlmap.py") {
        Write-ColorOutput "[✓] SQLMap is already installed at $sqlmapPath" "Green"
        return $true
    }

    Write-ColorOutput "[*] Installing SQLMap..." "Cyan"
    try {
        if (-not (Test-Path $InstallPath)) {
            New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
        }

        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git $sqlmapPath

        # Create a batch file wrapper
        $batchContent = "@echo off`npython `"$sqlmapPath\sqlmap.py`" %*"
        Set-Content -Path "$InstallPath\sqlmap.bat" -Value $batchContent

        Write-ColorOutput "[✓] SQLMap installed at $sqlmapPath" "Green"
        Write-ColorOutput "[i] Add $InstallPath to your PATH to use 'sqlmap' command" "Cyan"
        return $true
    }
    catch {
        Write-ColorOutput "[✗] Failed to install SQLMap: $_" "Red"
        return $false
    }
}

function Install-Gobuster {
    Write-Section "Installing Gobuster"

    if (Test-CommandExists "gobuster") {
        Write-ColorOutput "[✓] Gobuster is already installed" "Green"
        gobuster version
        return $true
    }

    Write-ColorOutput "[*] Installing Gobuster..." "Cyan"
    try {
        # Try chocolatey first
        choco install gobuster -y --no-progress 2>$null

        if (-not (Test-CommandExists "gobuster")) {
            # Manual download
            $gobusterUrl = "https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_3.6.0_Windows_x86_64.zip"
            $zipPath = "$env:TEMP\gobuster.zip"
            $extractPath = "$InstallPath\gobuster"

            Write-ColorOutput "[*] Downloading Gobuster from GitHub..." "Cyan"
            Invoke-WebRequest -Uri $gobusterUrl -OutFile $zipPath
            Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
            Remove-Item $zipPath

            Write-ColorOutput "[✓] Gobuster installed at $extractPath" "Green"
            Write-ColorOutput "[i] Add $extractPath to your PATH" "Cyan"
        }
        else {
            Write-ColorOutput "[✓] Gobuster installed via Chocolatey" "Green"
        }
        return $true
    }
    catch {
        Write-ColorOutput "[✗] Failed to install Gobuster: $_" "Red"
        return $false
    }
}

function Install-Feroxbuster {
    Write-Section "Installing Feroxbuster"

    if (Test-CommandExists "feroxbuster") {
        Write-ColorOutput "[✓] Feroxbuster is already installed" "Green"
        return $true
    }

    Write-ColorOutput "[*] Installing Feroxbuster..." "Cyan"
    try {
        $feroxUrl = "https://github.com/epi052/feroxbuster/releases/download/v2.10.4/x86_64-windows-feroxbuster.exe.zip"
        $zipPath = "$env:TEMP\feroxbuster.zip"
        $extractPath = "$InstallPath\feroxbuster"

        if (-not (Test-Path $extractPath)) {
            New-Item -ItemType Directory -Path $extractPath -Force | Out-Null
        }

        Write-ColorOutput "[*] Downloading Feroxbuster..." "Cyan"
        Invoke-WebRequest -Uri $feroxUrl -OutFile $zipPath
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
        Remove-Item $zipPath

        # Rename to feroxbuster.exe
        $exeFile = Get-ChildItem -Path $extractPath -Filter "*.exe" | Select-Object -First 1
        if ($exeFile -and $exeFile.Name -ne "feroxbuster.exe") {
            Rename-Item -Path $exeFile.FullName -NewName "feroxbuster.exe"
        }

        Write-ColorOutput "[✓] Feroxbuster installed at $extractPath" "Green"
        Write-ColorOutput "[i] Add $extractPath to your PATH" "Cyan"
        return $true
    }
    catch {
        Write-ColorOutput "[✗] Failed to install Feroxbuster: $_" "Red"
        return $false
    }
}

function Install-Nikto {
    Write-Section "Installing Nikto"

    $niktoPath = "$InstallPath\nikto"

    if (Test-Path "$niktoPath\program\nikto.pl") {
        Write-ColorOutput "[✓] Nikto is already installed at $niktoPath" "Green"
        return $true
    }

    Write-ColorOutput "[*] Installing Nikto..." "Cyan"
    Write-ColorOutput "[!] Note: Nikto requires Perl to run" "Yellow"

    try {
        # Install Strawberry Perl if not present
        if (-not (Test-CommandExists "perl")) {
            Write-ColorOutput "[*] Installing Strawberry Perl..." "Cyan"
            choco install strawberryperl -y --no-progress
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        }

        if (-not (Test-Path $InstallPath)) {
            New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
        }

        git clone --depth 1 https://github.com/sullo/nikto.git $niktoPath

        # Create batch wrapper
        $batchContent = "@echo off`nperl `"$niktoPath\program\nikto.pl`" %*"
        Set-Content -Path "$InstallPath\nikto.bat" -Value $batchContent

        Write-ColorOutput "[✓] Nikto installed at $niktoPath" "Green"
        return $true
    }
    catch {
        Write-ColorOutput "[✗] Failed to install Nikto: $_" "Red"
        return $false
    }
}

function Install-DNSRecon {
    Write-Section "Installing DNSRecon"

    $dnsreconPath = "$InstallPath\dnsrecon"

    if (Test-Path "$dnsreconPath\dnsrecon.py") {
        Write-ColorOutput "[✓] DNSRecon is already installed at $dnsreconPath" "Green"
        return $true
    }

    Write-ColorOutput "[*] Installing DNSRecon..." "Cyan"
    try {
        if (-not (Test-Path $InstallPath)) {
            New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
        }

        git clone --depth 1 https://github.com/darkoperator/dnsrecon.git $dnsreconPath

        # Install dependencies
        Set-Location $dnsreconPath
        python -m pip install -r requirements.txt --quiet --disable-pip-version-check
        Set-Location $PSScriptRoot

        # Create batch wrapper
        $batchContent = "@echo off`npython `"$dnsreconPath\dnsrecon.py`" %*"
        Set-Content -Path "$InstallPath\dnsrecon.bat" -Value $batchContent

        Write-ColorOutput "[✓] DNSRecon installed at $dnsreconPath" "Green"
        return $true
    }
    catch {
        Write-ColorOutput "[✗] Failed to install DNSRecon: $_" "Red"
        return $false
    }
}

function Install-Enum4Linux {
    Write-Section "Installing Enum4Linux-ng (Python version)"

    $enumPath = "$InstallPath\enum4linux-ng"

    if (Test-Path "$enumPath\enum4linux-ng.py") {
        Write-ColorOutput "[✓] Enum4Linux-ng is already installed at $enumPath" "Green"
        return $true
    }

    Write-ColorOutput "[*] Installing Enum4Linux-ng..." "Cyan"
    Write-ColorOutput "[!] Note: Full functionality requires smbclient" "Yellow"

    try {
        if (-not (Test-Path $InstallPath)) {
            New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
        }

        git clone --depth 1 https://github.com/cddmp/enum4linux-ng.git $enumPath

        # Install dependencies
        Set-Location $enumPath
        python -m pip install -r requirements.txt --quiet --disable-pip-version-check 2>$null
        Set-Location $PSScriptRoot

        # Create batch wrapper
        $batchContent = "@echo off`npython `"$enumPath\enum4linux-ng.py`" %*"
        Set-Content -Path "$InstallPath\enum4linux.bat" -Value $batchContent

        Write-ColorOutput "[✓] Enum4Linux-ng installed at $enumPath" "Green"
        return $true
    }
    catch {
        Write-ColorOutput "[✗] Failed to install Enum4Linux-ng: $_" "Red"
        return $false
    }
}

function Install-GitHarvester {
    Write-Section "Installing GitHarvester"

    $gitHarvesterPath = "$InstallPath\GitHarvester"

    if (Test-Path "$gitHarvesterPath\gitHarvester.py") {
        Write-ColorOutput "[✓] GitHarvester is already installed at $gitHarvesterPath" "Green"
        return $true
    }

    Write-ColorOutput "[*] Installing GitHarvester..." "Cyan"
    try {
        if (-not (Test-Path $InstallPath)) {
            New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
        }

        git clone --depth 1 https://github.com/metac0rtex/GitHarvester.git $gitHarvesterPath

        # Create batch wrapper
        $batchContent = "@echo off`npython `"$gitHarvesterPath\gitHarvester.py`" %*"
        Set-Content -Path "$InstallPath\githarvester.bat" -Value $batchContent

        Write-ColorOutput "[✓] GitHarvester installed at $gitHarvesterPath" "Green"
        return $true
    }
    catch {
        Write-ColorOutput "[✗] Failed to install GitHarvester: $_" "Red"
        return $false
    }
}

function Install-AWSBucketDump {
    Write-Section "Installing AWSBucketDump"

    $awsPath = "$InstallPath\AWSBucketDump"

    if (Test-Path "$awsPath\AWSBucketDump.py") {
        Write-ColorOutput "[✓] AWSBucketDump is already installed at $awsPath" "Green"
        return $true
    }

    Write-ColorOutput "[*] Installing AWSBucketDump..." "Cyan"
    try {
        if (-not (Test-Path $InstallPath)) {
            New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
        }

        git clone --depth 1 https://github.com/jordanpotti/AWSBucketDump.git $awsPath

        # Install dependencies
        python -m pip install boto3 --quiet --disable-pip-version-check

        # Create batch wrapper
        $batchContent = "@echo off`npython `"$awsPath\AWSBucketDump.py`" %*"
        Set-Content -Path "$InstallPath\awsbucketdump.bat" -Value $batchContent

        Write-ColorOutput "[✓] AWSBucketDump installed at $awsPath" "Green"
        return $true
    }
    catch {
        Write-ColorOutput "[✗] Failed to install AWSBucketDump: $_" "Red"
        return $false
    }
}

function Install-Wordlists {
    Write-Section "Installing Common Wordlists"

    $wordlistPath = "$InstallPath\wordlists"

    if (Test-Path "$wordlistPath\common.txt") {
        Write-ColorOutput "[✓] Wordlists already exist at $wordlistPath" "Green"
        return $true
    }

    Write-ColorOutput "[*] Downloading common wordlists..." "Cyan"
    try {
        if (-not (Test-Path $wordlistPath)) {
            New-Item -ItemType Directory -Path $wordlistPath -Force | Out-Null
        }

        # Download SecLists common wordlists
        $wordlists = @{
            "common.txt" = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
            "directory-list-2.3-medium.txt" = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt"
            "subdomains-top1million-5000.txt" = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
            "rockyou-top10000.txt" = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-75.txt"
        }

        foreach ($wordlist in $wordlists.GetEnumerator()) {
            Write-ColorOutput "[*] Downloading $($wordlist.Key)..." "Cyan"
            try {
                Invoke-WebRequest -Uri $wordlist.Value -OutFile "$wordlistPath\$($wordlist.Key)" -UseBasicParsing
                Write-ColorOutput "[✓] Downloaded $($wordlist.Key)" "Green"
            }
            catch {
                Write-ColorOutput "[!] Failed to download $($wordlist.Key)" "Yellow"
            }
        }

        return $true
    }
    catch {
        Write-ColorOutput "[✗] Failed to download wordlists: $_" "Red"
        return $false
    }
}

function Set-EnvironmentPath {
    Write-Section "Configuring Environment PATH"

    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $pathsToAdd = @($InstallPath)

    foreach ($pathToAdd in $pathsToAdd) {
        if ($currentPath -notlike "*$pathToAdd*") {
            Write-ColorOutput "[*] Adding $pathToAdd to PATH..." "Cyan"
            [Environment]::SetEnvironmentVariable("Path", "$currentPath;$pathToAdd", "User")
            $env:Path = "$env:Path;$pathToAdd"
            Write-ColorOutput "[✓] Added to PATH" "Green"
        }
        else {
            Write-ColorOutput "[✓] $pathToAdd already in PATH" "Green"
        }
    }
}

function Show-PostInstallInfo {
    Write-Section "Installation Complete!"

    $info = @"

╔══════════════════════════════════════════════════════════════════╗
║                     INSTALLATION SUMMARY                          ║
╚══════════════════════════════════════════════════════════════════╝

Tool Installation Path: $InstallPath

INSTALLED TOOLS:
  ✓ Python 3 + pip packages (shodan, pillow)
  ✓ Nmap - Network scanner
  ✓ SQLMap - SQL injection testing
  ✓ Gobuster - Directory brute-forcing
  ✓ Feroxbuster - Content discovery
  ✓ Nikto - Web vulnerability scanner
  ✓ DNSRecon - DNS enumeration
  ✓ Enum4Linux-ng - Windows/SMB enumeration
  ✓ GitHarvester - GitHub OSINT
  ✓ AWSBucketDump - S3 bucket enumeration
  ✓ Wordlists - Common security wordlists

NEXT STEPS:
  1. Restart your terminal to refresh PATH
  2. Configure Shodan API key in the app (Settings tab)
  3. Launch Recon-Superpowers:
     python recon_superpower.py

NOTES:
  - Metasploit: Install manually from https://www.metasploit.com/
  - TCPdump: Use Wireshark/npcap on Windows instead
  - Some tools have limited Windows functionality

For issues, visit: https://github.com/aingram702/Recon-Superpowers

"@
    Write-ColorOutput $info "Green"
}

function Install-Wireshark {
    Write-Section "Installing Wireshark/Npcap (for packet capture)"

    if (Test-CommandExists "tshark") {
        Write-ColorOutput "[✓] Wireshark is already installed" "Green"
        return $true
    }

    Write-ColorOutput "[*] Installing Wireshark..." "Cyan"
    Write-ColorOutput "[!] Note: This will also install Npcap for packet capture" "Yellow"

    try {
        choco install wireshark -y --no-progress
        Write-ColorOutput "[✓] Wireshark installed successfully" "Green"
        return $true
    }
    catch {
        Write-ColorOutput "[!] Wireshark installation may require manual steps" "Yellow"
        Write-ColorOutput "[i] Download from: https://www.wireshark.org/download.html" "Cyan"
        return $false
    }
}

# Main Installation Flow
function Start-Installation {
    Write-Banner

    Write-ColorOutput "This script will install the following:" "Cyan"
    Write-ColorOutput "  • Chocolatey Package Manager" "White"
    Write-ColorOutput "  • Python 3.11 + pip packages" "White"
    Write-ColorOutput "  • Git" "White"
    Write-ColorOutput "  • Nmap, Gobuster, Feroxbuster" "White"
    Write-ColorOutput "  • SQLMap, Nikto, DNSRecon" "White"
    Write-ColorOutput "  • Enum4Linux-ng, GitHarvester, AWSBucketDump" "White"
    Write-ColorOutput "  • Wireshark/Npcap (packet capture)" "White"
    Write-ColorOutput "  • Security wordlists" "White"
    Write-Host ""
    Write-ColorOutput "Install path: $InstallPath" "Yellow"
    Write-Host ""

    $confirm = Read-Host "Continue with installation? (Y/n)"
    if ($confirm -eq 'n' -or $confirm -eq 'N') {
        Write-ColorOutput "Installation cancelled." "Yellow"
        exit 0
    }

    # Create install directory
    if (-not (Test-Path $InstallPath)) {
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    }

    # Track results
    $results = @{}

    if (-not $SkipChocolatey) {
        $results["Chocolatey"] = Install-Chocolatey
    }

    if (-not $SkipPython) {
        $results["Python"] = Install-Python
        Install-PythonPackages
    }

    $results["Git"] = Install-Git

    if (-not $SkipTools) {
        $results["Nmap"] = Install-Nmap
        $results["SQLMap"] = Install-SQLMap
        $results["Gobuster"] = Install-Gobuster
        $results["Feroxbuster"] = Install-Feroxbuster
        $results["Nikto"] = Install-Nikto
        $results["DNSRecon"] = Install-DNSRecon
        $results["Enum4Linux"] = Install-Enum4Linux
        $results["Wireshark"] = Install-Wireshark
    }

    if (-not $SkipGitRepos) {
        $results["GitHarvester"] = Install-GitHarvester
        $results["AWSBucketDump"] = Install-AWSBucketDump
    }

    $results["Wordlists"] = Install-Wordlists

    Set-EnvironmentPath

    Show-PostInstallInfo

    # Summary
    Write-Section "Installation Results"
    foreach ($result in $results.GetEnumerator()) {
        if ($result.Value) {
            Write-ColorOutput "[✓] $($result.Key)" "Green"
        }
        else {
            Write-ColorOutput "[✗] $($result.Key)" "Red"
        }
    }
}

# Run the installer
Start-Installation
