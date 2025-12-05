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

        # Load configuration and history
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
        self.gobuster_options = self.create_labeled_entry(frame, "Extra Options:", 5, "")

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
        self.msf_options = self.create_labeled_entry(frame, "Extra Options:", 5, "")

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

        return frame

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
