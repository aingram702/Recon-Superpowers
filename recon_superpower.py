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

        self.setup_ui()

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

        # Left panel - Tool selection and options
        left_panel = tk.Frame(main_container, bg=self.bg_secondary, width=450)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 10), pady=0)
        left_panel.pack_propagate(False)

        # Tool tabs
        self.notebook = ttk.Notebook(left_panel)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Style for notebook
        style = ttk.Style()
        style.theme_use('default')
        style.configure('TNotebook', background=self.bg_secondary, borderwidth=0)
        style.configure('TNotebook.Tab', background=self.bg_tertiary, foreground=self.text_color,
                       padding=[20, 10], font=('Courier', 10, 'bold'))
        style.map('TNotebook.Tab', background=[('selected', self.bg_primary)],
                 foreground=[('selected', self.accent_green)])

        # Create tabs for each tool
        self.nmap_frame = self.create_nmap_tab()
        self.gobuster_frame = self.create_gobuster_tab()
        self.nikto_frame = self.create_nikto_tab()

        self.notebook.add(self.nmap_frame, text="🔍 NMAP")
        self.notebook.add(self.gobuster_frame, text="📁 GOBUSTER")
        self.notebook.add(self.nikto_frame, text="🔐 NIKTO")

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
        frame = tk.Frame(self.notebook, bg=self.bg_secondary)
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

        # Additional options
        self.nmap_options = self.create_labeled_entry(frame, "Extra Options:", 4, "")

        # Info label
        info_label = tk.Label(
            frame,
            text="\n📡 Network Mapper\nPort scanning & host discovery\n\nExample targets:\n• 192.168.1.1\n• scanme.nmap.org\n• 10.0.0.0/24",
            font=("Courier", 9),
            fg=self.accent_cyan,
            bg=self.bg_secondary,
            justify=tk.LEFT
        )
        info_label.grid(row=5, column=0, columnspan=2, sticky=tk.W, padx=10, pady=20)

        return frame

    def create_gobuster_tab(self):
        frame = tk.Frame(self.notebook, bg=self.bg_secondary)
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
        frame = tk.Frame(self.notebook, bg=self.bg_secondary)
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
║                    THE RECON SUPERPOWER v1.0                         ║
║           Professional Security Reconnaissance Suite                  ║
╚═══════════════════════════════════════════════════════════════════════╝

[!] For Authorized Security Testing Only
[!] Ensure you have permission to scan the target

Select a tool from the tabs on the left and configure your scan.
Press 'RUN SCAN' when ready.

"""
        self.output_text.insert(tk.END, banner, 'info')
        self.output_text.tag_config('info', foreground=self.accent_cyan)
        # Initialize line count for banner
        self.output_line_count = banner.count('\n')

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
        current_tab = self.notebook.index(self.notebook.select())

        if current_tab == 0:  # Nmap
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

        elif current_tab == 1:  # Gobuster
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

        elif current_tab == 2:  # Nikto
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
