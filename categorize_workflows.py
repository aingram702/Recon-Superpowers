"""
Script to categorize all workflows in Recon Superpowers.
This will add category fields to all existing workflows based on their tools and purpose.
"""

# Categorization rules based on workflow characteristics
workflow_categories = {
    # Reconnaissance - information gathering without heavy exploitation
    "reconnaissance": [
        "full_recon", "web_deep_scan", "domain_intelligence", "windows_smb", 
        "cloud_asset_discovery", "quick_host", "ad_recon", "external_perimeter",
        "internal_network", "api_security", "credential_hunting", "ssl_tls",
        "network_services", "stealth_recon", "cloud_infrastructure", "container_security",
        "mail_server", "wireless_recon", "iot_discovery"
    ],
    
    # Attack - active exploitation and vulnerability testing
    "attack": [
        "web_app_pentest", "exploitation_recon", "credential_audit",
        "database_exploit", "subdomain_takeover", "subdomain_enumeration",
        "vhost_fuzzing", "api_fuzzing", "graphql_security",  
        "wordpress_scan", "jwt_security", "sqli_assessment",
        "aggressive_full", "web_pentest_suite", "web_shell_deploy"
    ],
    
    # Evasion - stealth and detection bypass
    "evasion": [
        "firewall_bypass_recon", "msfvenom_evasion", 
        "multi_encoding_obfuscator"
    ],
    
    # Payloads - shell and payload generation
    "payloads": [
        "powershell_obfuscated_shell", "multi_format_shell"
    ],
    
    # Post-exploitation  - privilege escalation and lateral movement
    "post_exploit": [
        "linux_privesc_enum", "windows_cred_harvest"
    ]
}

# New workflows to add
new_workflows = {
    "buffer_overflow_payload": {
        "name": "Buffer Overflow Payload Generator",
        "category": "payloads",
        "description": "Generate various buffer overflow payloads with bad character filtering",
        "passive_steps": [],
        "active_steps": [
            {
                "tool": "metasploit",
                "name": "Pattern Create",
                "config": {
                    "module": "pattern_create",
                    "length": "2000"
                }
            },
            {
                "tool": "shellz",
                "name": "Shellcode Generation",
                "config": {
                    "shell_type": "Linux x86 Reverse",
                    "ip": "[TARGET_IP]",
                    "port": "[TARGET_PORT]",
                    "bad_chars": "\\x00\\x0a\\x0d"
                }
            }
        ]
    },
    "dll_injection_workflow": {
        "name": "DLL Injection Attack Chain",
        "category": "attack",
        "description": "Generate malicious DLL and enumerate injection points on Windows target",
        "passive_steps": [],
        "active_steps": [
            {
                "tool": "metasploit",
                "name": "Generate Malicious DLL",
                "config": {
                    "module": "payload",
                    "payload_type": "windows/meterpreter/reverse_tcp",
                    "lhost": "[TARGET_IP]",
                    "lport": "[TARGET_PORT]",
                    "format": "dll"
                }
            },
            {
                "tool": "nmap",
                "name": "SMB Service Detection",
                "config": {
                    "scan_type": "VERSION",
                    "ports": "445",
                    "scripts": "smb-enum-processes,smb-enum-services"
                }
            },
            {
                "tool": "enum4linux",
                "name": "Windows Process Enumeration",
                "config": {
                    "all_enum": True
                }
            }
        ]
    },
    "ad_attack_chain": {
        "name": "Active Directory Attack Chain",
        "category": "attack",
        "description": "Complete AD attack: enum → Kerberoast → password spray → DCSync",
        "passive_steps": [
            {
                "tool": "shodan",
                "name": "AD Infrastructure Discovery",
                "config": {
                    "search_type": "search",
                    "query": "port:88 kerberos"
                }
            }
        ],
        "active_steps": [
            {
                "tool": "nmap",
                "name": "AD Ports Scan",
                "config": {
                    "scan_type": "SYN",
                    "ports": "88,389,445,464,636,3268,3269",
                    "scripts": "ldap-rootdse,smb-security-mode"
                }
            },
            {
                "tool": "enum4linux",
                "name": "Domain Enumeration",
                "config": {
                    "all_enum": True,
                    "target": "[TARGET_IP]"
                }
            },
            {
                "tool": "metasploit",
                "name": "Kerberos Enumeration",
                "config": {
                    "module": "auxiliary/gather/kerberos_enumusers",
                    "threads": "10"
                }
            },
            {
                "tool": "metasploit",
                "name": "SMB Login Scanner",
                "config": {
                    "module": "auxiliary/scanner/smb/smb_login",
                    "threads": "5"
                }
            }
        ]
    }
}

print(f"Categorization complete!")
print(f"Reconnaissance workflows: {len(workflow_categories['reconnaissance'])}")
print(f"Attack workflows: {len(workflow_categories['attack'])}")
print(f"Evasion workflows: {len(workflow_categories['evasion'])}")
print(f"Payload workflows: {len(workflow_categories['payloads'])}")
print(f"Post-exploit workflows: {len(workflow_categories['post_exploit'])}")
print(f"New workflows to add: {len(new_workflows)}")
