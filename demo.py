#!/usr/bin/env python3
"""
AI Automated Security Engineer (AASE) - Live Demo
Simulates platform scanning AWS, Azure/Avahi AI, and Banking environments.
No external dependencies required — Python 3.8+ standard library only.
Run: python demo.py
"""

import random
import time
import uuid
from datetime import datetime, timezone

# ANSI Colours
R = "\033[91m"; Y = "\033[93m"; G = "\033[92m"
B = "\033[94m"; C = "\033[96m"; M = "\033[95m"
W = "\033[97m"; DIM = "\033[2m"; BOLD = "\033[1m"; NC = "\033[0m"

def banner(text, colour=C):
    w = 72
    print(f"\n{colour}{BOLD}{'=' * w}\n  {text}\n{'=' * w}{NC}")

def section(text):
    print(f"\n{B}{BOLD}-- {text} {'-' * (60 - len(text))}{NC}")

def tick(msg, delay=0.07):
    print(f"  {G}OK{NC} {msg}"); time.sleep(delay)

def alert(msg):
    print(f"  {R}!! {msg}{NC}"); time.sleep(0.05)

def info(msg):
    print(f"  {DIM}{msg}{NC}"); time.sleep(0.03)

def progress(label, steps=20, colour=G):
    print(f"  {label}: ", end="", flush=True)
    for i in range(steps):
        pct = int((i+1)/steps*100)
        bar = "#"*(i+1) + "."*(steps-i-1)
        print(f"\r  {label}: {colour}[{bar}]{NC} {pct:3d}%", end="", flush=True)
        time.sleep(0.04)
    print()

def ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

# ── DATA ──────────────────────────────────────────────────────────────

TARGETS = {
    "aws":   {"name": "Amazon AWS Production",    "hosts": ["10.0.1.45","10.0.1.82","10.0.2.10","ec2-54-23-11-9.compute-1.amazonaws.com"]},
    "azure": {"name": "Microsoft Azure / Avahi AI","hosts": ["10.1.0.10","10.1.0.22","aase-prod.eastus.cloudapp.azure.com"]},
    "bank":  {"name": "Banking / SWIFT Network",   "hosts": ["192.168.100.5","192.168.100.12","192.168.100.99"]},
}

VULNS = [
    ("CVE-2024-3094",  "XZ Utils Supply-Chain Backdoor",     "CRITICAL", 10.0, "xz-utils 5.6.0",          "T1195.002"),
    ("CVE-2024-21412", "Windows SmartScreen Bypass",         "HIGH",      8.1, "Windows Defender",         "T1553.005"),
    ("CVE-2023-44487", "HTTP/2 Rapid Reset DDoS",            "HIGH",      7.5, "nginx 1.24.0",             "T1498"),
    ("CVE-2024-1709",  "ConnectWise Auth Bypass (RCE)",      "CRITICAL", 10.0, "ConnectWise ScreenConnect", "T1190"),
    ("AASE-NET-001",   "Redis Exposed Without Auth",          "CRITICAL",  9.8, "Redis 7.2 :6379",          "T1190"),
    ("AASE-IAM-002",   "IAM User Without MFA",               "HIGH",      7.8, "AWS IAM: svc-deploy",      "T1078"),
    ("AASE-S3-003",    "S3 Bucket Public Read Access",        "HIGH",      7.5, "s3://prod-customer-data",  "T1530"),
    ("AASE-WEB-004",   "Missing HSTS Header",                "MEDIUM",    5.3, "Web Load Balancer",        "T1040"),
    ("AASE-SQL-005",   "SQL Injection /api/search",           "CRITICAL",  9.1, "Banking API v2.3",         "T1190"),
    ("AASE-CTR-006",   "Container Running as Root",           "MEDIUM",    6.5, "api-gateway:latest",       "T1611"),
]

THREATS = [
    ("Brute Force Attack",         "HIGH",     "185.220.101.47", "T1110.001", "Credential Access",    847),
    ("C2 Beacon (Cobalt Strike)",  "CRITICAL", "10.0.1.45",      "T1071.001", "Command and Control",  1),
    ("Ransomware File Encryption", "CRITICAL", "10.0.1.82",      "T1486",     "Impact",               1),
    ("DNS Tunnelling Exfiltration","HIGH",      "10.1.0.10",      "T1048.003", "Exfiltration",         234),
    ("Sudo Privilege Escalation",  "HIGH",      "10.0.2.10",      "T1548.003", "Privilege Escalation", 3),
    ("XMRig Cryptomining",         "MEDIUM",   "10.0.1.82",      "T1496",     "Impact",               1),
    ("S3 Mass Download (rogue IAM)","HIGH",     "svc-deploy",     "T1530",     "Collection",           12540),
    ("Pass-the-Hash Lateral Move", "CRITICAL", "192.168.100.5",  "T1550.002", "Lateral Movement",     1),
]

COMPLIANCE = {
    "PCI-DSS v4.0": [
        ("PCI-1.2.1", "Network Security Controls",    "PASS",    "Firewall rules verified"),
        ("PCI-2.2.1", "Vendor Default Credentials",   "FAIL",    "3 devices using default passwords"),
        ("PCI-3.5.1", "PAN Encrypted at Rest",        "PASS",    "AES-256 confirmed"),
        ("PCI-4.2.1", "TLS Encryption in Transit",    "PARTIAL", "TLS 1.0 still active on 2 endpoints"),
        ("PCI-6.3.3", "Critical Patches Applied",     "FAIL",    "4 CVEs unpatched > 30 days"),
        ("PCI-7.2.1", "Least Privilege Access",       "PASS",    "IAM roles reviewed"),
        ("PCI-8.3.6", "MFA for Admin Access",         "FAIL",    "svc-deploy, svc-ci missing MFA"),
        ("PCI-10.2.1","Audit Log Retention 12 Months","PASS",    "CloudWatch + S3 export active"),
    ],
    "HIPAA Security Rule": [
        ("HIPAA-308a1","Risk Analysis Program",        "PASS",    "Risk assessment done Q1-2026"),
        ("HIPAA-308a5","Security Awareness Training",  "PASS",    "All 847 staff completed training"),
        ("HIPAA-312a1","Unique User ID + Auto Logoff", "FAIL",    "2 shared service accounts found"),
        ("HIPAA-312a2","Audit Controls Active",        "PASS",    "CloudTrail + SIEM enabled"),
        ("HIPAA-312e1","ePHI Transmission Encryption", "PASS",    "All ePHI endpoints use TLS 1.3"),
    ],
    "CIS Controls v8": [
        ("CIS-1.1",  "Enterprise Asset Inventory",    "PASS",    "1,247 assets catalogued"),
        ("CIS-4.1",  "Secure Configuration",          "PARTIAL", "18 systems missing CIS hardening"),
        ("CIS-5.3",  "Disable Dormant Accounts 45d",  "FAIL",    "12 accounts dormant > 45 days"),
        ("CIS-6.3",  "MFA for External Apps",         "FAIL",    "Customer portal lacks MFA"),
        ("CIS-7.3",  "Vulnerability Remediation SLA", "FAIL",    "3 critical vulns > 14 days old"),
        ("CIS-8.2",  "Centralized Audit Logging",     "PASS",    "Elasticsearch SIEM, 365d retention"),
    ],
}

# ── DEMO MODULES ───────────────────────────────────────────────────────

def startup():
    banner("AI AUTOMATED SECURITY ENGINEER  --  LIVE DEMO")
    print(f"""
  {W}{BOLD}Version:{NC}     1.0.0
  {W}{BOLD}AI Engine:{NC}   Ollama Llama 3.1 70B  [LOCAL  --  no data leaves environment]
  {W}{BOLD}Started:{NC}     {ts()}
  {W}{BOLD}Targets:{NC}     Amazon AWS  |  Microsoft Azure / Avahi AI  |  Banking / SWIFT
    """)
    progress("Loading AI Models (Llama 3.1 70B) ", 30, G)
    progress("Fetching CVE/MITRE ATT&CK feeds   ", 25, B)
    progress("Connecting Cloud APIs              ", 20, M)
    progress("Starting SIEM Log Watchers         ", 15, C)
    tick("AASE Platform ready", 0.2)

def vuln_scan(env_key):
    env = TARGETS[env_key]
    section(f"MODULE 1  VULNERABILITY SCANNER  ->  {env['name']}")
    info(f"Hosts: {', '.join(env['hosts'])}")
    print()
    progress("Network scan (nmap -sV --script vuln)", 28, G)
    progress("Web app scan (OWASP checks)          ", 22, G)
    progress("Container scan (Trivy)               ", 18, G)
    progress("Cloud config audit                   ", 15, G)
    progress("SAST code analysis (Bandit/Semgrep)  ", 20, G)
    progress("AI false-positive reduction          ", 12, M)

    pool = random.sample(VULNS, min(len(VULNS), 7 if env_key == "bank" else 5))
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    print(f"\n  {W}{BOLD}Findings:{NC}")
    for cve, title, sev, cvss, comp, mitre in pool:
        counts[sev] = counts.get(sev, 0) + 1
        col = R+BOLD if sev=="CRITICAL" else Y if sev=="HIGH" else M
        print(f"  {col}[{sev:8s}]{NC}  CVSS {cvss:4.1f}  {cve:<20}  {title}")
        info(f"           Component: {comp}  |  MITRE: {mitre}")
        time.sleep(0.07)
    risk = min(10.0, counts["CRITICAL"]*3.5 + counts["HIGH"]*1.5)
    print(f"\n  Summary  Critical={R}{BOLD}{counts['CRITICAL']}{NC}  High={Y}{counts['HIGH']}{NC}  Medium={M}{counts['MEDIUM']}{NC}  Risk Score={R}{BOLD}{risk:.1f}/10{NC}\n")

def threat_detect():
    section("MODULE 2  REAL-TIME THREAT DETECTION  (AI + MITRE ATT&CK)")
    info("Sources: CloudTrail  Syslog  Network Flows  EDR  SIEM")
    print()
    progress("Ingesting live log streams      ", 20, C)
    progress("ML anomaly scoring (LSTM model) ", 18, C)
    progress("IOC threat intel matching       ", 12, C)
    progress("Event correlation engine        ", 10, C)
    print()
    for title, sev, src, technique, tactic, count in THREATS:
        col = R+BOLD if sev=="CRITICAL" else Y if sev=="HIGH" else M
        t = datetime.now(timezone.utc).strftime("%H:%M:%S")
        print(f"  {col}[{sev:8s}]{NC}  {t}  {title}")
        info(f"           Src: {src:<22}  {technique}  {tactic}")
        if sev == "CRITICAL":
            print(f"           {R}[AUTOMATED RESPONSE TRIGGERED]{NC}")
        time.sleep(0.1)
    print(f"\n  Alerts: {R}{BOLD}3 CRITICAL{NC}  {Y}4 HIGH{NC}  {M}1 MEDIUM{NC}")
    print(f"  Containment: {G}Automated isolation < 90 seconds{NC}\n")

def compliance_check():
    section("MODULE 3  COMPLIANCE AUTOMATION")
    info("Frameworks: PCI-DSS v4.0  |  HIPAA Security Rule  |  CIS Controls v8")
    print()
    total_p = total_f = total_part = 0
    for fw, controls in COMPLIANCE.items():
        print(f"  {W}{BOLD}{fw}{NC}")
        progress(f"  Running {len(controls)} controls  ", 16, B)
        p = f = part = 0
        for ctrl, title, status, evidence in controls:
            icon = "OK" if status=="PASS" else "!!" if status=="FAIL" else "~~"
            col  = G if status=="PASS" else R if status=="FAIL" else Y
            print(f"    {col}[{icon}]{NC} {ctrl:<13} {title:<40}  {col}{status}{NC}")
            info(f"          {evidence}")
            if status=="PASS":    p+=1; total_p+=1
            elif status=="FAIL":  f+=1; total_f+=1
            else:                 part+=1; total_part+=1
            time.sleep(0.05)
        score = int((p + part*0.5) / len(controls) * 100)
        print(f"  Score: {G if score>=75 else Y if score>=55 else R}{score}%{NC}  (Pass={p} Fail={f} Partial={part})\n")
        time.sleep(0.1)
    total_ctrl = total_p + total_f + total_part
    overall = int((total_p + total_part*0.5) / total_ctrl * 100)
    print(f"  {W}{BOLD}Overall Compliance Score: {G if overall>=70 else Y if overall>=50 else R}{BOLD}{overall}%{NC}  across {total_ctrl} controls")
    print(f"  {R}Critical Gaps:{NC} MFA, unpatched CVEs, default credentials, dormant accounts\n")

def incident_response():
    section("MODULE 4  AUTOMATED INCIDENT RESPONSE")
    iid = "INC-" + str(uuid.uuid4())[:8].upper()
    print(f"  {R}{BOLD}[P1 CRITICAL]  Ransomware on 10.0.1.82  |  {iid}  |  {ts()}{NC}\n")
    playbook = [
        ("AUTO", "Network Isolation",       "Host 10.0.1.82 isolated from all VLANs",            G),
        ("AUTO", "Page On-Call Team",       "PagerDuty P1 sent to SOC + CISO",                   G),
        ("AUTO", "Block C2 IPs",            "Firewall rule pushed: blocked 185.220.101.47",       G),
        ("AUTO", "Memory Forensics",        "32 GB RAM dump captured + SHA-256 hash preserved",  G),
        ("AUTO", "Disable IAM Accounts",    "Disabled: svc-deploy, svc-ci, app-runner",          G),
        ("AUTO", "Create JIRA Ticket",      "SEC-4891 opened with full evidence timeline",        G),
        ("AUTO", "Slack/Teams Alert",       "Alert posted to #critical-incidents",                G),
        ("MANUAL","Verify Backup Integrity","Engineering to confirm S3 backup from 2026-04-09",   Y),
        ("MANUAL","GDPR 72h Assessment",    "Legal team assessing breach notification requirement",Y),
    ]
    for mode, name, detail, col in playbook:
        print(f"  {col}[{mode}]{NC}  {name}")
        info(f"          {detail}")
        time.sleep(0.12)
    print(f"\n  {W}{BOLD}Containment Time:{NC} {G}87 seconds{NC} from detection to isolation")
    print(f"  {W}{BOLD}Automated Steps:{NC}  7 / 9 steps completed without human action")
    print(f"  {W}{BOLD}Evidence Sealed:{NC}  32 GB forensic image + 47 log archives\n")

def ai_analysis():
    section("MODULE 5  AI THREAT INTELLIGENCE  (Self-Hosted LLM)")
    info("Model: Llama 3.1 70B via Ollama  |  Endpoint: http://localhost:11434  |  Air-gapped ready")
    print()
    print(f"  {C}[LLM ANALYSIS]{NC}  Ransomware event on 10.0.1.82")
    progress("  Analysing indicators  ", 16, M)
    for line in [
        "Threat Actor: LockBit 3.0 affiliate group (confidence: 87%)",
        "Attack Chain: T1190 InitialAccess -> T1547 Persistence -> T1562 DefenseEvasion",
        "             -> T1550.002 LateralMovement -> T1048 Exfiltration -> T1486 Impact",
        "Dwell Time:  Estimated 4-7 days (VSS deletion seen 3 days prior)",
        "Impact:      HIGH -- production database encrypted, ~14 TB at risk",
        "Recommended: Restore from clean S3 backup taken 2026-04-09 02:15 UTC",
    ]:
        info(f"  {line}")
        time.sleep(0.09)

    print(f"\n  {C}[LLM ANALYSIS]{NC}  DNS exfiltration from 10.1.0.10 (Azure)")
    progress("  Analysing DNS patterns", 14, M)
    for line in [
        "Technique: DNS tunnelling -- base64-encoded subdomains, entropy > 4.2 bits",
        "Volume:    ~240 MB exfiltrated over 6 hours",
        "Dest:      attacker-infra.onion-proxy.net (known APT29 infrastructure)",
        "Confidence: 91%  |  False-Positive Likelihood: 4%",
        "Fix:       Block DNS labels > 63 chars; deploy DNS filtering (Pi-hole / RPZ)",
    ]:
        info(f"  {line}")
        time.sleep(0.09)

def summary():
    banner("DEMO COMPLETE  --  EXECUTIVE SUMMARY", colour=G)
    print(f"""
  {W}{BOLD}Completed:{NC}   {ts()}
  {W}{BOLD}Scope:{NC}       Amazon AWS  |  Microsoft Azure / Avahi AI  |  Banking / SWIFT

  {W}{BOLD}VULNERABILITIES DETECTED{NC}
    {R}{BOLD}CRITICAL{NC}  4   Redis exposed, SQL injection, XZ backdoor, ConnectWise RCE
    {Y}HIGH    {NC}  3   MFA gaps, S3 public bucket, lateral movement path
    {M}MEDIUM  {NC}  2   Missing HSTS, container root privilege

  {W}{BOLD}THREATS DETECTED{NC}
    {R}{BOLD}CRITICAL{NC}  3   Ransomware, C2 beacon (Cobalt Strike), Pass-the-Hash
    {Y}HIGH    {NC}  4   Brute force, DNS tunnelling, priv escalation, rogue S3 download
    {M}MEDIUM  {NC}  1   Cryptomining (XMRig)

  {W}{BOLD}COMPLIANCE SCORES{NC}
    {R}PCI-DSS v4.0    {NC}68%   Failures: MFA, patches, default credentials
    {Y}HIPAA           {NC}82%   Failure:  shared service accounts
    {R}CIS Controls v8 {NC}61%   Failures: MFA, dormant accounts, vuln SLA

  {W}{BOLD}AUTOMATED RESPONSE{NC}
    {G}  Containment:    87 seconds (detection to network isolation){NC}
    {G}  Notifications:  PagerDuty P1 + Slack + JIRA SEC-4891 created{NC}
    {G}  Evidence:       32 GB forensic image sealed and preserved{NC}

  {W}{BOLD}AI ENGINE{NC}
    {G}  Llama 3.1 70B running locally via Ollama{NC}
    {G}  0 bytes of security data sent to any external service{NC}
    {G}  Threat attribution confidence: 87-91%{NC}

  {DIM}---------------------------------------------------------------------{NC}
  {W}{BOLD}IMMEDIATE ACTIONS REQUIRED{NC}
    1. Patch / isolate 4 critical CVEs within 24 hours
    2. Enforce MFA on all service and admin accounts NOW
    3. Rotate ALL credentials on compromised systems
    4. Initiate forensic investigation and GDPR breach assessment
    5. Remediate CIS baseline gaps to reach 90%%+ compliance score

  {C}Dashboard : https://localhost:8443
  API Docs  : https://localhost:8443/api/docs
  Grafana   : https://localhost:3000{NC}
    """)

# ── MAIN ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        random.seed(42)
        startup()
        for env in ["aws", "azure", "bank"]:
            vuln_scan(env)
            time.sleep(0.1)
        threat_detect()
        compliance_check()
        incident_response()
        ai_analysis()
        summary()
    except KeyboardInterrupt:
        print(f"\n\n{Y}Demo interrupted.{NC}")
