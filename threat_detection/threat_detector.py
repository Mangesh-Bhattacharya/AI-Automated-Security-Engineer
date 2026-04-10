"""
AI Automated Security Engineer - Real-Time Threat Detection Engine

Combines rule-based detection (YARA, Sigma), ML anomaly detection,
and LLM-assisted threat analysis to provide real-time threat detection
across logs, network traffic, and cloud telemetry.

Supports: MITRE ATT&CK mapping, UEBA, lateral movement detection,
insider threat analysis, and automated threat hunting.
"""

import asyncio
import hashlib
import json
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import numpy as np
import structlog
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ai_engine.llm_client import LLMClient
from ai_engine.anomaly_detector import AnomalyDetector
from core.config import settings

logger = structlog.get_logger("aase.threat.detector")


# ─────────────────────────────────────────────
# Threat Models
# ─────────────────────────────────────────────

class ThreatSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatCategory(str, Enum):
    INTRUSION = "intrusion"
    MALWARE = "malware"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CREDENTIAL_THEFT = "credential_theft"
    RANSOMWARE = "ransomware"
    INSIDER_THREAT = "insider_threat"
    APT = "advanced_persistent_threat"
    DDOS = "denial_of_service"
    SUPPLY_CHAIN = "supply_chain"
    ZERO_DAY = "zero_day"
    PHISHING = "phishing"
    ANOMALY = "behavioral_anomaly"


class ThreatStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class ThreatEvent:
    """Represents a detected threat event."""
    event_id: str
    title: str
    description: str
    severity: ThreatSeverity
    category: ThreatCategory
    confidence: float  # 0.0 - 1.0
    
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_user: Optional[str] = None
    affected_hosts: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    raw_events: List[Dict[str, Any]] = field(default_factory=list)
    
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_count: int = 1
    
    remediation_steps: List[str] = field(default_factory=list)
    status: ThreatStatus = ThreatStatus.OPEN
    
    detection_method: str = "rule_based"
    rule_id: Optional[str] = None
    risk_score: float = 0.0


@dataclass
class LogEntry:
    """Normalized log entry from any source."""
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    message: str
    host: str = ""
    user: str = ""
    source_ip: str = ""
    dest_ip: str = ""
    process: str = ""
    file_path: str = ""
    command: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)


# ─────────────────────────────────────────────
# Detection Rules
# ─────────────────────────────────────────────

DETECTION_RULES = [
    {
        "id": "RULE-001",
        "name": "Brute Force Login Detection",
        "category": ThreatCategory.CREDENTIAL_THEFT,
        "severity": ThreatSeverity.HIGH,
        "description": "Multiple failed login attempts detected",
        "condition": "failed_logins > 10 within 5 minutes from same IP",
        "mitre_techniques": ["T1110", "T1110.001"],
        "mitre_tactics": ["TA0006"],
        "remediation": ["Block source IP", "Enable MFA", "Alert account owner"],
    },
    {
        "id": "RULE-002",
        "name": "Privilege Escalation via Sudo",
        "category": ThreatCategory.PRIVILEGE_ESCALATION,
        "severity": ThreatSeverity.HIGH,
        "description": "Unexpected sudo command execution detected",
        "mitre_techniques": ["T1548", "T1548.003"],
        "mitre_tactics": ["TA0004"],
        "remediation": ["Investigate user activity", "Review sudo policy"],
    },
    {
        "id": "RULE-003",
        "name": "Data Exfiltration via DNS",
        "category": ThreatCategory.DATA_EXFILTRATION,
        "severity": ThreatSeverity.CRITICAL,
        "description": "Unusually long or high-frequency DNS queries detected",
        "mitre_techniques": ["T1048.003", "T1071.004"],
        "mitre_tactics": ["TA0010"],
        "remediation": ["Block suspicious DNS queries", "Inspect endpoint", "Isolate host"],
    },
    {
        "id": "RULE-004",
        "name": "Lateral Movement - Pass the Hash",
        "category": ThreatCategory.LATERAL_MOVEMENT,
        "severity": ThreatSeverity.CRITICAL,
        "description": "Pass-the-hash attack pattern detected",
        "mitre_techniques": ["T1550.002"],
        "mitre_tactics": ["TA0008"],
        "remediation": ["Isolate affected systems", "Reset NTLM credentials", "Enable Credential Guard"],
    },
    {
        "id": "RULE-005",
        "name": "Ransomware File Encryption Activity",
        "category": ThreatCategory.RANSOMWARE,
        "severity": ThreatSeverity.CRITICAL,
        "description": "Mass file renaming/encryption pattern detected",
        "mitre_techniques": ["T1486"],
        "mitre_tactics": ["TA0040"],
        "remediation": ["IMMEDIATELY isolate host from network", "Preserve forensic evidence", "Execute ransomware response playbook"],
    },
    {
        "id": "RULE-006",
        "name": "Cloud Credential Theft - Metadata Service",
        "category": ThreatCategory.CREDENTIAL_THEFT,
        "severity": ThreatSeverity.HIGH,
        "description": "IMDS v1 metadata service access from unexpected source",
        "mitre_techniques": ["T1552.005"],
        "mitre_tactics": ["TA0006"],
        "remediation": ["Enforce IMDSv2", "Review IAM roles", "Rotate credentials"],
    },
    {
        "id": "RULE-007",
        "name": "Cryptomining Process Detection",
        "category": ThreatCategory.MALWARE,
        "severity": ThreatSeverity.MEDIUM,
        "description": "Cryptocurrency mining process or connection detected",
        "mitre_techniques": ["T1496"],
        "mitre_tactics": ["TA0040"],
        "remediation": ["Terminate malicious process", "Scan for malware", "Review deployment"],
    },
    {
        "id": "RULE-008",
        "name": "Command & Control Beacon Detection",
        "category": ThreatCategory.MALWARE,
        "severity": ThreatSeverity.CRITICAL,
        "description": "Periodic beacon pattern to external C2 server detected",
        "mitre_techniques": ["T1071", "T1071.001", "T1573"],
        "mitre_tactics": ["TA0011"],
        "remediation": ["Block C2 IP/domain", "Isolate infected host", "Full malware analysis"],
    },
]


# ─────────────────────────────────────────────
# Threat Detection Engine
# ─────────────────────────────────────────────

class ThreatDetector:
    """
    Real-time AI-powered threat detection engine.
    
    Detection methods:
    1. Rule-based (Sigma-style YAML rules)
    2. ML anomaly detection (Isolation Forest + LSTM)
    3. Behavioral analytics (UEBA)
    4. LLM-assisted threat hunting and correlation
    5. Threat intelligence matching (IOC lookup)
    """

    def __init__(self):
        self.llm_client = LLMClient()
        self.anomaly_detector = AnomalyDetector()
        self.rules = DETECTION_RULES
        
        # Event tracking windows for correlation
        self._failed_login_window: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=1000)
        )
        self._dns_query_window: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=100)
        )
        self._network_connections: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=500)
        )
        self._file_events: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=500)
        )
        
        # IOC cache
        self._malicious_ips: Set[str] = set()
        self._malicious_domains: Set[str] = set()
        self._malicious_hashes: Set[str] = set()
        
        # Alert callbacks
        self._alert_callbacks: List[Callable] = []
        
        # Correlation state
        self._active_threats: Dict[str, ThreatEvent] = {}
        
        logger.info("ThreatDetector initialized with %d rules", len(self.rules))

    async def analyze_log_entry(self, log: LogEntry) -> List[ThreatEvent]:
        """Analyze a single log entry for threats."""
        threats = []

        # Rule-based detection
        rule_threats = await self._apply_detection_rules(log)
        threats.extend(rule_threats)

        # Anomaly detection
        anomaly_threats = await self._detect_anomalies(log)
        threats.extend(anomaly_threats)

        # IOC matching
        ioc_threats = await self._match_iocs(log)
        threats.extend(ioc_threats)

        # Correlate with existing threats
        for threat in threats:
            await self._correlate_threat(threat)
            await self._notify_callbacks(threat)

        return threats

    async def analyze_batch(
        self, logs: List[LogEntry], use_ai_triage: bool = True
    ) -> List[ThreatEvent]:
        """Analyze a batch of log entries."""
        all_threats = []

        tasks = [self.analyze_log_entry(log) for log in logs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                all_threats.extend(result)

        if use_ai_triage and all_threats:
            all_threats = await self._ai_triage_threats(all_threats)

        return all_threats

    # ─── Rule-Based Detection ───────────────────────────────────────────────

    async def _apply_detection_rules(self, log: LogEntry) -> List[ThreatEvent]:
        """Apply all detection rules to a log entry."""
        threats = []

        # Brute Force Detection
        if self._is_failed_login(log):
            self._failed_login_window[log.source_ip].append(log.timestamp)
            threat = self._check_brute_force(log)
            if threat:
                threats.append(threat)

        # Privilege Escalation
        if self._is_sudo_escalation(log):
            threat = self._create_threat_event(
                log=log,
                rule_id="RULE-002",
                title="Privilege Escalation: Unexpected Sudo Command",
                description=f"User {log.user} executed sudo command: {log.command}",
                severity=ThreatSeverity.HIGH,
                category=ThreatCategory.PRIVILEGE_ESCALATION,
                confidence=0.80,
                mitre_techniques=["T1548", "T1548.003"],
            )
            threats.append(threat)

        # DNS Exfiltration
        if self._is_suspicious_dns(log):
            threat = self._check_dns_exfiltration(log)
            if threat:
                threats.append(threat)

        # Ransomware indicators
        if self._is_ransomware_indicator(log):
            threat = self._create_threat_event(
                log=log,
                rule_id="RULE-005",
                title="CRITICAL: Ransomware Activity Detected",
                description=f"Mass file encryption/renaming detected on {log.host}",
                severity=ThreatSeverity.CRITICAL,
                category=ThreatCategory.RANSOMWARE,
                confidence=0.92,
                mitre_techniques=["T1486"],
                remediation_steps=[
                    "IMMEDIATELY isolate host from network",
                    "Preserve forensic evidence",
                    "Execute ransomware response playbook",
                    "Contact incident response team",
                ],
            )
            threats.append(threat)

        # Cryptomining
        if self._is_cryptomining(log):
            threat = self._create_threat_event(
                log=log,
                rule_id="RULE-007",
                title="Cryptomining Process Detected",
                description=f"Cryptomining process detected: {log.process}",
                severity=ThreatSeverity.MEDIUM,
                category=ThreatCategory.MALWARE,
                confidence=0.75,
                mitre_techniques=["T1496"],
            )
            threats.append(threat)

        return threats

    def _is_failed_login(self, log: LogEntry) -> bool:
        """Check if log entry represents a failed login."""
        failed_indicators = [
            "failed password", "authentication failure", "invalid credentials",
            "login failed", "unauthorized", "access denied", "invalid user",
        ]
        return any(ind in log.message.lower() for ind in failed_indicators)

    def _check_brute_force(self, log: LogEntry) -> Optional[ThreatEvent]:
        """Check for brute force attack pattern."""
        window = self._failed_login_window[log.source_ip]
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=5)
        
        recent_failures = sum(1 for ts in window if ts >= cutoff)
        
        if recent_failures >= 10:
            return self._create_threat_event(
                log=log,
                rule_id="RULE-001",
                title=f"Brute Force Attack from {log.source_ip}",
                description=f"{recent_failures} failed login attempts in 5 minutes from {log.source_ip}",
                severity=ThreatSeverity.HIGH,
                category=ThreatCategory.CREDENTIAL_THEFT,
                confidence=min(0.95, 0.5 + (recent_failures * 0.02)),
                mitre_techniques=["T1110", "T1110.001"],
                remediation_steps=[
                    f"Block IP {log.source_ip} at firewall",
                    "Enable account lockout policy",
                    "Enforce MFA for affected accounts",
                    "Review authentication logs",
                ],
            )
        return None

    def _is_sudo_escalation(self, log: LogEntry) -> bool:
        """Detect sudo privilege escalation."""
        sudo_patterns = [r"sudo:\s+\w+", r"COMMAND=", r"sudo.*-i\b", r"sudo.*su"]
        suspicious_commands = ["bash", "sh", "python", "perl", "ruby", "nc", "netcat"]
        
        has_sudo = any(re.search(p, log.message, re.IGNORECASE) for p in sudo_patterns)
        has_suspicious = any(cmd in log.command.lower() for cmd in suspicious_commands)
        
        return has_sudo and (has_suspicious or log.user in ["nobody", "www-data"])

    def _is_suspicious_dns(self, log: LogEntry) -> bool:
        """Detect suspicious DNS activity."""
        if log.event_type not in ("dns_query", "dns", "network"):
            return False
        
        # Check for long subdomain (data exfiltration via DNS)
        domain_match = re.search(r"\b([a-z0-9.-]{50,})\.", log.message, re.IGNORECASE)
        
        # High-entropy subdomain
        if domain_match:
            subdomain = domain_match.group(1)
            entropy = self._calculate_entropy(subdomain)
            if entropy > 4.0:
                return True
        
        return False

    def _check_dns_exfiltration(self, log: LogEntry) -> Optional[ThreatEvent]:
        """Check for DNS tunneling/exfiltration."""
        self._dns_query_window[log.host].append(log.timestamp)
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=1)
        
        recent_dns = sum(1 for ts in self._dns_query_window[log.host] if ts >= cutoff)
        
        if recent_dns > 50:  # >50 DNS queries/minute
            return self._create_threat_event(
                log=log,
                rule_id="RULE-003",
                title=f"Possible DNS Exfiltration from {log.host}",
                description=f"High-frequency DNS queries ({recent_dns}/min) with high-entropy subdomains",
                severity=ThreatSeverity.HIGH,
                category=ThreatCategory.DATA_EXFILTRATION,
                confidence=0.72,
                mitre_techniques=["T1048.003", "T1071.004"],
                remediation_steps=[
                    "Block DNS queries to suspicious domains",
                    "Inspect endpoint for malware",
                    "Review data access logs",
                    "Implement DNS filtering",
                ],
            )
        return None

    def _is_ransomware_indicator(self, log: LogEntry) -> bool:
        """Detect ransomware activity patterns."""
        ransomware_extensions = [
            ".encrypted", ".locked", ".crypto", ".cerber", ".locky",
            ".zepto", ".odin", ".aesir", ".thor", ".zzzzz",
        ]
        shadow_delete = "vssadmin delete shadows"
        recovery_disable = "bcdedit.*recoveryenabled.*no"
        
        has_ransom_ext = any(ext in log.message.lower() for ext in ransomware_extensions)
        has_shadow_delete = shadow_delete in log.command.lower()
        has_recovery_disable = bool(re.search(recovery_disable, log.command, re.IGNORECASE))
        
        return has_ransom_ext or has_shadow_delete or has_recovery_disable

    def _is_cryptomining(self, log: LogEntry) -> bool:
        """Detect cryptocurrency mining."""
        mining_processes = ["xmrig", "cgminer", "bfgminer", "cpuminer", "minerd"]
        mining_pools = ["pool.minexmr.com", "xmrpool.net", "nanopool.org", "2miners.com"]
        
        has_mining_proc = any(p in log.process.lower() for p in mining_processes)
        has_mining_pool = any(p in log.message.lower() for p in mining_pools)
        high_cpu_mining = "stratum+tcp" in log.message.lower()
        
        return has_mining_proc or has_mining_pool or high_cpu_mining

    # ─── ML Anomaly Detection ───────────────────────────────────────────────

    async def _detect_anomalies(self, log: LogEntry) -> List[ThreatEvent]:
        """Use ML models to detect behavioral anomalies."""
        threats = []
        
        try:
            # Extract features from log entry
            features = self._extract_log_features(log)
            
            # Get anomaly score from ML model
            anomaly_score = await self.anomaly_detector.score(features)
            
            if anomaly_score > settings.ANOMALY_THRESHOLD:  # default 0.85
                threat = self._create_threat_event(
                    log=log,
                    rule_id="ML-ANOMALY",
                    title=f"ML Anomaly Detected: {log.event_type}",
                    description=f"Unusual behavior pattern detected (anomaly score: {anomaly_score:.2f})",
                    severity=ThreatSeverity.MEDIUM if anomaly_score < 0.95 else ThreatSeverity.HIGH,
                    category=ThreatCategory.ANOMALY,
                    confidence=anomaly_score,
                    detection_method="ml_anomaly",
                )
                threats.append(threat)
        except Exception as e:
            logger.debug("Anomaly detection error", error=str(e))
        
        return threats

    def _extract_log_features(self, log: LogEntry) -> List[float]:
        """Extract numerical features from a log entry for ML model."""
        now = datetime.now(timezone.utc)
        hour = log.timestamp.hour
        
        return [
            float(hour),
            float(log.timestamp.weekday()),
            float(len(log.message)),
            float(len(log.command)),
            float(len(log.source_ip.split(".")[0]) if log.source_ip else 0),
            float(self._calculate_entropy(log.message)),
            float(1 if log.user == "root" else 0),
            float(1 if log.severity in ("CRITICAL", "ERROR") else 0),
        ]

    # ─── IOC Matching ───────────────────────────────────────────────────────

    async def _match_iocs(self, log: LogEntry) -> List[ThreatEvent]:
        """Check log entry against known Indicators of Compromise."""
        threats = []

        # IP-based IOC
        if log.source_ip and log.source_ip in self._malicious_ips:
            threats.append(self._create_threat_event(
                log=log,
                rule_id="IOC-IP",
                title=f"Known Malicious IP: {log.source_ip}",
                description=f"Connection from IP address found in threat intelligence feed",
                severity=ThreatSeverity.HIGH,
                category=ThreatCategory.INTRUSION,
                confidence=0.90,
                mitre_techniques=["T1071"],
                detection_method="threat_intelligence",
            ))

        # Domain IOC
        domain_match = re.search(r"(?:https?://)?([a-zA-Z0-9.-]+.[a-zA-Z]{2,})", log.message)
        if domain_match:
            domain = domain_match.group(1).lower()
            if domain in self._malicious_domains:
                threats.append(self._create_threat_event(
                    log=log,
                    rule_id="IOC-DOMAIN",
                    title=f"Known Malicious Domain: {domain}",
                    description=f"Communication with known malicious domain detected",
                    severity=ThreatSeverity.HIGH,
                    category=ThreatCategory.MALWARE,
                    confidence=0.88,
                    mitre_techniques=["T1071.001"],
                    detection_method="threat_intelligence",
                ))

        # File hash IOC
        hash_match = re.search(r"\b[a-f0-9]{64}\b", log.message, re.IGNORECASE)
        if hash_match:
            file_hash = hash_match.group(0).lower()
            if file_hash in self._malicious_hashes:
                threats.append(self._create_threat_event(
                    log=log,
                    rule_id="IOC-HASH",
                    title=f"Malicious File Hash Detected",
                    description=f"Known malicious file hash found: {file_hash[:16]}...",
                    severity=ThreatSeverity.CRITICAL,
                    category=ThreatCategory.MALWARE,
                    confidence=0.95,
                    mitre_techniques=["T1204"],
                    detection_method="threat_intelligence",
                ))

        return threats

    # ─── AI-Assisted Threat Triage ──────────────────────────────────────────

    async def _ai_triage_threats(
        self, threats: List[ThreatEvent]
    ) -> List[ThreatEvent]:
        """Use LLM to triage and enrich threat events."""
        if not threats or not settings.AI_TRIAGE_ENABLED:
            return threats

        # Only triage high/critical events to conserve LLM resources
        critical_threats = [
            t for t in threats
            if t.severity in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH)
        ]

        for threat in critical_threats[:5]:  # Limit to 5 per batch
            try:
                prompt = f"""You are an expert threat analyst. Analyze this security threat:

Title: {threat.title}
Category: {threat.category.value}
Severity: {threat.severity.value}
Confidence: {threat.confidence}
Description: {threat.description}
MITRE Techniques: {threat.mitre_techniques}
Source IP: {threat.source_ip}
Affected Hosts: {threat.affected_hosts}

Provide:
1. Threat assessment and likely attack chain
2. False positive likelihood (0.0-1.0)
3. Additional MITRE techniques that may be involved
4. Top 5 immediate remediation steps
5. Related threat actor groups if applicable

Respond in JSON."""

                response = await self.llm_client.chat(
                    prompt=prompt,
                    system="You are a senior threat intelligence analyst. Respond only with valid JSON.",
                    max_tokens=600,
                )
                
                data = json.loads(response)
                
                fp_likelihood = float(data.get("false_positive_likelihood", 0.1))
                if fp_likelihood > 0.8:
                    threat.status = ThreatStatus.FALSE_POSITIVE
                    continue
                
                threat.confidence = min(1.0, threat.confidence * (1.0 - fp_likelihood * 0.5))
                
                extra_techniques = data.get("additional_mitre_techniques", [])
                threat.mitre_techniques.extend(extra_techniques)
                threat.mitre_techniques = list(set(threat.mitre_techniques))
                
                if data.get("remediation_steps"):
                    threat.remediation_steps = data["remediation_steps"]

                threat.risk_score = self._calculate_risk_score(threat)

            except Exception as e:
                logger.debug("AI triage failed for threat", error=str(e))

        return threats

    # ─── Threat Correlation ─────────────────────────────────────────────────

    async def _correlate_threat(self, threat: ThreatEvent) -> None:
        """Correlate new threat with existing active threats."""
        for existing_id, existing in list(self._active_threats.items()):
            if (
                threat.category == existing.category
                and threat.source_ip == existing.source_ip
                and (datetime.now(timezone.utc) - existing.last_seen) < timedelta(hours=1)
            ):
                existing.event_count += 1
                existing.last_seen = datetime.now(timezone.utc)
                existing.raw_events.extend(threat.raw_events)
                if threat.confidence > existing.confidence:
                    existing.confidence = threat.confidence
                return

        # New threat
        self._active_threats[threat.event_id] = threat

    # ─── IOC Management ─────────────────────────────────────────────────────

    async def load_threat_intelligence(
        self,
        malicious_ips: List[str] = None,
        malicious_domains: List[str] = None,
        malicious_hashes: List[str] = None,
    ) -> None:
        """Load threat intelligence feeds into memory."""
        if malicious_ips:
            self._malicious_ips.update(malicious_ips)
        if malicious_domains:
            self._malicious_domains.update(malicious_domains)
        if malicious_hashes:
            self._malicious_hashes.update(malicious_hashes)

        logger.info(
            "Threat intelligence loaded",
            ips=len(self._malicious_ips),
            domains=len(self._malicious_domains),
            hashes=len(self._malicious_hashes),
        )

    # ─── Alert Callbacks ────────────────────────────────────────────────────

    def register_callback(self, callback: Callable) -> None:
        """Register a callback for threat alerts."""
        self._alert_callbacks.append(callback)

    async def _notify_callbacks(self, threat: ThreatEvent) -> None:
        """Notify registered callbacks of a new threat."""
        if threat.severity in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH):
            for callback in self._alert_callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(threat)
                    else:
                        callback(threat)
                except Exception as e:
                    logger.error("Alert callback error", error=str(e))

    # ─── Utility Methods ────────────────────────────────────────────────────

    def _create_threat_event(
        self,
        log: LogEntry,
        rule_id: str,
        title: str,
        description: str,
        severity: ThreatSeverity,
        category: ThreatCategory,
        confidence: float,
        mitre_techniques: List[str] = None,
        mitre_tactics: List[str] = None,
        remediation_steps: List[str] = None,
        detection_method: str = "rule_based",
    ) -> ThreatEvent:
        """Create a standardized ThreatEvent."""
        import uuid
        
        rule_data = next((r for r in self.rules if r["id"] == rule_id), {})
        
        return ThreatEvent(
            event_id=str(uuid.uuid4()),
            title=title,
            description=description,
            severity=severity,
            category=category,
            confidence=confidence,
            source_ip=log.source_ip,
            dest_ip=log.dest_ip,
            source_user=log.user,
            affected_hosts=[log.host] if log.host else [],
            mitre_tactics=mitre_tactics or rule_data.get("mitre_tactics", []),
            mitre_techniques=mitre_techniques or rule_data.get("mitre_techniques", []),
            indicators=[{
                "type": "log_entry",
                "value": log.message[:200],
                "source": log.source,
            }],
            raw_events=[log.raw],
            remediation_steps=remediation_steps or rule_data.get("remediation", []),
            detection_method=detection_method,
            rule_id=rule_id,
            risk_score=self._calculate_risk_score_simple(severity, confidence),
        )

    def _calculate_risk_score(self, threat: ThreatEvent) -> float:
        """Calculate risk score for a threat event (0-100)."""
        severity_weights = {
            ThreatSeverity.CRITICAL: 100,
            ThreatSeverity.HIGH: 75,
            ThreatSeverity.MEDIUM: 50,
            ThreatSeverity.LOW: 25,
            ThreatSeverity.INFO: 5,
        }
        base = severity_weights.get(threat.severity, 50)
        return base * threat.confidence

    def _calculate_risk_score_simple(
        self, severity: ThreatSeverity, confidence: float
    ) -> float:
        weights = {
            ThreatSeverity.CRITICAL: 100,
            ThreatSeverity.HIGH: 75,
            ThreatSeverity.MEDIUM: 50,
            ThreatSeverity.LOW: 25,
            ThreatSeverity.INFO: 5,
        }
        return weights.get(severity, 50) * confidence

    @staticmethod
    def _calculate_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        freq = defaultdict(int)
        for c in data:
            freq[c] += 1
        entropy = 0.0
        n = len(data)
        for count in freq.values():
            p = count / n
            if p > 0:
                import math
                entropy -= p * math.log2(p)
        return entropy

    def get_active_threats(
        self,
        severity_filter: Optional[ThreatSeverity] = None,
    ) -> List[ThreatEvent]:
        """Get list of active threats, optionally filtered by severity."""
        threats = list(self._active_threats.values())
        if severity_filter:
            threats = [t for t in threats if t.severity == severity_filter]
        return sorted(threats, key=lambda t: t.risk_score, reverse=True)


# ─────────────────────────────────────────────
# Global Instance
# ─────────────────────────────────────────────

_detector: Optional[ThreatDetector] = None


def get_threat_detector() -> ThreatDetector:
    global _detector
    if _detector is None:
        _detector = ThreatDetector()
    return _detector
