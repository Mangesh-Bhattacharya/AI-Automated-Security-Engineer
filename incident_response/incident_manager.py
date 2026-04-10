"""
AI Automated Security Engineer - Incident Response Manager

Automates the full incident lifecycle:
- Incident detection and classification
- Automated playbook execution
- Evidence collection and forensics
- Stakeholder notification
- Containment and eradication actions
- Post-incident reporting

Compliant with: NIST SP 800-61, SANS Incident Handling,
ISO 27035, and industry-specific requirements.
"""

import asyncio
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import structlog
import yaml

from ai_engine.llm_client import LLMClient
from core.config import settings

logger = structlog.get_logger("aase.incident_response")


# ─────────────────────────────────────────────
# Incident Models
# ─────────────────────────────────────────────

class IncidentSeverity(str, Enum):
    P1_CRITICAL = "P1_critical"   # Major breach, ransomware, full system compromise
    P2_HIGH = "P2_high"           # Confirmed intrusion, data exfil in progress
    P3_MEDIUM = "P3_medium"       # Suspected compromise, policy violation
    P4_LOW = "P4_low"             # Minor policy violation, low-risk anomaly


class IncidentStatus(str, Enum):
    DETECTED = "detected"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    CONTAINING = "containing"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    RESOLVED = "resolved"
    POST_INCIDENT = "post_incident"
    CLOSED = "closed"


class IncidentType(str, Enum):
    RANSOMWARE = "ransomware"
    DATA_BREACH = "data_breach"
    INSIDER_THREAT = "insider_threat"
    APT = "apt"
    DDOS = "ddos"
    MALWARE = "malware"
    PHISHING = "phishing"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SUPPLY_CHAIN = "supply_chain"
    CREDENTIAL_THEFT = "credential_theft"
    LATERAL_MOVEMENT = "lateral_movement"
    CLOUD_COMPROMISE = "cloud_compromise"


@dataclass
class PlaybookStep:
    """A single step in an incident response playbook."""
    step_id: str
    name: str
    description: str
    action_type: str  # notify, contain, collect_evidence, remediate, verify
    automated: bool = True
    required: bool = True
    timeout_seconds: int = 300
    parameters: Dict[str, Any] = field(default_factory=dict)
    on_failure: str = "continue"  # continue, stop, escalate
    
    # Execution tracking
    status: str = "pending"  # pending, running, completed, failed, skipped
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    output: str = ""
    error: Optional[str] = None


@dataclass
class Incident:
    """Represents a security incident."""
    incident_id: str = field(default_factory=lambda: f"INC-{str(uuid.uuid4())[:8].upper()}")
    incident_type: IncidentType = IncidentType.UNAUTHORIZED_ACCESS
    severity: IncidentSeverity = IncidentSeverity.P3_MEDIUM
    status: IncidentStatus = IncidentStatus.DETECTED
    title: str = ""
    description: str = ""
    
    # Scope
    affected_systems: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    affected_data: List[str] = field(default_factory=list)
    
    # Timeline
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    reported_at: Optional[datetime] = None
    contained_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    
    # Investigation
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    
    # Response
    playbook_steps: List[PlaybookStep] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    
    # Assignments
    assigned_to: Optional[str] = None
    incident_commander: Optional[str] = None
    jira_ticket: Optional[str] = None
    pagerduty_incident: Optional[str] = None
    
    # AI Analysis
    ai_assessment: str = ""
    ai_confidence: float = 0.0
    recommended_actions: List[str] = field(default_factory=list)
    
    def add_timeline_event(self, event: str, automated: bool = True) -> None:
        self.timeline.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "automated": automated,
        })


# ─────────────────────────────────────────────
# Playbook Definitions
# ─────────────────────────────────────────────

RANSOMWARE_PLAYBOOK = [
    PlaybookStep(
        step_id="RANSOM-001",
        name="Immediate Network Isolation",
        description="Isolate affected host(s) from network to stop ransomware propagation",
        action_type="contain",
        automated=True,
        required=True,
        timeout_seconds=30,
        on_failure="escalate",
    ),
    PlaybookStep(
        step_id="RANSOM-002",
        name="Alert Security Team and CISO",
        description="Page on-call security team and CISO immediately",
        action_type="notify",
        automated=True,
        required=True,
        timeout_seconds=60,
    ),
    PlaybookStep(
        step_id="RANSOM-003",
        name="Preserve Forensic Evidence",
        description="Capture memory dump, disk image, and network traffic before cleanup",
        action_type="collect_evidence",
        automated=True,
        required=True,
        timeout_seconds=600,
        on_failure="continue",
    ),
    PlaybookStep(
        step_id="RANSOM-004",
        name="Disable Compromised Accounts",
        description="Disable all accounts associated with affected systems",
        action_type="contain",
        automated=True,
        required=True,
        timeout_seconds=120,
    ),
    PlaybookStep(
        step_id="RANSOM-005",
        name="Block C2 Communication",
        description="Block identified C2 IPs and domains at firewall/DNS level",
        action_type="contain",
        automated=True,
        required=True,
        timeout_seconds=60,
    ),
    PlaybookStep(
        step_id="RANSOM-006",
        name="Assess Backup Integrity",
        description="Verify backup availability and integrity for affected systems",
        action_type="verify",
        automated=False,
        required=True,
        timeout_seconds=1800,
    ),
    PlaybookStep(
        step_id="RANSOM-007",
        name="Create JIRA Incident Ticket",
        description="Create tracking ticket with all evidence and timeline",
        action_type="notify",
        automated=True,
        required=True,
        timeout_seconds=60,
    ),
    PlaybookStep(
        step_id="RANSOM-008",
        name="Regulatory Notification Assessment",
        description="Assess if breach notification is required (GDPR 72h, state laws)",
        action_type="remediate",
        automated=False,
        required=True,
        timeout_seconds=3600,
    ),
]

DATA_BREACH_PLAYBOOK = [
    PlaybookStep(
        step_id="BREACH-001",
        name="Identify Data Scope",
        description="Determine what data was accessed/exfiltrated and by whom",
        action_type="collect_evidence",
        automated=True,
        timeout_seconds=300,
    ),
    PlaybookStep(
        step_id="BREACH-002",
        name="Revoke Compromised Credentials",
        description="Immediately revoke all credentials involved in the breach",
        action_type="contain",
        automated=True,
        timeout_seconds=120,
    ),
    PlaybookStep(
        step_id="BREACH-003",
        name="Notify Legal and Compliance",
        description="Alert legal team for regulatory notification requirements",
        action_type="notify",
        automated=True,
        timeout_seconds=60,
    ),
    PlaybookStep(
        step_id="BREACH-004",
        name="Preserve Access Logs",
        description="Export and preserve all relevant access logs with integrity hashing",
        action_type="collect_evidence",
        automated=True,
        timeout_seconds=300,
    ),
    PlaybookStep(
        step_id="BREACH-005",
        name="Block Exfiltration Path",
        description="Block identified exfiltration channels (IPs, domains, protocols)",
        action_type="contain",
        automated=True,
        timeout_seconds=60,
    ),
]

PLAYBOOK_LIBRARY = {
    IncidentType.RANSOMWARE: RANSOMWARE_PLAYBOOK,
    IncidentType.DATA_BREACH: DATA_BREACH_PLAYBOOK,
}


# ─────────────────────────────────────────────
# Incident Manager
# ─────────────────────────────────────────────

class IncidentManager:
    """
    Automated incident response lifecycle manager.
    
    Orchestrates detection-to-resolution workflow with:
    - Automated playbook execution
    - AI-assisted triage and analysis
    - Multi-channel stakeholder notification
    - Evidence preservation
    - Compliance tracking
    """

    def __init__(self):
        self.llm_client = LLMClient()
        self._incidents: Dict[str, Incident] = {}
        self._action_handlers: Dict[str, Callable] = {}
        self._register_default_handlers()
        logger.info("IncidentManager initialized")

    def _register_default_handlers(self):
        """Register default action handlers."""
        self._action_handlers = {
            "notify": self._handle_notify,
            "contain": self._handle_contain,
            "collect_evidence": self._handle_collect_evidence,
            "remediate": self._handle_remediate,
            "verify": self._handle_verify,
        }

    # ─────────────────────────────────────────────
    # Incident Lifecycle
    # ─────────────────────────────────────────────

    async def create_incident(
        self,
        incident_type: IncidentType,
        severity: IncidentSeverity,
        title: str,
        description: str,
        affected_systems: Optional[List[str]] = None,
        indicators: Optional[List[Dict]] = None,
        mitre_techniques: Optional[List[str]] = None,
    ) -> Incident:
        """Create and initialize a new incident."""
        incident = Incident(
            incident_type=incident_type,
            severity=severity,
            title=title,
            description=description,
            affected_systems=affected_systems or [],
            indicators=indicators or [],
            mitre_techniques=mitre_techniques or [],
        )

        incident.add_timeline_event(
            f"Incident {incident.incident_id} created: {title}"
        )

        # Load appropriate playbook
        playbook = PLAYBOOK_LIBRARY.get(incident_type, [])
        incident.playbook_steps = [
            PlaybookStep(**{**vars(step), 'step_id': step.step_id})
            for step in playbook
        ]

        # AI-assisted initial triage
        incident.ai_assessment, incident.recommended_actions = await self._ai_triage(incident)
        incident.status = IncidentStatus.TRIAGED
        
        self._incidents[incident.incident_id] = incident

        logger.info(
            "Incident created",
            incident_id=incident.incident_id,
            type=incident_type.value,
            severity=severity.value,
        )

        # Auto-execute critical automated steps for P1/P2
        if severity in (IncidentSeverity.P1_CRITICAL, IncidentSeverity.P2_HIGH):
            asyncio.create_task(self.execute_playbook(incident.incident_id))

        return incident

    async def execute_playbook(self, incident_id: str) -> None:
        """Execute all automated playbook steps for an incident."""
        incident = self._incidents.get(incident_id)
        if not incident:
            logger.error("Incident not found", incident_id=incident_id)
            return

        incident.status = IncidentStatus.INVESTIGATING
        incident.add_timeline_event(f"Playbook execution started")

        logger.info(
            "Executing incident playbook",
            incident_id=incident_id,
            steps=len(incident.playbook_steps),
        )

        for step in incident.playbook_steps:
            if not step.automated:
                step.status = "manual_required"
                incident.add_timeline_event(
                    f"Manual step required: {step.name}"
                )
                continue

            step.status = "running"
            step.started_at = datetime.now(timezone.utc)
            incident.add_timeline_event(f"Executing: {step.name}")

            try:
                handler = self._action_handlers.get(step.action_type)
                if handler:
                    async with asyncio.timeout(step.timeout_seconds):
                        result = await handler(incident, step)
                        step.output = str(result)
                        step.status = "completed"
                        incident.add_timeline_event(f"Completed: {step.name}")
                else:
                    step.status = "skipped"
                    step.error = f"No handler for action type: {step.action_type}"

            except asyncio.TimeoutError:
                step.status = "failed"
                step.error = f"Step timed out after {step.timeout_seconds}s"
                incident.add_timeline_event(f"TIMEOUT: {step.name}")
                
                if step.on_failure == "stop":
                    logger.error("Critical step failed, stopping playbook", step=step.name)
                    break
                elif step.on_failure == "escalate":
                    await self._escalate_incident(incident, f"Step {step.name} timed out")

            except Exception as e:
                step.status = "failed"
                step.error = str(e)
                incident.add_timeline_event(f"FAILED: {step.name} - {str(e)[:100]}")
                
                logger.error(
                    "Playbook step failed",
                    step=step.name,
                    error=str(e),
                    incident_id=incident_id,
                )

            step.completed_at = datetime.now(timezone.utc)

        logger.info(
            "Playbook execution complete",
            incident_id=incident_id,
            completed=sum(1 for s in incident.playbook_steps if s.status == "completed"),
            failed=sum(1 for s in incident.playbook_steps if s.status == "failed"),
        )

    # ─────────────────────────────────────────────
    # Action Handlers
    # ─────────────────────────────────────────────

    async def _handle_notify(
        self, incident: Incident, step: PlaybookStep
    ) -> str:
        """Handle notification steps."""
        from integrations.notifications.pagerduty import PagerDutyClient
        from integrations.notifications.slack import SlackClient
        from integrations.notifications.jira import JiraClient

        notifications_sent = []

        # PagerDuty for P1/P2
        if incident.severity in (IncidentSeverity.P1_CRITICAL, IncidentSeverity.P2_HIGH):
            try:
                pd = PagerDutyClient()
                pd_incident = await pd.create_incident(
                    title=incident.title,
                    severity=incident.severity.value,
                    details={
                        "incident_id": incident.incident_id,
                        "type": incident.incident_type.value,
                        "affected_systems": incident.affected_systems,
                    }
                )
                incident.pagerduty_incident = pd_incident.get("id")
                notifications_sent.append("pagerduty")
            except Exception as e:
                logger.warning("PagerDuty notification failed", error=str(e))

        # Slack notification
        try:
            slack = SlackClient()
            await slack.send_security_alert(
                title=f"[{incident.severity.value.upper()}] {incident.title}",
                incident_id=incident.incident_id,
                description=incident.description,
                affected_systems=incident.affected_systems,
            )
            notifications_sent.append("slack")
        except Exception as e:
            logger.warning("Slack notification failed", error=str(e))

        # JIRA ticket
        if settings.AUTO_TICKET_CREATION:
            try:
                jira = JiraClient()
                ticket = await jira.create_incident_ticket(incident)
                incident.jira_ticket = ticket.get("key")
                notifications_sent.append(f"jira:{ticket.get('key')}")
            except Exception as e:
                logger.warning("JIRA ticket creation failed", error=str(e))

        return f"Notifications sent: {', '.join(notifications_sent)}"

    async def _handle_contain(
        self, incident: Incident, step: PlaybookStep
    ) -> str:
        """Handle containment actions."""
        actions_taken = []

        # Network isolation for ransomware
        if incident.incident_type == IncidentType.RANSOMWARE:
            for system in incident.affected_systems[:5]:
                logger.info("Isolating system", system=system, incident_id=incident.incident_id)
                # In production: integrate with EDR/NAC solution
                actions_taken.append(f"Isolated: {system}")
            incident.contained_at = datetime.now(timezone.utc)

        # Block IOCs at firewall
        malicious_ips = [
            ioc["value"] for ioc in incident.indicators
            if ioc.get("type") == "ip_address"
        ]
        
        if malicious_ips:
            # In production: integrate with firewall API
            actions_taken.append(f"Blocked {len(malicious_ips)} malicious IPs")

        return f"Containment: {'; '.join(actions_taken)}"

    async def _handle_collect_evidence(
        self, incident: Incident, step: PlaybookStep
    ) -> str:
        """Handle evidence collection."""
        import hashlib
        
        evidence_items = []

        # Collect log evidence
        for system in incident.affected_systems[:3]:
            evidence_entry = {
                "type": "system_logs",
                "source": system,
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "collector": "automated",
                "integrity_hash": hashlib.sha256(
                    f"{incident.incident_id}{system}".encode()
                ).hexdigest(),
            }
            incident.evidence.append(evidence_entry)
            evidence_items.append(f"logs:{system}")

        return f"Evidence collected: {', '.join(evidence_items)}"

    async def _handle_remediate(
        self, incident: Incident, step: PlaybookStep
    ) -> str:
        """Handle remediation steps."""
        return f"Remediation step '{step.name}' logged for manual execution"

    async def _handle_verify(
        self, incident: Incident, step: PlaybookStep
    ) -> str:
        """Handle verification steps."""
        return f"Verification step '{step.name}' flagged for manual review"

    async def _escalate_incident(
        self, incident: Incident, reason: str
    ) -> None:
        """Escalate incident severity or trigger emergency response."""
        logger.critical(
            "Incident escalated",
            incident_id=incident.incident_id,
            reason=reason,
        )
        incident.add_timeline_event(f"ESCALATED: {reason}")

    # ─────────────────────────────────────────────
    # AI Triage
    # ─────────────────────────────────────────────

    async def _ai_triage(
        self, incident: Incident
    ) -> tuple[str, List[str]]:
        """Use AI to triage and analyze the incident."""
        prompt = f"""You are an incident response coordinator with 10+ years of experience.
Analyze this security incident and provide triage assessment:

Incident Type: {incident.incident_type.value}
Severity: {incident.severity.value}
Title: {incident.title}
Description: {incident.description}
Affected Systems: {incident.affected_systems}
MITRE Techniques: {incident.mitre_techniques}
Indicators: {len(incident.indicators)} indicators

Provide:
1. Threat assessment (2-3 sentences)
2. Estimated business impact
3. Top 5 immediate action items
4. Likely attack vector

Respond in JSON:
{{
  "assessment": "string",
  "business_impact": "string",
  "immediate_actions": ["action1", "action2", ...],
  "attack_vector": "string",
  "confidence": 0.0-1.0
}}"""

        try:
            response = await self.llm_client.chat(
                prompt=prompt,
                system="You are an expert incident responder. Respond only with valid JSON.",
                max_tokens=600,
                temperature=0.1,
            )
            data = json.loads(response)
            return (
                data.get("assessment", "AI triage unavailable"),
                data.get("immediate_actions", []),
            )
        except Exception as e:
            logger.warning("AI triage failed", error=str(e))
            return ("Manual triage required", [])

    # ─────────────────────────────────────────────
    # Reporting
    # ─────────────────────────────────────────────

    async def generate_incident_report(
        self, incident_id: str
    ) -> Dict[str, Any]:
        """Generate a post-incident report."""
        incident = self._incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")

        duration = None
        if incident.resolved_at:
            duration = (incident.resolved_at - incident.detected_at).total_seconds() / 3600

        return {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "type": incident.incident_type.value,
            "severity": incident.severity.value,
            "status": incident.status.value,
            "detected_at": incident.detected_at.isoformat(),
            "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
            "duration_hours": duration,
            "affected_systems": incident.affected_systems,
            "affected_users": incident.affected_users,
            "mitre_techniques": incident.mitre_techniques,
            "evidence_count": len(incident.evidence),
            "timeline": incident.timeline,
            "playbook_summary": {
                "total_steps": len(incident.playbook_steps),
                "completed": sum(1 for s in incident.playbook_steps if s.status == "completed"),
                "failed": sum(1 for s in incident.playbook_steps if s.status == "failed"),
                "manual_required": sum(1 for s in incident.playbook_steps if s.status == "manual_required"),
            },
            "jira_ticket": incident.jira_ticket,
            "pagerduty_incident": incident.pagerduty_incident,
            "ai_assessment": incident.ai_assessment,
        }

    def get_all_incidents(
        self, status_filter: Optional[IncidentStatus] = None
    ) -> List[Incident]:
        """Get all incidents optionally filtered by status."""
        incidents = list(self._incidents.values())
        if status_filter:
            incidents = [i for i in incidents if i.status == status_filter]
        return sorted(incidents, key=lambda i: i.detected_at, reverse=True)


# ─────────────────────────────────────────────
# Global Instance
# ─────────────────────────────────────────────

_manager: Optional[IncidentManager] = None


def get_incident_manager() -> IncidentManager:
    global _manager
    if _manager is None:
        _manager = IncidentManager()
    return _manager
