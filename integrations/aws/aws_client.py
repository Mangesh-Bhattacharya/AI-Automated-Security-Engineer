"""
AI Automated Security Engineer - AWS Integration Client

Comprehensive AWS security monitoring and scanning integration.
Integrates with: GuardDuty, SecurityHub, CloudTrail, Config,
IAM Access Analyzer, Macie, Inspector v2, S3, EC2, EKS, Lambda.

Fully self-hosted: all analysis runs locally.
AWS credentials are used only for read-only API calls.
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import boto3
import structlog
from botocore.exceptions import ClientError

from core.config import settings

logger = structlog.get_logger("aase.integration.aws")


class AWSSecurityClient:
    """
    AWS Security Integration Client.
    
    Aggregates security findings from AWS native services and
    provides unified security telemetry for the AASE platform.
    
    Permissions required (IAM policy):
    - guardduty:Get*, guardduty:List*
    - securityhub:Get*, securityhub:List*, securityhub:Describe*
    - cloudtrail:Get*, cloudtrail:List*, cloudtrail:Describe*, cloudtrail:LookupEvents
    - config:Get*, config:List*, config:Describe*
    - iam:Get*, iam:List*
    - access-analyzer:Get*, access-analyzer:List*
    - macie2:Get*, macie2:List*
    - inspector2:Get*, inspector2:List*
    - ec2:Describe*
    - eks:Describe*, eks:List*
    - s3:GetBucketAcl, s3:GetBucketPolicy*, s3:GetBucketLogging, s3:ListBuckets
    """

    def __init__(
        self,
        region: Optional[str] = None,
        role_arn: Optional[str] = None,
    ):
        self.region = region or settings.AWS_DEFAULT_REGION
        self.role_arn = role_arn
        self._session = self._create_session()
        logger.info("AWSSecurityClient initialized", region=self.region)

    def _create_session(self) -> boto3.Session:
        """Create boto3 session with optional role assumption."""
        if self.role_arn:
            sts = boto3.client("sts")
            assumed = sts.assume_role(
                RoleArn=self.role_arn,
                RoleSessionName="AASE-SecurityScan",
            )
            creds = assumed["Credentials"]
            return boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=self.region,
            )
        return boto3.Session(region_name=self.region)

    def _client(self, service: str, region: Optional[str] = None):
        return self._session.client(service, region_name=region or self.region)

    # ─────────────────────────────────────────────
    # GuardDuty Integration
    # ─────────────────────────────────────────────

    async def get_guardduty_findings(
        self,
        severity_threshold: float = 4.0,
        hours_back: int = 24,
    ) -> List[Dict[str, Any]]:
        """Retrieve GuardDuty findings above severity threshold."""
        loop = asyncio.get_event_loop()
        
        def _fetch():
            gd = self._client("guardduty")
            findings = []

            try:
                # Get detector IDs
                detectors = gd.list_detectors()
                
                for detector_id in detectors.get("DetectorIds", []):
                    # List findings with filter
                    finding_ids_resp = gd.list_findings(
                        DetectorId=detector_id,
                        FindingCriteria={
                            "Criterion": {
                                "severity": {
                                    "Gte": int(severity_threshold * 10),
                                },
                                "updatedAt": {
                                    "Gte": int(
                                        (datetime.now(timezone.utc) - timedelta(hours=hours_back))
                                        .timestamp() * 1000
                                    ),
                                },
                            }
                        },
                        MaxResults=50,
                    )
                    
                    finding_ids = finding_ids_resp.get("FindingIds", [])
                    if not finding_ids:
                        continue
                    
                    # Get full finding details
                    details = gd.get_findings(
                        DetectorId=detector_id,
                        FindingIds=finding_ids,
                    )
                    findings.extend(details.get("Findings", []))
                    
            except ClientError as e:
                logger.error("GuardDuty API error", error=str(e))
                
            return findings

        raw_findings = await loop.run_in_executor(None, _fetch)
        return [self._normalize_guardduty_finding(f) for f in raw_findings]

    def _normalize_guardduty_finding(self, finding: Dict) -> Dict[str, Any]:
        """Normalize GuardDuty finding to AASE standard format."""
        return {
            "source": "aws_guardduty",
            "id": finding.get("Id", ""),
            "title": finding.get("Title", ""),
            "description": finding.get("Description", ""),
            "severity": finding.get("Severity", 0) / 10,  # Normalize to 0-1
            "type": finding.get("Type", ""),
            "region": finding.get("Region", self.region),
            "account_id": finding.get("AccountId", ""),
            "created_at": finding.get("CreatedAt", ""),
            "updated_at": finding.get("UpdatedAt", ""),
            "resource": finding.get("Resource", {}),
            "service": finding.get("Service", {}),
            "mitre_tactics": self._map_guardduty_to_mitre(finding.get("Type", "")),
            "raw": finding,
        }

    def _map_guardduty_to_mitre(self, finding_type: str) -> List[str]:
        """Map GuardDuty finding types to MITRE ATT&CK tactics."""
        type_map = {
            "Backdoor": ["TA0011"],
            "Behavior": ["TA0010"],
            "CryptoCurrency": ["TA0040"],
            "DefenseEvasion": ["TA0005"],
            "Discovery": ["TA0007"],
            "Exfiltration": ["TA0010"],
            "InitialAccess": ["TA0001"],
            "LateralMovement": ["TA0008"],
            "Persistence": ["TA0003"],
            "PrivilegeEscalation": ["TA0004"],
            "Recon": ["TA0043"],
            "Stealth": ["TA0005"],
            "Trojan": ["TA0001", "TA0011"],
            "UnauthorizedAccess": ["TA0001"],
        }
        
        for key, tactics in type_map.items():
            if key in finding_type:
                return tactics
        return []

    # ─────────────────────────────────────────────
    # CloudTrail Analysis
    # ─────────────────────────────────────────────

    async def analyze_cloudtrail_events(
        self,
        hours_back: int = 24,
        suspicious_events: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Analyze CloudTrail events for suspicious activity."""
        if suspicious_events is None:
            suspicious_events = [
                "CreateUser", "DeleteUser", "AttachUserPolicy", "AttachRolePolicy",
                "CreateAccessKey", "DeleteTrail", "StopLogging", "UpdateTrail",
                "ConsoleLogin", "CreateNetworkAcl", "AuthorizeSecurityGroupIngress",
                "CreateKeyPair", "ImportKeyPair", "RunInstances", "TerminateInstances",
                "DeleteBucket", "PutBucketPolicy", "PutBucketAcl", "DeleteBucketPolicy",
                "AssumeRoleWithWebIdentity", "GetCredentialsForIdentity",
            ]

        loop = asyncio.get_event_loop()
        
        def _fetch():
            ct = self._client("cloudtrail")
            events = []
            
            try:
                start_time = datetime.now(timezone.utc) - timedelta(hours=hours_back)
                
                for event_name in suspicious_events[:20]:  # Limit API calls
                    try:
                        resp = ct.lookup_events(
                            LookupAttributes=[{
                                "AttributeKey": "EventName",
                                "AttributeValue": event_name,
                            }],
                            StartTime=start_time,
                            EndTime=datetime.now(timezone.utc),
                            MaxResults=20,
                        )
                        events.extend(resp.get("Events", []))
                    except ClientError:
                        continue
                        
            except ClientError as e:
                logger.error("CloudTrail API error", error=str(e))
                
            return events

        raw_events = await loop.run_in_executor(None, _fetch)
        return [self._normalize_cloudtrail_event(e) for e in raw_events]

    def _normalize_cloudtrail_event(self, event: Dict) -> Dict[str, Any]:
        """Normalize CloudTrail event."""
        detail = json.loads(event.get("CloudTrailEvent", "{}"))
        
        return {
            "source": "aws_cloudtrail",
            "event_id": event.get("EventId", ""),
            "event_name": event.get("EventName", ""),
            "event_time": str(event.get("EventTime", "")),
            "username": event.get("Username", ""),
            "source_ip": detail.get("sourceIPAddress", ""),
            "user_agent": detail.get("userAgent", ""),
            "aws_region": detail.get("awsRegion", self.region),
            "request_parameters": detail.get("requestParameters", {}),
            "response_elements": detail.get("responseElements", {}),
            "error_code": detail.get("errorCode", ""),
            "error_message": detail.get("errorMessage", ""),
            "is_privileged": self._is_privileged_action(event.get("EventName", "")),
            "raw": detail,
        }

    def _is_privileged_action(self, event_name: str) -> bool:
        """Check if CloudTrail event represents a privileged action."""
        privileged = [
            "CreateUser", "DeleteUser", "AttachUserPolicy", "DetachUserPolicy",
            "CreateRole", "DeleteRole", "AttachRolePolicy", "CreateAccessKey",
            "DeleteTrail", "StopLogging", "CreateNetworkAcl", "ModifyVpcAttribute",
        ]
        return event_name in privileged

    # ─────────────────────────────────────────────
    # IAM Security Analysis
    # ─────────────────────────────────────────────

    async def analyze_iam_security(self) -> Dict[str, Any]:
        """Analyze IAM configuration for security issues."""
        loop = asyncio.get_event_loop()
        
        def _analyze():
            iam = self._client("iam")
            issues = []
            
            try:
                # Check for users without MFA
                users_resp = iam.list_users()
                for user in users_resp.get("Users", []):
                    username = user["UserName"]
                    
                    # Check MFA devices
                    mfa_resp = iam.list_mfa_devices(UserName=username)
                    if not mfa_resp.get("MFADevices"):
                        issues.append({
                            "issue_type": "NO_MFA",
                            "severity": "HIGH",
                            "resource": f"iam:user/{username}",
                            "description": f"IAM user {username} has no MFA device enrolled",
                            "remediation": f"Enforce MFA for user {username}",
                        })
                    
                    # Check access keys age
                    keys_resp = iam.list_access_keys(UserName=username)
                    for key in keys_resp.get("AccessKeyMetadata", []):
                        if key["Status"] == "Active":
                            created = key["CreateDate"].replace(tzinfo=timezone.utc)
                            age_days = (datetime.now(timezone.utc) - created).days
                            
                            if age_days > 90:
                                issues.append({
                                    "issue_type": "STALE_ACCESS_KEY",
                                    "severity": "MEDIUM",
                                    "resource": f"iam:user/{username}",
                                    "description": f"Access key {key['AccessKeyId'][:8]}... is {age_days} days old",
                                    "remediation": "Rotate access keys every 90 days",
                                })
                
                # Check for root account usage
                summary = iam.get_account_summary()
                if summary["SummaryMap"].get("AccountMFAEnabled") == 0:
                    issues.append({
                        "issue_type": "ROOT_MFA_DISABLED",
                        "severity": "CRITICAL",
                        "resource": "iam:root",
                        "description": "AWS root account MFA is not enabled",
                        "remediation": "Enable MFA on root account immediately",
                    })
                    
            except ClientError as e:
                logger.error("IAM analysis error", error=str(e))
                
            return {"issues": issues, "issue_count": len(issues)}

        return await loop.run_in_executor(None, _analyze)

    # ─────────────────────────────────────────────
    # S3 Security Audit
    # ─────────────────────────────────────────────

    async def audit_s3_security(self) -> List[Dict[str, Any]]:
        """Audit S3 buckets for security misconfigurations."""
        loop = asyncio.get_event_loop()
        
        def _audit():
            s3 = self._client("s3")
            findings = []
            
            try:
                buckets = s3.list_buckets().get("Buckets", [])
                
                for bucket in buckets:
                    bucket_name = bucket["Name"]
                    
                    # Check public access
                    try:
                        pab = s3.get_public_access_block(Bucket=bucket_name)
                        config = pab.get("PublicAccessBlockConfiguration", {})
                        
                        if not all([
                            config.get("BlockPublicAcls"),
                            config.get("BlockPublicPolicy"),
                            config.get("IgnorePublicAcls"),
                            config.get("RestrictPublicBuckets"),
                        ]):
                            findings.append({
                                "source": "aws_s3",
                                "bucket": bucket_name,
                                "issue": "S3_PUBLIC_ACCESS_NOT_BLOCKED",
                                "severity": "HIGH",
                                "description": f"Bucket {bucket_name} does not have all public access block settings enabled",
                                "remediation": "Enable all S3 Public Access Block settings",
                            })
                    except ClientError:
                        findings.append({
                            "source": "aws_s3",
                            "bucket": bucket_name,
                            "issue": "S3_NO_PUBLIC_ACCESS_BLOCK",
                            "severity": "HIGH",
                            "description": f"Bucket {bucket_name} has no Public Access Block configuration",
                        })
                    
                    # Check bucket logging
                    try:
                        logging = s3.get_bucket_logging(Bucket=bucket_name)
                        if "LoggingEnabled" not in logging:
                            findings.append({
                                "source": "aws_s3",
                                "bucket": bucket_name,
                                "issue": "S3_LOGGING_DISABLED",
                                "severity": "MEDIUM",
                                "description": f"Access logging not enabled for bucket {bucket_name}",
                                "remediation": "Enable S3 server access logging",
                            })
                    except ClientError:
                        pass
                        
            except ClientError as e:
                logger.error("S3 audit error", error=str(e))
                
            return findings

        return await loop.run_in_executor(None, _audit)

    # ─────────────────────────────────────────────
    # Security Hub Aggregation
    # ─────────────────────────────────────────────

    async def get_security_hub_findings(
        self,
        severity_labels: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Get Security Hub aggregated findings."""
        if severity_labels is None:
            severity_labels = ["CRITICAL", "HIGH"]

        loop = asyncio.get_event_loop()
        
        def _fetch():
            sh = self._client("securityhub")
            findings = []
            
            try:
                resp = sh.get_findings(
                    Filters={
                        "SeverityLabel": [
                            {"Value": label, "Comparison": "EQUALS"}
                            for label in severity_labels
                        ],
                        "WorkflowStatus": [
                            {"Value": "NEW", "Comparison": "EQUALS"},
                            {"Value": "NOTIFIED", "Comparison": "EQUALS"},
                        ],
                        "RecordState": [
                            {"Value": "ACTIVE", "Comparison": "EQUALS"}
                        ],
                    },
                    MaxResults=100,
                )
                findings = resp.get("Findings", [])
                
            except ClientError as e:
                if "not subscribed" in str(e).lower():
                    logger.info("Security Hub not enabled in this account/region")
                else:
                    logger.error("Security Hub API error", error=str(e))
                    
            return findings

        return await loop.run_in_executor(None, _fetch)

    async def get_security_posture_summary(self) -> Dict[str, Any]:
        """Get an overall security posture summary for the AWS account."""
        gd_task = self.get_guardduty_findings(severity_threshold=2.0, hours_back=24)
        s3_task = self.audit_s3_security()
        iam_task = self.analyze_iam_security()
        sh_task = self.get_security_hub_findings()
        
        gd_findings, s3_findings, iam_analysis, sh_findings = await asyncio.gather(
            gd_task, s3_task, iam_task, sh_task, return_exceptions=True
        )
        
        return {
            "account_id": settings.AWS_ACCOUNT_ID,
            "region": self.region,
            "assessed_at": datetime.now(timezone.utc).isoformat(),
            "guardduty": {
                "findings_24h": len(gd_findings) if isinstance(gd_findings, list) else 0,
            },
            "s3": {
                "misconfigurations": len(s3_findings) if isinstance(s3_findings, list) else 0,
            },
            "iam": iam_analysis if isinstance(iam_analysis, dict) else {"error": str(iam_analysis)},
            "security_hub": {
                "active_findings": len(sh_findings) if isinstance(sh_findings, list) else 0,
            },
        }
