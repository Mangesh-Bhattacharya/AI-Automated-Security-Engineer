"""
AI Automated Security Engineer - Application Configuration

Centralized settings management using Pydantic Settings.
All configuration loaded from environment variables or .env file.
"""

from functools import lru_cache
from typing import Any, Dict, List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    Includes configuration for:
    - Core application
    - AI/ML models (self-hosted)
    - Database and caching
    - Cloud integrations
    - Security scanning
    - Compliance frameworks
    - Incident response
    - Notifications
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ─── Core Application ───────────────────────────────────────────────────
    ENVIRONMENT: str = Field(default="development", description="deployment environment")
    VERSION: str = Field(default="1.0.0")
    PORT: int = Field(default=8443)
    SECRET_KEY: str = Field(default="change-me-in-production")
    JWT_SECRET: str = Field(default="change-me-in-production")
    JWT_EXPIRE_MINUTES: int = Field(default=60)
    ALLOWED_HOSTS: List[str] = Field(default=["localhost", "127.0.0.1"])
    CORS_ORIGINS: List[str] = Field(default=["http://localhost:3000"])
    DEBUG: bool = Field(default=False)

    # ─── Database ───────────────────────────────────────────────────────────
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://aase:password@localhost:5432/aase_db"
    )
    DATABASE_POOL_SIZE: int = Field(default=20)
    DATABASE_MAX_OVERFLOW: int = Field(default=40)

    # ─── Redis / Celery ─────────────────────────────────────────────────────
    REDIS_URL: str = Field(default="redis://localhost:6379/0")
    CELERY_BROKER_URL: str = Field(default="redis://localhost:6379/1")
    CELERY_RESULT_BACKEND: str = Field(default="redis://localhost:6379/2")

    # ─── Elasticsearch / SIEM ───────────────────────────────────────────────
    ELASTICSEARCH_URL: str = Field(default="http://localhost:9200")
    ELASTICSEARCH_USERNAME: str = Field(default="elastic")
    ELASTICSEARCH_PASSWORD: str = Field(default="")
    ELASTICSEARCH_INDEX_PREFIX: str = Field(default="aase")
    LOG_RETENTION_DAYS: int = Field(default=365)

    # ─── Self-Hosted AI Models ───────────────────────────────────────────────
    # All AI runs locally - NO external API calls
    OLLAMA_BASE_URL: str = Field(default="http://localhost:11434")
    DEFAULT_LLM_MODEL: str = Field(default="llama3.1:70b")
    FALLBACK_LLM_MODEL: str = Field(default="mistral:7b")
    EMBEDDING_MODEL: str = Field(default="nomic-embed-text")
    CODE_ANALYSIS_MODEL: str = Field(default="codellama:34b")
    PRELOAD_AI_MODELS: bool = Field(default=False)
    AI_TRIAGE_ENABLED: bool = Field(default=True)
    AI_COMPLIANCE_ANALYSIS: bool = Field(default=True)
    ANOMALY_THRESHOLD: float = Field(default=0.85)
    ACTIVE_MODELS: List[str] = Field(default=["llama3.1:70b", "mistral:7b"])

    # ─── AWS Integration ────────────────────────────────────────────────────
    AWS_DEFAULT_REGION: str = Field(default="us-east-1")
    AWS_ACCOUNT_ID: str = Field(default="")
    AWS_ACCESS_KEY_ID: str = Field(default="")
    AWS_SECRET_ACCESS_KEY: str = Field(default="")
    AWS_SCANNER_ROLE_ARN: str = Field(default="")

    # ─── Azure Integration ──────────────────────────────────────────────────
    AZURE_TENANT_ID: str = Field(default="")
    AZURE_CLIENT_ID: str = Field(default="")
    AZURE_CLIENT_SECRET: str = Field(default="")
    AZURE_SUBSCRIPTION_ID: str = Field(default="")

    # ─── GCP Integration ────────────────────────────────────────────────────
    GCP_PROJECT_ID: str = Field(default="")
    GOOGLE_APPLICATION_CREDENTIALS: str = Field(default="")

    # ─── LDAP / Active Directory ────────────────────────────────────────────
    LDAP_SERVER: str = Field(default="")
    LDAP_BIND_DN: str = Field(default="")
    LDAP_BIND_PASSWORD: str = Field(default="")
    LDAP_SEARCH_BASE: str = Field(default="")

    # ─── Notifications ──────────────────────────────────────────────────────
    SLACK_WEBHOOK_URL: str = Field(default="")
    SLACK_BOT_TOKEN: str = Field(default="")
    SLACK_SECURITY_CHANNEL: str = Field(default="#security-alerts")
    SLACK_CRITICAL_CHANNEL: str = Field(default="#critical-incidents")
    TEAMS_WEBHOOK_URL: str = Field(default="")
    PAGERDUTY_API_KEY: str = Field(default="")
    PAGERDUTY_SERVICE_ID: str = Field(default="")
    PAGERDUTY_FROM_EMAIL: str = Field(default="")
    JIRA_URL: str = Field(default="")
    JIRA_USERNAME: str = Field(default="")
    JIRA_TOKEN: str = Field(default="")
    JIRA_PROJECT_KEY: str = Field(default="SEC")

    # ─── Scanning Configuration ─────────────────────────────────────────────
    MAX_CONCURRENT_SCANS: int = Field(default=10)
    SCAN_TIMEOUT_SECONDS: int = Field(default=3600)
    ALLOW_LOCALHOST_SCAN: bool = Field(default=False)
    NETWORK_SCAN_RATE_LIMIT: int = Field(default=1000)
    ENABLE_ACTIVE_SCANNING: bool = Field(default=True)
    SCHEDULED_SCAN_INTERVAL_HOURS: int = Field(default=24)

    # ─── Compliance ─────────────────────────────────────────────────────────
    ENABLED_FRAMEWORKS: List[str] = Field(
        default=["pci_dss_v4", "hipaa", "soc2_type_ii", "iso_27001_2022", "nist_csf_2", "cis_controls_v8"]
    )
    AUTO_REMEDIATION_ENABLED: bool = Field(default=False)
    COMPLIANCE_REPORT_FORMAT: List[str] = Field(default=["pdf", "json"])

    # ─── Incident Response ──────────────────────────────────────────────────
    AUTO_ISOLATE_ON_RANSOMWARE: bool = Field(default=True)
    AUTO_BLOCK_BRUTE_FORCE_IPS: bool = Field(default=True)
    AUTO_TICKET_CREATION: bool = Field(default=True)
    INCIDENT_ESCALATION_MINUTES: int = Field(default=30)
    PLAYBOOK_DIRECTORY: str = Field(default="/app/incident_response/playbooks")

    # ─── Threat Intelligence ────────────────────────────────────────────────
    THREAT_INTEL_UPDATE_HOURS: int = Field(default=6)
    ALIENVAULT_OTX_API_KEY: str = Field(default="")
    VIRUSTOTAL_API_KEY: str = Field(default="")
    MISP_URL: str = Field(default="")
    MISP_API_KEY: str = Field(default="")
    NVD_API_KEY: str = Field(default="")
    CVE_DB_PATH: str = Field(default="/app/data/cve_database")

    # ─── TLS ────────────────────────────────────────────────────────────────
    TLS_CERT_PATH: str = Field(default="/app/certs/server.crt")
    TLS_KEY_PATH: str = Field(default="/app/certs/server.key")
    TLS_MIN_VERSION: str = Field(default="TLSv1.2")

    # ─── Banking/Financial ──────────────────────────────────────────────────
    BANKING_COMPLIANCE_MODE: bool = Field(default=False)
    FRAUD_DETECTION_ENABLED: bool = Field(default=False)
    PCI_CDE_NETWORKS: List[str] = Field(default=[])

    # ─── Validators ─────────────────────────────────────────────────────────

    @field_validator("ALLOWED_HOSTS", "CORS_ORIGINS", "ACTIVE_MODELS",
                     "ENABLED_FRAMEWORKS", "COMPLIANCE_REPORT_FORMAT",
                     "PCI_CDE_NETWORKS", mode="before")
    @classmethod
    def parse_list(cls, v: Any) -> List[str]:
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v or []

    @field_validator("ANOMALY_THRESHOLD")
    @classmethod
    def validate_threshold(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("ANOMALY_THRESHOLD must be between 0.0 and 1.0")
        return v

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def is_aws_configured(self) -> bool:
        return bool(self.AWS_ACCOUNT_ID or self.AWS_SCANNER_ROLE_ARN)

    @property
    def is_azure_configured(self) -> bool:
        return bool(self.AZURE_TENANT_ID and self.AZURE_CLIENT_ID)

    @property
    def is_gcp_configured(self) -> bool:
        return bool(self.GCP_PROJECT_ID)

    @property
    def notifications_configured(self) -> Dict[str, bool]:
        return {
            "slack": bool(self.SLACK_WEBHOOK_URL or self.SLACK_BOT_TOKEN),
            "pagerduty": bool(self.PAGERDUTY_API_KEY),
            "jira": bool(self.JIRA_URL and self.JIRA_TOKEN),
            "teams": bool(self.TEAMS_WEBHOOK_URL),
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Global settings instance
settings = get_settings()


async def get_service_status() -> Dict[str, bool]:
    """Check status of all integrated services."""
    import httpx
    
    status = {}
    
    # Check Ollama
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{settings.OLLAMA_BASE_URL}/api/version")
            status["ollama"] = resp.status_code == 200
    except Exception:
        status["ollama"] = False
    
    # Check Redis
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.REDIS_URL)
        await r.ping()
        status["redis"] = True
        await r.aclose()
    except Exception:
        status["redis"] = False
    
    # Check Elasticsearch
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{settings.ELASTICSEARCH_URL}/_cluster/health")
            status["elasticsearch"] = resp.status_code == 200
    except Exception:
        status["elasticsearch"] = False
    
    return status
