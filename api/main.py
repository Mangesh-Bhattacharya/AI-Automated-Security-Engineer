"""
AI Automated Security Engineer Platform
API Main Application - FastAPI Entry Point

Self-hosted, enterprise-grade AI security automation platform
for AWS, Azure, GCP, banking, and on-premise environments.
"""

import logging
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

from core.config import settings
from core.database import init_db, close_db
from api.auth import auth_router
from api.routes.scans import router as scans_router
from api.routes.threats import router as threats_router
from api.routes.compliance import router as compliance_router
from api.routes.incidents import router as incidents_router
from api.routes.dashboard import router as dashboard_router
from api.middleware.rate_limiter import RateLimitMiddleware
from api.middleware.audit_logger import AuditLogMiddleware

# ─────────────────────────────────────────────
# Logging Setup
# ─────────────────────────────────────────────
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
)
logger = structlog.get_logger("aase.api")

# ─────────────────────────────────────────────
# Prometheus Metrics
# ─────────────────────────────────────────────
REQUEST_COUNT = Counter(
    "aase_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status_code"]
)
REQUEST_LATENCY = Histogram(
    "aase_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "endpoint"]
)
SECURITY_EVENTS = Counter(
    "aase_security_events_total",
    "Total security events detected",
    ["severity", "category"]
)
SCANS_INITIATED = Counter(
    "aase_scans_initiated_total",
    "Total scans initiated",
    ["scan_type"]
)

# ─────────────────────────────────────────────
# Application Lifecycle
# ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Startup and shutdown lifecycle management."""
    logger.info(
        "Starting AI Automated Security Engineer Platform",
        version=settings.VERSION,
        environment=settings.ENVIRONMENT
    )
    
    # Initialize database connections
    await init_db()
    logger.info("Database connections initialized")
    
    # Initialize AI models (lazy loading)
    if settings.PRELOAD_AI_MODELS:
        from ai_engine.model_manager import ModelManager
        await ModelManager.initialize()
        logger.info("AI models preloaded")
    
    # Start background threat intelligence refresh
    from threat_detection.threat_intel import ThreatIntelligenceManager
    await ThreatIntelligenceManager.start_background_refresh()
    
    logger.info("AASE Platform startup complete", port=settings.PORT)
    yield
    
    # Graceful shutdown
    logger.info("Shutting down AASE Platform...")
    await close_db()
    logger.info("AASE Platform shutdown complete")


# ─────────────────────────────────────────────
# FastAPI Application
# ─────────────────────────────────────────────
app = FastAPI(
    title="AI Automated Security Engineer",
    description="""
## AI Automated Security Engineer (AASE)

Entirely self-hosted AI-powered cybersecurity platform for enterprise environments.

### Capabilities
- **Vulnerability Scanning**: SAST/DAST, container scanning, cloud misconfigurations
- **Threat Detection**: Real-time AI-based IDS/IPS with MITRE ATT&CK mapping
- **Compliance**: Automated PCI-DSS, HIPAA, SOC2, ISO 27001, NIST, FedRAMP checks
- **Incident Response**: Automated playbook execution and forensic analysis
- **Multi-Cloud**: AWS, Azure, GCP, and on-premise integrations

### Security Model
All AI inference runs on locally-hosted models. No data leaves your environment.
    """,
    version=settings.VERSION,
    docs_url="/api/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/api/redoc" if settings.ENVIRONMENT != "production" else None,
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
    swagger_ui_parameters={"persistAuthorization": True},
)

# ─────────────────────────────────────────────
# Middleware Stack
# ─────────────────────────────────────────────
# Security: Trusted Hosts
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-RateLimit-Remaining"],
)

# Rate Limiting
app.add_middleware(RateLimitMiddleware)

# Audit Logging
app.add_middleware(AuditLogMiddleware)


# ─────────────────────────────────────────────
# Request Instrumentation
# ─────────────────────────────────────────────
@app.middleware("http")
async def instrument_requests(request: Request, call_next):
    """Prometheus metrics and request tracking middleware."""
    start_time = time.time()
    
    # Add request ID
    import uuid
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    
    response = await call_next(request)
    
    # Record metrics
    duration = time.time() - start_time
    endpoint = request.url.path
    
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=endpoint,
        status_code=response.status_code
    ).inc()
    
    REQUEST_LATENCY.labels(
        method=request.method,
        endpoint=endpoint
    ).observe(duration)
    
    # Add security headers
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    return response


# ─────────────────────────────────────────────
# Exception Handlers
# ─────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(
        "Unhandled exception",
        path=request.url.path,
        method=request.method,
        error=str(exc),
        exc_info=True,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "request_id": getattr(request.state, "request_id", None),
        },
    )


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────
# Authentication
app.include_router(auth_router, prefix="/api/v1/auth", tags=["Authentication"])

# Security Scanning
app.include_router(scans_router, prefix="/api/v1/scans", tags=["Vulnerability Scanning"])

# Threat Detection
app.include_router(threats_router, prefix="/api/v1/threats", tags=["Threat Detection"])

# Compliance
app.include_router(compliance_router, prefix="/api/v1/compliance", tags=["Compliance"])

# Incident Response
app.include_router(incidents_router, prefix="/api/v1/incidents", tags=["Incident Response"])

# Dashboard
app.include_router(dashboard_router, prefix="/api/v1/dashboard", tags=["Dashboard"])


# ─────────────────────────────────────────────
# Health & Metrics Endpoints
# ─────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health_check():
    """Platform health check endpoint."""
    from core.database import check_db_health
    from core.config import get_service_status
    
    db_healthy = await check_db_health()
    services = await get_service_status()
    
    overall_status = "healthy" if db_healthy and all(services.values()) else "degraded"
    
    return {
        "status": overall_status,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "services": {
            "database": "up" if db_healthy else "down",
            **services,
        },
        "ai_models": {
            "ollama": services.get("ollama", False),
            "loaded_models": settings.ACTIVE_MODELS,
        },
    }


@app.get("/metrics", tags=["System"])
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )


@app.get("/api/v1/info", tags=["System"])
async def platform_info():
    """Platform information and capabilities."""
    return {
        "name": "AI Automated Security Engineer",
        "version": settings.VERSION,
        "capabilities": [
            "vulnerability_scanning",
            "threat_detection",
            "compliance_automation",
            "incident_response",
            "siem_integration",
            "ai_threat_intelligence",
        ],
        "integrations": {
            "cloud": ["aws", "azure", "gcp"],
            "siem": ["elasticsearch", "splunk"],
            "ticketing": ["jira", "servicenow"],
            "notifications": ["slack", "teams", "pagerduty"],
            "identity": ["ldap", "active_directory", "okta"],
        },
        "ai_model": {
            "type": "self_hosted",
            "provider": "ollama",
            "data_leaves_environment": False,
        },
        "compliance_frameworks": [
            "PCI-DSS v4.0",
            "HIPAA",
            "SOC2 Type II",
            "ISO 27001:2022",
            "NIST CSF 2.0",
            "FedRAMP Moderate",
            "CIS Controls v8",
            "SWIFT CSP",
            "GDPR",
        ],
    }


# Serve dashboard static files
app.mount("/", StaticFiles(directory="dashboard", html=True), name="dashboard")
