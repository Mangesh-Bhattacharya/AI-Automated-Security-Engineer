# ============================================================
# AI Automated Security Engineer - Makefile
# Easy deployment and management commands
# ============================================================

.PHONY: help setup dev prod down logs models update-cve certs test lint clean

DOCKER_COMPOSE = docker-compose
APP_NAME = aase

help: ## Show this help message
	@echo "AI Automated Security Engineer - Available Commands"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'

# --- Setup ---
setup: ## Initial platform setup (run first)
	@echo "Setting up AASE platform..."
	@cp -n .env.example .env || true
	@mkdir -p certs logs data/cve_database
	@openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=aase-platform" 2>/dev/null || true
	@echo "Setup complete. Edit .env before starting."

models: ## Download self-hosted AI models
	@echo "Pulling AI models for local inference (this may take 30-60 min)..."
	@docker run --rm -v ollama-models:/root/.ollama ollama/ollama pull llama3.1:70b
	@docker run --rm -v ollama-models:/root/.ollama ollama/ollama pull mistral:7b
	@docker run --rm -v ollama-models:/root/.ollama ollama/ollama pull nomic-embed-text
	@docker run --rm -v ollama-models:/root/.ollama ollama/ollama pull codellama:34b
	@echo "AI models ready."

certs: ## Generate TLS certificates
	@mkdir -p certs
	@openssl req -x509 -newkey rsa:4096 -sha256 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/C=US/O=AASE/CN=security-platform"
	@chmod 600 certs/server.key

# --- Running ---
dev: ## Start development environment
	$(DOCKER_COMPOSE) up -d postgres redis elasticsearch ollama
	@sleep 10
	uvicorn api.main:app --reload --host 0.0.0.0 --port 8443 --ssl-keyfile certs/server.key --ssl-certfile certs/server.crt

prod: ## Start production environment
	$(DOCKER_COMPOSE) up -d
	@echo "AASE Platform started - Dashboard: https://localhost:8443"

down: ## Stop all services
	$(DOCKER_COMPOSE) down

restart: ## Restart API services
	$(DOCKER_COMPOSE) restart aase-api celery-scanner celery-threats celery-beat

# --- Maintenance ---
logs: ## Tail application logs
	$(DOCKER_COMPOSE) logs -f aase-api celery-scanner

update-cve: ## Update local CVE database
	$(DOCKER_COMPOSE) exec aase-api python scripts/update_cve_db.py

backup: ## Backup database
	@mkdir -p backups
	$(DOCKER_COMPOSE) exec postgres pg_dump -U aase aase_db | gzip > backups/aase_backup.sql.gz

# --- Testing ---
test: ## Run full test suite
	pytest tests/ -v --cov=. --cov-report=term-missing

test-unit: ## Run unit tests
	pytest tests/unit/ -v

test-security: ## Run security analysis on codebase
	bandit -r . -x tests/,venv/ -ll
	safety check

# --- Code Quality ---
lint: ## Run linting
	flake8 . --max-line-length=120 --exclude=venv,migrations
	mypy . --ignore-missing-imports

format: ## Auto-format code
	black . --line-length 100
	isort . --profile black

# --- Kubernetes ---
k8s-deploy: ## Deploy to Kubernetes
	kubectl apply -f k8s/

k8s-status: ## Check K8s deployment
	kubectl get pods -n aase-platform

# --- Cleanup ---
clean: ## Remove containers and build artifacts
	$(DOCKER_COMPOSE) down -v
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.pyc' -delete

status: ## Show platform status
	@echo "=== AASE Platform Status ==="
	$(DOCKER_COMPOSE) ps
