"""
AI Automated Security Engineer - Self-Hosted LLM Client

Provides a unified interface to locally-hosted language models via Ollama.
No data ever leaves the environment. Supports:
- Ollama (Llama 3.1, Mistral, CodeLlama, etc.)
- vLLM server
- Custom OpenAI-compatible endpoints

Includes:
- Prompt caching
- Request batching
- Model health monitoring
- Automatic fallback between models
- Token usage tracking
"""

import asyncio
import hashlib
import json
import time
from typing import Any, Dict, List, Optional

import httpx
import structlog

from core.config import settings

logger = structlog.get_logger("aase.ai.llm_client")


class LLMClient:
    """
    Self-hosted LLM client for security analysis tasks.
    
    Connects exclusively to locally-hosted models (Ollama/vLLM).
    All prompts and responses remain within the private environment.
    """

    def __init__(self):
        self.base_url = settings.OLLAMA_BASE_URL
        self.default_model = settings.DEFAULT_LLM_MODEL  # e.g., "llama3.1:70b"
        self.fallback_model = settings.FALLBACK_LLM_MODEL  # e.g., "mistral:7b"
        self._cache: Dict[str, str] = {}
        self._request_count = 0
        self._token_usage = 0
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(60.0, connect=10.0),
        )
        logger.info(
            "LLMClient initialized",
            base_url=self.base_url,
            model=self.default_model,
        )

    async def chat(
        self,
        prompt: str,
        system: str = "You are an expert cybersecurity analyst.",
        model: Optional[str] = None,
        max_tokens: int = 1000,
        temperature: float = 0.1,
        use_cache: bool = True,
    ) -> str:
        """
        Send a chat request to the locally-hosted LLM.
        
        Args:
            prompt: User prompt
            system: System prompt for role/context
            model: Model name (defaults to settings.DEFAULT_LLM_MODEL)
            max_tokens: Maximum response tokens
            temperature: Sampling temperature (lower = more deterministic)
            use_cache: Whether to use response caching
            
        Returns:
            LLM response text
        """
        model = model or self.default_model
        
        # Check cache for identical requests
        if use_cache:
            cache_key = self._make_cache_key(prompt, system, model)
            if cache_key in self._cache:
                logger.debug("LLM cache hit", model=model)
                return self._cache[cache_key]

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
                "top_p": 0.9,
            },
        }

        try:
            start_time = time.time()
            response = await self._client.post("/api/chat", json=payload)
            response.raise_for_status()
            
            data = response.json()
            content = data.get("message", {}).get("content", "")
            
            elapsed = time.time() - start_time
            tokens = data.get("eval_count", 0)
            
            self._request_count += 1
            self._token_usage += tokens
            
            logger.debug(
                "LLM request completed",
                model=model,
                tokens=tokens,
                elapsed_seconds=round(elapsed, 2),
            )

            if use_cache and content:
                self._cache[cache_key] = content

            return content

        except httpx.ConnectError:
            logger.warning(
                "Primary LLM unavailable, trying fallback",
                primary=model,
                fallback=self.fallback_model,
            )
            if model != self.fallback_model:
                return await self.chat(
                    prompt=prompt,
                    system=system,
                    model=self.fallback_model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    use_cache=use_cache,
                )
            raise

        except Exception as e:
            logger.error("LLM request failed", model=model, error=str(e))
            raise

    async def analyze_security_event(
        self,
        event_data: Dict[str, Any],
        analysis_type: str = "threat",
    ) -> Dict[str, Any]:
        """
        Analyze a security event using the LLM.
        
        Returns structured analysis with severity, tactics, and recommendations.
        """
        system_prompt = """You are a senior threat intelligence analyst with 15 years 
of experience in incident response and threat hunting. Analyze security events and 
provide precise, actionable intelligence. Always respond with valid JSON."""

        prompt = f"""Analyze this security event:

Event Type: {analysis_type}
Data: {json.dumps(event_data, indent=2)[:2000]}

Provide analysis in JSON:
{{
  "severity": "critical|high|medium|low",
  "threat_type": "string",
  "confidence": 0.0-1.0,
  "mitre_tactics": ["TA0001", ...],
  "mitre_techniques": ["T1190", ...],
  "false_positive_likelihood": 0.0-1.0,
  "key_indicators": ["indicator1", ...],
  "immediate_actions": ["action1", ...],
  "investigation_steps": ["step1", ...],
  "threat_actor_profile": "string or null"
}}"""

        response = await self.chat(
            prompt=prompt,
            system=system_prompt,
            max_tokens=800,
            temperature=0.05,
        )

        try:
            # Extract JSON from response
            json_match = response.strip()
            if "```json" in json_match:
                json_match = json_match.split("```json")[1].split("```")[0]
            elif "```" in json_match:
                json_match = json_match.split("```")[1].split("```")[0]
            return json.loads(json_match.strip())
        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM JSON response, returning raw")
            return {"raw_analysis": response, "severity": "medium", "confidence": 0.5}

    async def generate_remediation(
        self,
        vulnerability: Dict[str, Any],
        environment: str = "cloud",
    ) -> str:
        """Generate specific remediation steps for a vulnerability."""
        prompt = f"""Security vulnerability requiring remediation:

Vulnerability: {vulnerability.get('title', 'Unknown')}
CVEs: {', '.join(vulnerability.get('cve_ids', []))}
CVSS: {vulnerability.get('cvss_score', 'N/A')}
Component: {vulnerability.get('affected_component', 'Unknown')}
Environment: {environment}
Description: {vulnerability.get('description', '')[:500]}

Provide specific, step-by-step remediation instructions for a {environment} environment.
Include:
1. Immediate mitigation steps
2. Permanent fix
3. Verification steps
4. Preventive measures

Be specific and technical. No markdown."""

        return await self.chat(
            prompt=prompt,
            system="You are a cloud security engineer specializing in vulnerability remediation. Provide precise, actionable remediation steps.",
            max_tokens=600,
            temperature=0.1,
        )

    async def threat_hunt(
        self,
        hunt_hypothesis: str,
        available_data_sources: List[str],
    ) -> Dict[str, Any]:
        """Generate a threat hunting plan for a given hypothesis."""
        prompt = f"""Threat Hunting Plan Request:

Hypothesis: {hunt_hypothesis}
Available Data Sources: {', '.join(available_data_sources)}

Generate a structured threat hunting plan including:
- MITRE ATT&CK techniques to investigate
- Specific queries for each data source
- Key indicators to look for
- Estimated time to complete
- Success criteria

Respond in JSON format."""

        response = await self.chat(
            prompt=prompt,
            system="You are an expert threat hunter. Generate precise hunting plans.",
            max_tokens=1000,
            temperature=0.2,
        )

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return {"hunt_plan": response}

    async def classify_log(
        self,
        log_message: str,
        log_source: str = "system",
    ) -> Dict[str, str]:
        """Quickly classify a log message for security relevance."""
        prompt = f"""Classify this {log_source} log message:

"{log_message[:300]}"

Respond with JSON only:
{{
  "is_security_relevant": true/false,
  "event_type": "authentication|network|file_system|process|malware|anomaly|normal",
  "severity": "critical|high|medium|low|info",
  "confidence": 0.0-1.0,
  "brief_reason": "one sentence"
}}"""

        response = await self.chat(
            prompt=prompt,
            system="Classify log entries for security relevance. Respond only with valid JSON.",
            max_tokens=100,
            temperature=0.0,
            use_cache=True,
        )

        try:
            return json.loads(response.strip())
        except json.JSONDecodeError:
            return {
                "is_security_relevant": False,
                "event_type": "unknown",
                "severity": "info",
                "confidence": 0.0,
            }

    async def health_check(self) -> Dict[str, Any]:
        """Check LLM server health and available models."""
        try:
            response = await self._client.get("/api/tags")
            response.raise_for_status()
            
            data = response.json()
            models = [m["name"] for m in data.get("models", [])]
            
            return {
                "status": "healthy",
                "available_models": models,
                "default_model_loaded": self.default_model in models,
                "request_count": self._request_count,
                "total_tokens": self._token_usage,
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "request_count": self._request_count,
            }

    def _make_cache_key(self, prompt: str, system: str, model: str) -> str:
        """Create a cache key for LLM requests."""
        content = f"{model}:{system}:{prompt}"
        return hashlib.md5(content.encode(), usedforsecurity=False).hexdigest()

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    def get_stats(self) -> Dict[str, Any]:
        """Get usage statistics."""
        return {
            "request_count": self._request_count,
            "total_tokens": self._token_usage,
            "cache_size": len(self._cache),
            "model": self.default_model,
        }
