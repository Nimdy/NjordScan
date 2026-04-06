"""
LLM-powered vulnerability analysis.

Supports Claude (Anthropic) and OpenAI for:
  1. Explaining findings in plain language with fix code
  2. Filtering false positives by providing code context
  3. Generating custom detection rules from natural language

Requires an API key set via environment variable or config:
  ANTHROPIC_API_KEY  or  OPENAI_API_KEY

Usage is opt-in via --explain-with-ai on the CLI.
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class LLMProvider(Enum):
    CLAUDE = "claude"
    OPENAI = "openai"


@dataclass
class LLMConfig:
    provider: LLMProvider = LLMProvider.CLAUDE
    api_key: Optional[str] = None
    model: Optional[str] = None  # None = use default per provider
    max_tokens: int = 1024
    temperature: float = 0.2

    def resolve_api_key(self) -> Optional[str]:
        if self.api_key:
            return self.api_key
        if self.provider == LLMProvider.CLAUDE:
            return os.environ.get('ANTHROPIC_API_KEY')
        return os.environ.get('OPENAI_API_KEY')

    def resolve_model(self) -> str:
        if self.model:
            return self.model
        if self.provider == LLMProvider.CLAUDE:
            return "claude-sonnet-4-20250514"
        return "gpt-4o-mini"


@dataclass
class LLMExplanation:
    """Result of asking the LLM to explain a finding."""
    summary: str
    risk_explanation: str
    fix_suggestion: str
    fix_code: str
    is_false_positive: bool
    confidence: float
    raw_response: str


class LLMAnalyzer:
    """Analyze vulnerabilities using Claude or OpenAI."""

    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or LLMConfig()
        self._api_key = self.config.resolve_api_key()
        self._model = self.config.resolve_model()

        if not self._api_key:
            raise ValueError(
                f"No API key found for {self.config.provider.value}. "
                f"Set {'ANTHROPIC_API_KEY' if self.config.provider == LLMProvider.CLAUDE else 'OPENAI_API_KEY'} "
                f"environment variable or pass api_key in config."
            )

    async def explain_finding(self, vuln: Dict[str, Any],
                              code_context: str,
                              file_path: str) -> LLMExplanation:
        """Ask the LLM to explain a vulnerability finding and suggest a fix."""
        prompt = self._build_explain_prompt(vuln, code_context, file_path)

        response = await self._call_llm(prompt)
        return self._parse_explanation(response)

    async def filter_false_positives(self,
                                      vulns: List[Dict[str, Any]],
                                      code_snippets: Dict[str, str]) -> List[Dict[str, Any]]:
        """Ask the LLM to identify likely false positives.

        Returns the input list with an added 'llm_false_positive' boolean
        and 'llm_reasoning' string on each vuln dict.
        """
        if not vulns:
            return vulns

        # Batch up to 10 findings per request to stay within token limits
        batch_size = 10
        for i in range(0, len(vulns), batch_size):
            batch = vulns[i:i + batch_size]
            prompt = self._build_fp_filter_prompt(batch, code_snippets)
            response = await self._call_llm(prompt)
            self._apply_fp_results(batch, response)

        return vulns

    # ----------------------------------------------------------------- #
    #  Prompt builders
    # ----------------------------------------------------------------- #

    def _build_explain_prompt(self, vuln: Dict[str, Any],
                               code_context: str, file_path: str) -> str:
        return f"""You are a security engineer reviewing a vulnerability finding from a static analysis tool.

**Finding:**
- Title: {vuln.get('title', 'Unknown')}
- Severity: {vuln.get('severity', 'unknown')}
- Type: {vuln.get('vuln_type', 'unknown')}
- File: {file_path}
- Line: {vuln.get('line_number', 'N/A')}
- Description: {vuln.get('description', '')}

**Code context:**
```
{code_context[:3000]}
```

Respond with a JSON object (no markdown fences) containing:
{{
  "summary": "1-2 sentence plain-language explanation of the issue",
  "risk_explanation": "What an attacker could do if this is exploited",
  "fix_suggestion": "How to fix it in plain language",
  "fix_code": "Corrected code snippet (just the fixed lines)",
  "is_false_positive": true/false,
  "confidence": 0.0-1.0
}}"""

    def _build_fp_filter_prompt(self, vulns: List[Dict[str, Any]],
                                 code_snippets: Dict[str, str]) -> str:
        findings = []
        for i, v in enumerate(vulns):
            snippet = code_snippets.get(v.get('file_path', ''), '')[:500]
            findings.append(
                f"[{i}] {v.get('title', '')} | {v.get('severity', '')} | "
                f"File: {v.get('file_path', '')} | Line: {v.get('line_number', '')}\\n"
                f"Code: {snippet}"
            )

        return f"""You are a security engineer filtering false positives from a static analysis scan.

For each finding below, determine if it is a true positive or false positive.

**Findings:**
{'\\n\\n'.join(findings)}

Respond with a JSON array (no markdown fences). Each element should be:
{{
  "index": <int>,
  "is_false_positive": true/false,
  "reasoning": "brief explanation"
}}"""

    # ----------------------------------------------------------------- #
    #  LLM API calls
    # ----------------------------------------------------------------- #

    async def _call_llm(self, prompt: str) -> str:
        if self.config.provider == LLMProvider.CLAUDE:
            return await self._call_claude(prompt)
        return await self._call_openai(prompt)

    async def _call_claude(self, prompt: str) -> str:
        """Call the Anthropic Claude API."""
        try:
            import httpx
        except ImportError:
            raise ImportError("httpx is required for Claude API calls: pip install httpx")

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self._api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self._model,
                    "max_tokens": self.config.max_tokens,
                    "temperature": self.config.temperature,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            response.raise_for_status()
            data = response.json()
            return data["content"][0]["text"]

    async def _call_openai(self, prompt: str) -> str:
        """Call the OpenAI API."""
        try:
            import httpx
        except ImportError:
            raise ImportError("httpx is required for OpenAI API calls: pip install httpx")

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self._model,
                    "max_tokens": self.config.max_tokens,
                    "temperature": self.config.temperature,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]

    # ----------------------------------------------------------------- #
    #  Response parsers
    # ----------------------------------------------------------------- #

    def _parse_explanation(self, response: str) -> LLMExplanation:
        """Parse the LLM explanation response."""
        try:
            # Strip markdown fences if present
            text = response.strip()
            if text.startswith('```'):
                text = text.split('\n', 1)[1] if '\n' in text else text[3:]
            if text.endswith('```'):
                text = text[:-3]
            text = text.strip()

            data = json.loads(text)
            return LLMExplanation(
                summary=data.get("summary", ""),
                risk_explanation=data.get("risk_explanation", ""),
                fix_suggestion=data.get("fix_suggestion", ""),
                fix_code=data.get("fix_code", ""),
                is_false_positive=data.get("is_false_positive", False),
                confidence=float(data.get("confidence", 0.5)),
                raw_response=response,
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            return LLMExplanation(
                summary=response[:200],
                risk_explanation="",
                fix_suggestion="",
                fix_code="",
                is_false_positive=False,
                confidence=0.5,
                raw_response=response,
            )

    def _apply_fp_results(self, batch: List[Dict[str, Any]], response: str):
        """Apply false-positive filtering results to the batch."""
        try:
            text = response.strip()
            if text.startswith('```'):
                text = text.split('\n', 1)[1] if '\n' in text else text[3:]
            if text.endswith('```'):
                text = text[:-3]
            text = text.strip()

            results = json.loads(text)
            for item in results:
                idx = item.get("index")
                if idx is not None and 0 <= idx < len(batch):
                    batch[idx]["llm_false_positive"] = item.get("is_false_positive", False)
                    batch[idx]["llm_reasoning"] = item.get("reasoning", "")
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse FP filter response: {e}")
            for v in batch:
                v["llm_false_positive"] = False
                v["llm_reasoning"] = "LLM response could not be parsed"
