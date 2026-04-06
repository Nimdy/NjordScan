#!/usr/bin/env python3
"""
Tests for the LLM analyzer — prompt construction and response parsing.
Does NOT make actual API calls.
"""

import pytest
import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from njordscan.analysis.llm_analyzer import (
    LLMAnalyzer, LLMConfig, LLMProvider, LLMExplanation
)


class TestLLMConfig:

    def test_default_provider_is_claude(self):
        cfg = LLMConfig()
        assert cfg.provider == LLMProvider.CLAUDE

    def test_resolve_model_claude(self):
        cfg = LLMConfig(provider=LLMProvider.CLAUDE)
        assert 'claude' in cfg.resolve_model().lower() or 'sonnet' in cfg.resolve_model().lower()

    def test_resolve_model_openai(self):
        cfg = LLMConfig(provider=LLMProvider.OPENAI)
        assert 'gpt' in cfg.resolve_model().lower()

    def test_custom_model_overrides(self):
        cfg = LLMConfig(model="my-custom-model")
        assert cfg.resolve_model() == "my-custom-model"

    def test_resolve_api_key_from_config(self):
        cfg = LLMConfig(api_key="sk-test-123")
        assert cfg.resolve_api_key() == "sk-test-123"

    def test_raises_without_api_key(self):
        # Clear env vars to ensure no key is found
        env_backup = {k: os.environ.pop(k) for k in ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY'] if k in os.environ}
        try:
            with pytest.raises(ValueError, match="No API key"):
                LLMAnalyzer(LLMConfig(provider=LLMProvider.CLAUDE))
        finally:
            os.environ.update(env_backup)


class TestResponseParsing:

    @pytest.fixture
    def analyzer(self):
        """Create analyzer with a fake key (won't make real calls)."""
        return LLMAnalyzer(LLMConfig(api_key="sk-fake-for-testing"))

    def test_parse_valid_json_response(self, analyzer):
        response = json.dumps({
            "summary": "XSS vulnerability found",
            "risk_explanation": "Attacker can inject scripts",
            "fix_suggestion": "Use textContent instead of innerHTML",
            "fix_code": "el.textContent = userInput;",
            "is_false_positive": False,
            "confidence": 0.92
        })
        result = analyzer._parse_explanation(response)
        assert isinstance(result, LLMExplanation)
        assert result.summary == "XSS vulnerability found"
        assert result.fix_code == "el.textContent = userInput;"
        assert result.is_false_positive is False
        assert result.confidence == 0.92

    def test_parse_json_with_markdown_fences(self, analyzer):
        response = '```json\n{"summary": "test", "confidence": 0.5}\n```'
        result = analyzer._parse_explanation(response)
        assert result.summary == "test"

    def test_parse_invalid_json_gracefully(self, analyzer):
        response = "This is not JSON at all, just plain text explanation."
        result = analyzer._parse_explanation(response)
        assert isinstance(result, LLMExplanation)
        assert result.raw_response == response
        assert result.confidence == 0.5  # default

    def test_apply_fp_results_valid(self, analyzer):
        batch = [
            {"title": "XSS", "severity": "high"},
            {"title": "SQL Injection", "severity": "critical"},
        ]
        response = json.dumps([
            {"index": 0, "is_false_positive": True, "reasoning": "Static string, not user input"},
            {"index": 1, "is_false_positive": False, "reasoning": "Real injection risk"},
        ])
        analyzer._apply_fp_results(batch, response)
        assert batch[0]["llm_false_positive"] is True
        assert batch[1]["llm_false_positive"] is False
        assert "Static string" in batch[0]["llm_reasoning"]

    def test_apply_fp_results_bad_json(self, analyzer):
        batch = [{"title": "XSS"}]
        analyzer._apply_fp_results(batch, "not json")
        assert batch[0]["llm_false_positive"] is False


class TestPromptConstruction:

    @pytest.fixture
    def analyzer(self):
        return LLMAnalyzer(LLMConfig(api_key="sk-fake"))

    def test_explain_prompt_contains_vuln_info(self, analyzer):
        vuln = {"title": "XSS via innerHTML", "severity": "high",
                "vuln_type": "xss_dom", "line_number": 42,
                "description": "Tainted data flows to innerHTML"}
        prompt = analyzer._build_explain_prompt(vuln, "el.innerHTML = x;", "app.js")
        assert "XSS via innerHTML" in prompt
        assert "app.js" in prompt
        assert "innerHTML" in prompt

    def test_fp_filter_prompt_contains_findings(self, analyzer):
        vulns = [
            {"title": "Finding 1", "severity": "high", "file_path": "a.js", "line_number": 10},
            {"title": "Finding 2", "severity": "low", "file_path": "b.js", "line_number": 20},
        ]
        prompt = analyzer._build_fp_filter_prompt(vulns, {"a.js": "code here"})
        assert "Finding 1" in prompt
        assert "Finding 2" in prompt
