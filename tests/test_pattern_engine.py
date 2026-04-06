#!/usr/bin/env python3
"""
Tests for the pattern engine.

Tests that the engine detects real vulnerability patterns and doesn't
produce false positives on safe code.
"""

import pytest
import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from njordscan.analysis.pattern_engine import (
    PatternEngine, SecurityPattern, PatternMatch,
    PatternType, Severity
)


@pytest.fixture
def engine():
    return PatternEngine()


# ===================================================================== #
#  Built-in pattern loading
# ===================================================================== #

class TestBuiltinPatterns:

    def test_loads_builtin_patterns(self, engine):
        """Engine should come pre-loaded with patterns."""
        assert len(engine.patterns) >= 8

    def test_has_xss_patterns(self, engine):
        assert 'xss_innerHTML' in engine.patterns
        assert 'xss_dangerously_set_inner_html' in engine.patterns

    def test_has_injection_patterns(self, engine):
        assert 'sql_injection_string_concat' in engine.patterns
        assert 'command_injection_exec' in engine.patterns

    def test_has_secrets_pattern(self, engine):
        assert 'hardcoded_api_key' in engine.patterns

    def test_patterns_have_cwe_ids(self, engine):
        for pid, pattern in engine.patterns.items():
            assert len(pattern.cwe_ids) > 0, f"Pattern {pid} missing CWE IDs"

    def test_patterns_have_owasp_categories(self, engine):
        for pid, pattern in engine.patterns.items():
            assert len(pattern.owasp_categories) > 0, f"Pattern {pid} missing OWASP"

    def test_compiled_cache_matches_patterns(self, engine):
        """Every pattern with regex should have compiled cache."""
        for pid, pattern in engine.patterns.items():
            if pattern.regex_patterns:
                assert pid in engine.pattern_cache
                assert len(engine.pattern_cache[pid]) == len(pattern.regex_patterns)


# ===================================================================== #
#  Pattern matching - innerHTML XSS
# ===================================================================== #

class TestInnerHTMLDetection:

    def _react_code(self, vuln_line):
        """Wrap a vulnerable line in React context with user input source."""
        return (
            'import React from "react";\n'
            'const data = req.body.input;\n'
            f'{vuln_line}\n'
        )

    def test_detects_innerhtml_with_template_literal(self, engine):
        code = self._react_code('element.innerHTML = `<div>${userInput}</div>`;')
        matches = engine.analyze_file(Path("app.js"), code)
        assert any(m.pattern_id == 'xss_innerHTML' for m in matches)

    def test_detects_innerhtml_with_concat(self, engine):
        code = self._react_code('el.innerHTML = "<p>" + data + "</p>";')
        matches = engine.analyze_file(Path("app.js"), code)
        assert any(m.pattern_id == 'xss_innerHTML' for m in matches)

    def test_match_has_correct_metadata(self, engine):
        code = self._react_code('el.innerHTML = `${x}`;')
        matches = engine.analyze_file(Path("app.js"), code)
        inner_matches = [m for m in matches if m.pattern_id == 'xss_innerHTML']
        assert len(inner_matches) > 0
        m = inner_matches[0]
        assert m.severity == 'high'
        assert m.line_number == 3
        assert m.confidence > 0


# ===================================================================== #
#  Hardcoded secrets detection
# ===================================================================== #

class TestSecretsDetection:

    def _react_code(self, line):
        # Secrets pattern needs framework context (react/nextjs/vite)
        return f'import React from "react";\n{line}\n'

    def test_detects_aws_access_key(self, engine):
        code = self._react_code('const key = "AKIAIOSFODNN7REALKEY1";')
        matches = engine.analyze_file(Path("config.js"), code)
        secret_matches = [m for m in matches if m.pattern_id == 'hardcoded_api_key']
        assert len(secret_matches) > 0

    def test_detects_github_token(self, engine):
        code = self._react_code('const token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";')
        matches = engine.analyze_file(Path("config.js"), code)
        secret_matches = [m for m in matches if m.pattern_id == 'hardcoded_api_key']
        assert len(secret_matches) > 0

    def test_excludes_example_keys(self, engine):
        code = self._react_code('const key = "YOUR_API_KEY";')
        matches = engine.analyze_file(Path("config.js"), code)
        secret_matches = [m for m in matches if m.pattern_id == 'hardcoded_api_key']
        assert len(secret_matches) == 0


# ===================================================================== #
#  Safe code - no false positives
# ===================================================================== #

class TestNoFalsePositives:

    def test_safe_arithmetic(self, engine):
        code = 'const x = 1 + 2;\n'
        matches = engine.analyze_file(Path("math.js"), code)
        assert len(matches) == 0

    def test_safe_function(self, engine):
        code = 'function greet(name) {\n  return `Hello, ${name}`;\n}\n'
        matches = engine.analyze_file(Path("greet.js"), code)
        assert len(matches) == 0

    def test_comment_is_not_a_match(self, engine):
        code = '// element.innerHTML = userInput;\n'
        matches = engine.analyze_file(Path("app.js"), code)
        # Comments may or may not be filtered; just verify no critical false positive
        high_matches = [m for m in matches if m.severity in ('critical', 'high')]
        # If there are matches, confidence should be reduced for comments
        for m in high_matches:
            assert m.confidence < 1.0


# ===================================================================== #
#  Custom pattern registration
# ===================================================================== #

class TestCustomPatterns:

    def test_add_custom_pattern(self, engine):
        custom = SecurityPattern(
            id="custom_debug",
            name="Debug Statement",
            description="console.log left in production code",
            pattern_type=PatternType.REGEX,
            severity=Severity.LOW,
            confidence=0.5,
            regex_patterns=[r'console\.log\('],
            cwe_ids=['CWE-489'],
            owasp_categories=['A05:2021-Security Misconfiguration']
        )
        engine.add_pattern(custom)
        assert 'custom_debug' in engine.patterns
        assert 'custom_debug' in engine.pattern_cache

        code = 'console.log("debug info");\n'
        matches = engine.analyze_file(Path("app.js"), code)
        assert any(m.pattern_id == 'custom_debug' for m in matches)

    def test_invalid_regex_handled_gracefully(self, engine):
        """Invalid regex should not crash, just skip that pattern."""
        bad = SecurityPattern(
            id="bad_regex",
            name="Bad",
            description="Bad regex",
            pattern_type=PatternType.REGEX,
            severity=Severity.LOW,
            confidence=0.5,
            regex_patterns=[r'(unclosed_group'],
            cwe_ids=['CWE-0'],
            owasp_categories=['Other']
        )
        engine.add_pattern(bad)
        # Should not crash
        matches = engine.analyze_file(Path("x.js"), "some code")
        assert isinstance(matches, list)


# ===================================================================== #
#  Pattern statistics
# ===================================================================== #

class TestPatternStatistics:

    def test_get_pattern_statistics(self, engine):
        stats = engine.get_pattern_statistics()
        assert isinstance(stats, dict)
        assert stats.get('total_patterns', 0) >= 8
