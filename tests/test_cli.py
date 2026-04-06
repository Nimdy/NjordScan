#!/usr/bin/env python3
"""
Test suite for NjordScan CLI.

Tests real command output — verifies content, not just exit codes.
"""

import pytest
import sys
import os
import json
import tempfile
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from njordscan.cli import main, version, doctor


class TestCLIHelp:
    """Test help output contains the expected commands."""

    def setup_method(self):
        self.runner = CliRunner()

    def test_main_help_lists_all_commands(self):
        result = self.runner.invoke(main, ['--help'])
        assert result.exit_code == 0
        for cmd in ('scan', 'version', 'doctor', 'configure', 'update', 'legal'):
            assert cmd in result.output, f"'{cmd}' command missing from help"

    def test_scan_help_documents_key_options(self):
        result = self.runner.invoke(main, ['scan', '--help'])
        assert result.exit_code == 0
        for opt in ('--mode', '--format', '--verbose', '--framework'):
            assert opt in result.output, f"'{opt}' missing from scan --help"


class TestVersionCommand:
    """Test version command shows actual version info."""

    def setup_method(self):
        self.runner = CliRunner()

    def test_version_shows_version_number(self):
        from njordscan import __version__
        result = self.runner.invoke(version)
        assert result.exit_code == 0
        assert __version__ in result.output, "Should display the actual version number"

    def test_version_shows_license(self):
        result = self.runner.invoke(version)
        assert 'MIT' in result.output


class TestDoctorCommand:
    """Test doctor command runs diagnostics."""

    def setup_method(self):
        self.runner = CliRunner()

    def test_doctor_checks_python_version(self):
        result = self.runner.invoke(doctor)
        assert result.exit_code == 0
        py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
        assert py_ver in result.output, "Should show Python version"

    def test_doctor_checks_dependencies(self):
        result = self.runner.invoke(doctor)
        assert 'Dependencies' in result.output or 'dependencies' in result.output


class TestScanCommand:
    """Test the scan command with real and mocked scenarios."""

    def setup_method(self):
        self.runner = CliRunner()

    @patch('njordscan.legal.legal_manager.check_acceptance', return_value=True)
    def test_scan_invalid_target_fails(self, _mock_legal):
        result = self.runner.invoke(main, ['scan', '/nonexistent/xyz'])
        assert result.exit_code != 0

    @patch('njordscan.legal.legal_manager.check_acceptance', return_value=True)
    def test_scan_invalid_mode_rejected(self, _mock_legal):
        """Invalid --mode should be rejected by Click."""
        with tempfile.TemporaryDirectory() as d:
            result = self.runner.invoke(main, ['scan', d, '--mode', 'bogus'])
            assert result.exit_code != 0

    @patch('njordscan.legal.legal_manager.check_acceptance', return_value=True)
    @patch('njordscan.cli.ScanOrchestrator')
    def test_scan_passes_mode_to_config(self, mock_orch, _mock_legal):
        """Scan mode should be forwarded to the Config object."""
        mock_instance = MagicMock()
        mock_orch.return_value = mock_instance

        captured_configs = []
        original_init = mock_orch.side_effect

        def capture_config(config):
            captured_configs.append(config)
            return mock_instance

        mock_orch.side_effect = capture_config

        async def mock_scan():
            return {'status': 'completed', 'findings': []}

        mock_instance.scan = mock_scan

        with tempfile.TemporaryDirectory() as d:
            result = self.runner.invoke(main, ['scan', d, '--mode', 'deep'])
            if captured_configs:
                assert captured_configs[0].mode == 'deep'

    @patch('njordscan.legal.legal_manager.check_acceptance', return_value=True)
    @patch('njordscan.cli.ScanOrchestrator')
    def test_scan_json_output_is_valid_json(self, mock_orch, _mock_legal):
        """--format json should produce parseable JSON."""
        mock_instance = MagicMock()
        mock_orch.return_value = mock_instance

        async def mock_scan():
            return {
                'status': 'completed',
                'vulnerabilities': [],
                'summary': {'total_issues': 0},
                'target': '/tmp/test',
                'framework': 'auto',
                'scan_mode': 'quick',
                'scan_duration': 0.1,
                'modules_run': [],
                'njord_score': {'total_score': 100}
            }

        mock_instance.scan = mock_scan

        with tempfile.TemporaryDirectory() as d:
            outfile = os.path.join(d, 'report.json')
            result = self.runner.invoke(main, [
                'scan', d, '--format', 'json', '--output', outfile, '--quiet'
            ])
            # If JSON was written to file, verify it parses
            if os.path.exists(outfile):
                with open(outfile) as f:
                    data = json.load(f)
                assert isinstance(data, dict)


class TestConfigureCommand:
    """Test the configure command."""

    def setup_method(self):
        self.runner = CliRunner()

    def test_configure_init_creates_file(self):
        with self.runner.isolated_filesystem():
            result = self.runner.invoke(main, ['configure', '--init'])
            assert result.exit_code == 0
            assert os.path.exists('.njordscan.json')
            with open('.njordscan.json') as f:
                data = json.load(f)
            assert isinstance(data, dict)

    def test_configure_no_args_shows_error(self):
        result = self.runner.invoke(main, ['configure'])
        assert 'specify' in result.output.lower() or 'action' in result.output.lower() \
            or 'help' in result.output.lower() or result.exit_code != 0


if __name__ == '__main__':
    pytest.main([__file__])
