#!/usr/bin/env python3
"""
Test suite for NjordScan CLI functionality.
"""

import pytest
import sys
import os
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from njordscan.cli import main, scan, version, doctor


class TestCLI:
    """Test CLI functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.runner = CliRunner()
    
    def test_main_help(self):
        """Test main CLI help command."""
        result = self.runner.invoke(main, ['--help'])
        assert result.exit_code == 0
        assert 'NjordScan' in result.output
        assert 'scan' in result.output
        assert 'version' in result.output
        assert 'doctor' in result.output
    
    def test_version_command(self):
        """Test version command."""
        result = self.runner.invoke(version)
        assert result.exit_code == 0
        assert 'NjordScan' in result.output
        assert 'version' in result.output.lower()
    
    def test_doctor_command(self):
        """Test doctor command."""
        result = self.runner.invoke(doctor)
        assert result.exit_code == 0
        assert 'system' in result.output.lower() or 'check' in result.output.lower()
    
    def test_scan_help(self):
        """Test scan command help."""
        result = self.runner.invoke(scan, ['--help'])
        assert result.exit_code == 0
        assert 'scan' in result.output.lower()
        assert 'target' in result.output.lower()
    
    @patch('njordscan.cli.ScanOrchestrator')
    def test_scan_basic(self, mock_orchestrator):
        """Test basic scan functionality."""
        # Mock the orchestrator
        mock_instance = MagicMock()
        mock_orchestrator.return_value = mock_instance
        mock_instance.scan.return_value = {'status': 'completed', 'findings': []}
        
        # Create a temporary directory for testing
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.runner.invoke(scan, [temp_dir, '--mode', 'quick'])
            assert result.exit_code == 0
    
    def test_scan_invalid_target(self):
        """Test scan with invalid target."""
        result = self.runner.invoke(scan, ['/nonexistent/path'])
        assert result.exit_code != 0
    
    def test_scan_modes(self):
        """Test different scan modes."""
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            # Test quick mode
            result = self.runner.invoke(scan, [temp_dir, '--mode', 'quick'])
            assert result.exit_code == 0
            
            # Test standard mode
            result = self.runner.invoke(scan, [temp_dir, '--mode', 'standard'])
            assert result.exit_code == 0
            
            # Test deep mode
            result = self.runner.invoke(scan, [temp_dir, '--mode', 'deep'])
            assert result.exit_code == 0
    
    def test_scan_output_formats(self):
        """Test different output formats."""
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            # Test JSON output
            result = self.runner.invoke(scan, [temp_dir, '--output-format', 'json'])
            assert result.exit_code == 0
            
            # Test HTML output
            result = self.runner.invoke(scan, [temp_dir, '--output-format', 'html'])
            assert result.exit_code == 0
    
    def test_scan_verbose_mode(self):
        """Test verbose mode."""
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.runner.invoke(scan, [temp_dir, '--verbose'])
            assert result.exit_code == 0
    
    def test_scan_ai_enhanced(self):
        """Test AI-enhanced scanning."""
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.runner.invoke(scan, [temp_dir, '--ai-enhanced'])
            assert result.exit_code == 0


if __name__ == '__main__':
    pytest.main([__file__])
