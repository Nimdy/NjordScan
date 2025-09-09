"""
Tests for CLI functionality.
"""

import pytest
from click.testing import CliRunner
from njordscan.cli import main

def test_cli_help():
    """Test CLI help output."""
    runner = CliRunner()
    result = runner.invoke(main, ['--help'])
    assert result.exit_code == 0
    assert 'NjordScan' in result.output

def test_cli_version():
    """Test version command."""
    runner = CliRunner()
    result = runner.invoke(main, ['version'])
    assert result.exit_code == 0
    assert 'version' in result.output.lower()

def test_cli_explain():
    """Test explain command."""
    runner = CliRunner()
    result = runner.invoke(main, ['explain', 'xss'])
    assert result.exit_code == 0