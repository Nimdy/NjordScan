"""
Tests for Scanner functionality.
"""

import pytest
import tempfile
from pathlib import Path
from njordscan.scanner import Scanner
from njordscan.config import Config

def test_scanner_initialization():
    """Test scanner initialization."""
    config = Config(target=".", mode="static")
    scanner = Scanner(config)
    assert scanner.config == config
    assert len(scanner.modules) > 0

@pytest.mark.asyncio
async def test_scanner_with_temp_directory():
    """Test scanner with temporary directory."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a simple package.json
        package_json = Path(temp_dir) / "package.json"
        package_json.write_text('{"name": "test", "dependencies": {"react": "^18.0.0"}}')
        
        config = Config(target=temp_dir, mode="static")
        scanner = Scanner(config)
        results = await scanner.scan()
        
        assert results['target'] == temp_dir
        assert results['framework'] in ['react', 'unknown']
        assert 'vulnerabilities' in results