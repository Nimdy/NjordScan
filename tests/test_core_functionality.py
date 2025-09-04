#!/usr/bin/env python3
"""
Test suite for NjordScan core functionality.
"""

import pytest
import sys
import os
import tempfile
import json
from unittest.mock import patch, MagicMock

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from njordscan.scanner import Scanner
from njordscan.config import Config
from njordscan.utils import load_config, validate_target


class TestScanner:
    """Test Scanner core functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.scanner = Scanner()
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_scanner_initialization(self):
        """Test scanner initialization."""
        assert self.scanner is not None
        assert hasattr(self.scanner, 'scan')
    
    def test_scan_empty_directory(self):
        """Test scanning an empty directory."""
        result = self.scanner.scan(self.temp_dir)
        assert result is not None
        assert 'status' in result
    
    def test_scan_with_files(self):
        """Test scanning a directory with files."""
        # Create test files
        test_files = {
            'test.js': 'console.log("Hello World");',
            'test.py': 'print("Hello World")',
            'test.html': '<html><body>Hello World</body></html>'
        }
        
        for filename, content in test_files.items():
            filepath = os.path.join(self.temp_dir, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
        
        result = self.scanner.scan(self.temp_dir)
        assert result is not None
        assert 'status' in result
        assert 'files_scanned' in result
    
    def test_scan_with_vulnerabilities(self):
        """Test scanning files with potential vulnerabilities."""
        # Create a file with potential XSS vulnerability
        vulnerable_file = os.path.join(self.temp_dir, 'vulnerable.html')
        with open(vulnerable_file, 'w', encoding='utf-8') as f:
            f.write('<script>document.write(document.URL)</script>')
        
        result = self.scanner.scan(self.temp_dir)
        assert result is not None
        # Should detect potential XSS vulnerability


class TestConfig:
    """Test configuration functionality."""
    
    def test_config_initialization(self):
        """Test config initialization."""
        config = Config()
        assert config is not None
        assert hasattr(config, 'get')
        assert hasattr(config, 'set')
    
    def test_config_defaults(self):
        """Test default configuration values."""
        config = Config()
        # Test some default values
        assert config.get('scan_mode', 'quick') == 'quick'
        assert config.get('output_format', 'json') == 'json'
    
    def test_config_set_get(self):
        """Test setting and getting configuration values."""
        config = Config()
        config.set('test_key', 'test_value')
        assert config.get('test_key') == 'test_value'
    
    def test_config_validation(self):
        """Test configuration validation."""
        config = Config()
        # Test valid values
        assert config.validate_scan_mode('quick') == True
        assert config.validate_scan_mode('standard') == True
        assert config.validate_scan_mode('deep') == True
        
        # Test invalid values
        assert config.validate_scan_mode('invalid') == False


class TestUtils:
    """Test utility functions."""
    
    def test_load_config(self):
        """Test loading configuration from file."""
        # Create a temporary config file
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
            assert config is not None
            assert config.get('scan_mode') == 'standard'
            assert config.get('output_format') == 'json'
            assert config.get('verbose') == True
        finally:
            os.unlink(config_file)
    
    def test_validate_target(self):
        """Test target validation."""
        # Test valid directory
        with tempfile.TemporaryDirectory() as temp_dir:
            assert validate_target(temp_dir) == True
        
        # Test invalid path
        assert validate_target('/nonexistent/path') == False
        
        # Test file instead of directory
        with tempfile.NamedTemporaryFile() as temp_file:
            assert validate_target(temp_file.name) == True  # Files are also valid targets


class TestModules:
    """Test individual module functionality."""
    
    def test_static_analysis_module(self):
        """Test static analysis module."""
        from njordscan.modules.code_static import StaticCodeAnalyzer
        
        analyzer = StaticCodeAnalyzer()
        assert analyzer is not None
        
        # Test with sample code
        sample_code = '''
        function test() {
            var userInput = document.getElementById('input').value;
            document.getElementById('output').innerHTML = userInput;
        }
        '''
        
        result = analyzer.analyze(sample_code, 'test.js')
        assert result is not None
        assert 'vulnerabilities' in result
    
    def test_dependency_analysis_module(self):
        """Test dependency analysis module."""
        from njordscan.modules.dependencies import DependencyAnalyzer
        
        analyzer = DependencyAnalyzer()
        assert analyzer is not None
        
        # Test with package.json-like data
        package_data = {
            'dependencies': {
                'express': '^4.18.0',
                'lodash': '^4.17.21'
            }
        }
        
        result = analyzer.analyze(package_data)
        assert result is not None
        assert 'dependencies' in result
    
    def test_security_headers_module(self):
        """Test security headers module."""
        from njordscan.modules.headers import SecurityHeadersAnalyzer
        
        analyzer = SecurityHeadersAnalyzer()
        assert analyzer is not None
        
        # Test with sample headers
        headers = {
            'Content-Security-Policy': "default-src 'self'",
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff'
        }
        
        result = analyzer.analyze(headers)
        assert result is not None
        assert 'security_headers' in result


class TestIntegration:
    """Test integration scenarios."""
    
    def test_full_scan_workflow(self):
        """Test complete scan workflow."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            test_files = {
                'index.html': '''
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Test Page</title>
                </head>
                <body>
                    <script>
                        var userInput = prompt("Enter your name:");
                        document.write("Hello " + userInput);
                    </script>
                </body>
                </html>
                ''',
                'package.json': '''
                {
                    "name": "test-app",
                    "version": "1.0.0",
                    "dependencies": {
                        "express": "^4.18.0",
                        "lodash": "^4.17.21"
                    }
                }
                '''
            }
            
            for filename, content in test_files.items():
                filepath = os.path.join(temp_dir, filename)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
            
            # Run full scan
            scanner = Scanner()
            result = scanner.scan(temp_dir, mode='standard')
            
            assert result is not None
            assert 'status' in result
            assert 'files_scanned' in result
            assert 'vulnerabilities' in result
            assert 'dependencies' in result
    
    def test_error_handling(self):
        """Test error handling in various scenarios."""
        scanner = Scanner()
        
        # Test with invalid target
        result = scanner.scan('/nonexistent/path')
        assert result is not None
        assert 'error' in result or 'status' in result
        
        # Test with permission denied (if possible)
        # This might not work on all systems, so we'll just ensure it doesn't crash
        try:
            result = scanner.scan('/root')  # Usually requires root access
            assert result is not None
        except PermissionError:
            pass  # Expected on some systems


if __name__ == '__main__':
    pytest.main([__file__])
