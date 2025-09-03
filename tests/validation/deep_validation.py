#!/usr/bin/env python3
"""
🛡️ NjordScan Deep Validation Suite

Comprehensive validation system that tests all aspects of NjordScan including:
- Import validation across all modules
- Configuration system testing
- CLI functionality testing
- Module system validation
- Orchestrator integration testing
- Full workflow simulation
- Package structure validation
"""

import sys
import os
import traceback
import importlib
import subprocess
import tempfile
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import time

# Add the package to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

@dataclass
class ValidationResult:
    """Result of a validation test."""
    test_name: str
    passed: bool
    message: str
    details: Optional[str] = None
    duration: float = 0.0

class DeepValidator:
    """Comprehensive validation system for NjordScan."""
    
    def __init__(self):
        self.results: List[ValidationResult] = []
        self.project_root = Path(__file__).parent.parent.parent
        self.package_root = self.project_root / "njordscan"
        
    def run_all_validations(self) -> Dict[str, Any]:
        """Run all validation tests."""
        print("🛡️  NjordScan Deep Validation Suite")
        print("=" * 60)
        
        # Test categories
        test_categories = [
            ("📦 Import Validation", self.validate_imports),
            ("⚙️  Configuration System", self.validate_configuration),
            ("🖥️  CLI Functionality", self.validate_cli),
            ("🔧 Module System", self.validate_modules),
            ("🧠 Orchestrator Integration", self.validate_orchestrators),
            ("🔍 Workflow Simulation", self.simulate_workflows),
            ("📋 Package Structure", self.validate_package_structure),
            ("🚀 Installation Readiness", self.validate_installation),
        ]
        
        for category_name, test_function in test_categories:
            print(f"\n{category_name}")
            print("-" * 40)
            
            try:
                test_function()
            except Exception as e:
                self.results.append(ValidationResult(
                    test_name=f"{category_name} - Critical Error",
                    passed=False,
                    message=f"Validation category failed: {str(e)}",
                    details=traceback.format_exc()
                ))
        
        return self.generate_report()
    
    def validate_imports(self):
        """Test all critical imports."""
        import_tests = [
            ("Core Package", "njordscan"),
            ("Configuration", "njordscan.config"),
            ("CLI Module", "njordscan.cli"),
            ("Scanner", "njordscan.scanner"),
            ("Vulnerability Model", "njordscan.vulnerability"),
            ("Utils", "njordscan.utils"),
            ("Cache", "njordscan.cache"),
        ]
        
        for test_name, module_name in import_tests:
            start_time = time.time()
            try:
                importlib.import_module(module_name)
                duration = time.time() - start_time
                self.results.append(ValidationResult(
                    test_name=f"Import - {test_name}",
                    passed=True,
                    message=f"Successfully imported {module_name}",
                    duration=duration
                ))
                print(f"✅ {test_name}")
            except Exception as e:
                duration = time.time() - start_time
                self.results.append(ValidationResult(
                    test_name=f"Import - {test_name}",
                    passed=False,
                    message=f"Failed to import {module_name}: {str(e)}",
                    details=traceback.format_exc(),
                    duration=duration
                ))
                print(f"❌ {test_name}: {str(e)}")
        
        # Test optional imports
        optional_imports = [
            ("Data Updater", "njordscan.data_updater"),
            ("Legacy Plugins", "njordscan.plugins"),
            ("Plugin Creator", "njordscan.plugin_creator"),
        ]
        
        for test_name, module_name in optional_imports:
            start_time = time.time()
            try:
                importlib.import_module(module_name)
                duration = time.time() - start_time
                self.results.append(ValidationResult(
                    test_name=f"Optional Import - {test_name}",
                    passed=True,
                    message=f"Successfully imported {module_name}",
                    duration=duration
                ))
                print(f"✅ {test_name} (Optional)")
            except Exception as e:
                duration = time.time() - start_time
                self.results.append(ValidationResult(
                    test_name=f"Optional Import - {test_name}",
                    passed=True,  # Optional imports are allowed to fail
                    message=f"Optional import not available: {module_name}",
                    details=str(e),
                    duration=duration
                ))
                print(f"⚠️  {test_name} (Optional - Not Available)")
    
    def validate_configuration(self):
        """Test configuration system."""
        try:
            from njordscan.config import Config, ScanMode, Theme, AIConfig, CommunityConfig
            
            # Test basic config creation
            start_time = time.time()
            config = Config()
            duration = time.time() - start_time
            self.results.append(ValidationResult(
                test_name="Config - Basic Creation",
                passed=True,
                message="Successfully created basic configuration",
                duration=duration
            ))
            print("✅ Basic Configuration Creation")
            
            # Test config with advanced features
            start_time = time.time()
            advanced_config = Config(
                ai_enhanced=True,
                behavioral_analysis=True,
                community_rules=True,
                mode="enterprise",
                theme="cyberpunk"
            )
            duration = time.time() - start_time
            self.results.append(ValidationResult(
                test_name="Config - Advanced Features",
                passed=True,
                message="Successfully created advanced configuration",
                duration=duration
            ))
            print("✅ Advanced Configuration Creation")
            
            # Test config validation
            start_time = time.time()
            issues = advanced_config.validate()
            duration = time.time() - start_time
            self.results.append(ValidationResult(
                test_name="Config - Validation",
                passed=len(issues) == 0,
                message=f"Configuration validation: {len(issues)} issues found",
                details="; ".join(issues) if issues else None,
                duration=duration
            ))
            if len(issues) == 0:
                print("✅ Configuration Validation")
            else:
                print(f"⚠️  Configuration Validation: {len(issues)} issues")
            
            # Test config serialization
            start_time = time.time()
            config_dict = config.to_dict()
            duration = time.time() - start_time
            self.results.append(ValidationResult(
                test_name="Config - Serialization",
                passed=isinstance(config_dict, dict) and len(config_dict) > 0,
                message="Configuration serialization successful",
                duration=duration
            ))
            print("✅ Configuration Serialization")
            
        except Exception as e:
            self.results.append(ValidationResult(
                test_name="Config - System Test",
                passed=False,
                message=f"Configuration system failed: {str(e)}",
                details=traceback.format_exc()
            ))
            print(f"❌ Configuration System: {str(e)}")
    
    def validate_cli(self):
        """Test CLI functionality."""
        try:
            from njordscan.cli import main
            from njordscan import __version__
            
            # Test CLI import
            self.results.append(ValidationResult(
                test_name="CLI - Import",
                passed=True,
                message="CLI module imported successfully"
            ))
            print("✅ CLI Import")
            
            # Test version access
            start_time = time.time()
            version = __version__
            duration = time.time() - start_time
            self.results.append(ValidationResult(
                test_name="CLI - Version Access",
                passed=version is not None and len(version) > 0,
                message=f"Version: {version}",
                duration=duration
            ))
            print(f"✅ Version Access: {version}")
            
            # Test CLI help (this would require subprocess for full test)
            # For now, just test that the main function exists and is callable
            start_time = time.time()
            is_callable = callable(main)
            duration = time.time() - start_time
            self.results.append(ValidationResult(
                test_name="CLI - Main Function",
                passed=is_callable,
                message="CLI main function is callable",
                duration=duration
            ))
            print("✅ CLI Main Function")
            
        except Exception as e:
            self.results.append(ValidationResult(
                test_name="CLI - Validation",
                passed=False,
                message=f"CLI validation failed: {str(e)}",
                details=traceback.format_exc()
            ))
            print(f"❌ CLI Validation: {str(e)}")
    
    def validate_modules(self):
        """Test module system."""
        try:
            from njordscan.modules import (
                get_available_modules, 
                get_module_class, 
                is_module_available,
                MODULE_REGISTRY
            )
            
            # Test module registry
            start_time = time.time()
            available_modules = get_available_modules()
            duration = time.time() - start_time
            self.results.append(ValidationResult(
                test_name="Modules - Registry",
                passed=isinstance(available_modules, list),
                message=f"Available modules: {available_modules}",
                duration=duration
            ))
            print(f"✅ Module Registry: {len(available_modules)} modules available")
            
            # Test each available module
            for module_name in available_modules:
                start_time = time.time()
                try:
                    module_class = get_module_class(module_name)
                    is_available = is_module_available(module_name)
                    duration = time.time() - start_time
                    
                    self.results.append(ValidationResult(
                        test_name=f"Module - {module_name}",
                        passed=module_class is not None and is_available,
                        message=f"Module {module_name} is available and loadable",
                        duration=duration
                    ))
                    print(f"✅ Module: {module_name}")
                except Exception as e:
                    duration = time.time() - start_time
                    self.results.append(ValidationResult(
                        test_name=f"Module - {module_name}",
                        passed=False,
                        message=f"Module {module_name} failed: {str(e)}",
                        details=traceback.format_exc(),
                        duration=duration
                    ))
                    print(f"❌ Module {module_name}: {str(e)}")
            
        except Exception as e:
            self.results.append(ValidationResult(
                test_name="Modules - System Test",
                passed=False,
                message=f"Module system failed: {str(e)}",
                details=traceback.format_exc()
            ))
            print(f"❌ Module System: {str(e)}")
    
    def validate_orchestrators(self):
        """Test orchestrator integration."""
        try:
            from njordscan.scanner import ScanOrchestrator, ADVANCED_ORCHESTRATORS
            from njordscan.config import Config
            
            # Test basic orchestrator
            start_time = time.time()
            config = Config()
            orchestrator = ScanOrchestrator(config)
            duration = time.time() - start_time
            
            self.results.append(ValidationResult(
                test_name="Orchestrator - Basic Creation",
                passed=orchestrator is not None,
                message="Basic orchestrator created successfully",
                duration=duration
            ))
            print("✅ Basic Orchestrator Creation")
            
            # Test advanced orchestrators availability
            self.results.append(ValidationResult(
                test_name="Orchestrator - Advanced Available",
                passed=True,  # This is informational
                message=f"Advanced orchestrators: {'Available' if ADVANCED_ORCHESTRATORS else 'Not Available'}",
            ))
            print(f"ℹ️  Advanced Orchestrators: {'Available' if ADVANCED_ORCHESTRATORS else 'Not Available'}")
            
            # Test orchestrator with advanced config
            if ADVANCED_ORCHESTRATORS:
                start_time = time.time()
                advanced_config = Config(ai_enhanced=True, mode="enterprise")
                advanced_orchestrator = ScanOrchestrator(advanced_config)
                duration = time.time() - start_time
                
                self.results.append(ValidationResult(
                    test_name="Orchestrator - Advanced Creation",
                    passed=advanced_orchestrator is not None,
                    message="Advanced orchestrator created successfully",
                    duration=duration
                ))
                print("✅ Advanced Orchestrator Creation")
            
        except Exception as e:
            self.results.append(ValidationResult(
                test_name="Orchestrator - Integration Test",
                passed=False,
                message=f"Orchestrator integration failed: {str(e)}",
                details=traceback.format_exc()
            ))
            print(f"❌ Orchestrator Integration: {str(e)}")
    
    def simulate_workflows(self):
        """Simulate complete workflows."""
        try:
            from njordscan.config import Config
            from njordscan.scanner import ScanOrchestrator
            from njordscan.modules import get_available_modules
            
            # Simulate basic scan workflow
            start_time = time.time()
            config = Config(target=".", mode="quick")
            orchestrator = ScanOrchestrator(config)
            
            # Test that orchestrator has the expected components
            has_modules = hasattr(orchestrator, 'modules')
            has_config = hasattr(orchestrator, 'config')
            has_formatter = hasattr(orchestrator, 'report_formatter')
            
            duration = time.time() - start_time
            workflow_success = has_modules and has_config and has_formatter
            
            self.results.append(ValidationResult(
                test_name="Workflow - Basic Setup",
                passed=workflow_success,
                message="Basic scan workflow setup successful",
                details=f"Modules: {has_modules}, Config: {has_config}, Formatter: {has_formatter}",
                duration=duration
            ))
            print("✅ Basic Workflow Setup")
            
            # Test configuration scenarios
            scenarios = [
                ("Quick Scan", {"mode": "quick", "target": "."}),
                ("Standard Scan", {"mode": "standard", "target": "."}),
                ("AI Enhanced", {"ai_enhanced": True, "target": "."}),
                ("Community Rules", {"community_rules": True, "target": "."}),
            ]
            
            for scenario_name, config_params in scenarios:
                start_time = time.time()
                try:
                    scenario_config = Config(**config_params)
                    scenario_orchestrator = ScanOrchestrator(scenario_config)
                    duration = time.time() - start_time
                    
                    self.results.append(ValidationResult(
                        test_name=f"Workflow - {scenario_name}",
                        passed=True,
                        message=f"{scenario_name} workflow setup successful",
                        duration=duration
                    ))
                    print(f"✅ {scenario_name} Workflow")
                except Exception as e:
                    duration = time.time() - start_time
                    self.results.append(ValidationResult(
                        test_name=f"Workflow - {scenario_name}",
                        passed=False,
                        message=f"{scenario_name} workflow failed: {str(e)}",
                        details=traceback.format_exc(),
                        duration=duration
                    ))
                    print(f"❌ {scenario_name} Workflow: {str(e)}")
            
        except Exception as e:
            self.results.append(ValidationResult(
                test_name="Workflow - Simulation",
                passed=False,
                message=f"Workflow simulation failed: {str(e)}",
                details=traceback.format_exc()
            ))
            print(f"❌ Workflow Simulation: {str(e)}")
    
    def validate_package_structure(self):
        """Validate package structure and entry points."""
        required_files = [
            "njordscan/__init__.py",
            "njordscan/__main__.py", 
            "njordscan/main.py",
            "njordscan/cli.py",
            "njordscan/config.py",
            "njordscan/scanner.py",
            "setup.py",
            "pyproject.toml",
            "requirements.txt",
            "README.md",
            "LICENSE",
        ]
        
        for file_path in required_files:
            full_path = self.project_root / file_path
            exists = full_path.exists()
            
            self.results.append(ValidationResult(
                test_name=f"Structure - {file_path}",
                passed=exists,
                message=f"File {'exists' if exists else 'missing'}: {file_path}"
            ))
            
            if exists:
                print(f"✅ {file_path}")
            else:
                print(f"❌ {file_path} - MISSING")
        
        # Test entry points
        try:
            from njordscan.main import main as main_entry
            self.results.append(ValidationResult(
                test_name="Structure - Main Entry Point",
                passed=callable(main_entry),
                message="Main entry point is callable"
            ))
            print("✅ Main Entry Point")
        except Exception as e:
            self.results.append(ValidationResult(
                test_name="Structure - Main Entry Point",
                passed=False,
                message=f"Main entry point failed: {str(e)}"
            ))
            print(f"❌ Main Entry Point: {str(e)}")
    
    def validate_installation(self):
        """Test installation readiness."""
        # Test package metadata
        try:
            from njordscan import __version__, __title__, __description__
            
            self.results.append(ValidationResult(
                test_name="Install - Package Metadata",
                passed=all([__version__, __title__, __description__]),
                message=f"Version: {__version__}, Title: {__title__}",
            ))
            print(f"✅ Package Metadata: {__version__}")
        except Exception as e:
            self.results.append(ValidationResult(
                test_name="Install - Package Metadata",
                passed=False,
                message=f"Package metadata failed: {str(e)}"
            ))
            print(f"❌ Package Metadata: {str(e)}")
        
        # Test setup.py syntax
        setup_py = self.project_root / "setup.py"
        if setup_py.exists():
            try:
                result = subprocess.run([
                    sys.executable, str(setup_py), "--help-commands"
                ], capture_output=True, text=True, timeout=30)
                
                self.results.append(ValidationResult(
                    test_name="Install - setup.py Syntax",
                    passed=result.returncode == 0,
                    message="setup.py syntax is valid" if result.returncode == 0 else "setup.py has syntax errors",
                    details=result.stderr if result.returncode != 0 else None
                ))
                
                if result.returncode == 0:
                    print("✅ setup.py Syntax")
                else:
                    print(f"❌ setup.py Syntax: {result.stderr[:100]}...")
            except Exception as e:
                self.results.append(ValidationResult(
                    test_name="Install - setup.py Syntax",
                    passed=False,
                    message=f"setup.py test failed: {str(e)}"
                ))
                print(f"❌ setup.py Test: {str(e)}")
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive validation report."""
        passed_tests = [r for r in self.results if r.passed]
        failed_tests = [r for r in self.results if not r.passed]
        
        total_duration = sum(r.duration for r in self.results)
        
        report = {
            "summary": {
                "total_tests": len(self.results),
                "passed": len(passed_tests),
                "failed": len(failed_tests),
                "success_rate": len(passed_tests) / len(self.results) * 100 if self.results else 0,
                "total_duration": total_duration,
            },
            "passed_tests": [
                {
                    "name": r.test_name,
                    "message": r.message,
                    "duration": r.duration
                } for r in passed_tests
            ],
            "failed_tests": [
                {
                    "name": r.test_name,
                    "message": r.message,
                    "details": r.details,
                    "duration": r.duration
                } for r in failed_tests
            ]
        }
        
        # Print summary
        print("\n" + "=" * 60)
        print("🛡️  VALIDATION SUMMARY")
        print("=" * 60)
        print(f"📊 Total Tests: {report['summary']['total_tests']}")
        print(f"✅ Passed: {report['summary']['passed']}")
        print(f"❌ Failed: {report['summary']['failed']}")
        print(f"📈 Success Rate: {report['summary']['success_rate']:.1f}%")
        print(f"⏱️  Total Duration: {report['summary']['total_duration']:.2f}s")
        
        if failed_tests:
            print(f"\n❌ FAILED TESTS:")
            for test in failed_tests:
                print(f"  • {test.test_name}: {test.message}")
        
        overall_status = "✅ PASSED" if len(failed_tests) == 0 else "❌ FAILED"
        print(f"\n🎯 Overall Status: {overall_status}")
        
        return report

def main():
    """Run deep validation."""
    validator = DeepValidator()
    report = validator.run_all_validations()
    
    # Save report
    report_file = Path(__file__).parent / "validation_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📄 Detailed report saved to: {report_file}")
    
    # Exit with appropriate code
    sys.exit(0 if report['summary']['failed'] == 0 else 1)

if __name__ == "__main__":
    main()
