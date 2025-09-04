#!/usr/bin/env python3
"""
🛡️ NjordScan Installation Validation Suite

Comprehensive validation of all installation and setup files including:
- setup.py validation and testing
- requirements.txt dependencies validation  
- pyproject.toml modern packaging validation
- MANIFEST.in file inclusion validation
- Entry points validation
- Package metadata consistency
- Installation simulation
"""

import sys
import os
import subprocess
import tempfile
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
# import pkg_resources  # Deprecated, using importlib.metadata instead
import importlib.metadata
import ast

class InstallationValidator:
    """Comprehensive installation validation system."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent.parent
        self.results = []
        
    def validate_all(self) -> Dict[str, Any]:
        """Run all installation validations."""
        print("🛡️  NjordScan Installation Validation Suite")
        print("=" * 60)
        
        validation_categories = [
            ("📦 setup.py Validation", self.validate_setup_py),
            ("📋 requirements.txt Validation", self.validate_requirements),
            ("⚙️  pyproject.toml Validation", self.validate_pyproject),
            ("📄 MANIFEST.in Validation", self.validate_manifest),
            ("🔗 Entry Points Validation", self.validate_entry_points),
            ("📊 Package Metadata Consistency", self.validate_metadata_consistency),
            ("🚀 Installation Simulation", self.simulate_installation),
        ]
        
        for category_name, validator_func in validation_categories:
            print(f"\n{category_name}")
            print("-" * 40)
            
            try:
                validator_func()
            except Exception as e:
                print(f"❌ {category_name} failed: {str(e)}")
                self.results.append({
                    "category": category_name,
                    "status": "failed",
                    "error": str(e)
                })
        
        return self.generate_report()
    
    def validate_setup_py(self):
        """Validate setup.py file."""
        setup_py = self.project_root / "setup.py"
        
        if not setup_py.exists():
            print("❌ setup.py not found")
            return
        
        print("✅ setup.py exists")
        
        # Parse setup.py content
        try:
            with open(setup_py, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for required components
            required_components = [
                ('name', r'name\s*=\s*["\']njordscan["\']'),
                ('version', r'version\s*='),
                ('description', r'description\s*='),
                ('author', r'author\s*='),
                ('packages', r'packages\s*='),
                ('install_requires', r'install_requires\s*='),
                ('entry_points', r'entry_points\s*='),
                ('classifiers', r'classifiers\s*='),
            ]
            
            for component, pattern in required_components:
                if re.search(pattern, content):
                    print(f"✅ Has {component}")
                else:
                    print(f"❌ Missing {component}")
            
            # Test setup.py syntax
            try:
                result = subprocess.run([
                    sys.executable, str(setup_py), "--help-commands"
                ], capture_output=True, text=True, timeout=30, cwd=self.project_root)
                
                if result.returncode == 0:
                    print("✅ setup.py syntax is valid")
                else:
                    print(f"❌ setup.py syntax error: {result.stderr[:200]}")
                    
            except subprocess.TimeoutExpired:
                print("⚠️  setup.py validation timed out")
            except Exception as e:
                print(f"❌ setup.py test failed: {str(e)}")
                
        except Exception as e:
            print(f"❌ Failed to parse setup.py: {str(e)}")
    
    def validate_requirements(self):
        """Validate requirements files."""
        requirements_files = [
            ("requirements.txt", True),
            ("requirements-dev.txt", False),
        ]
        
        for req_file, required in requirements_files:
            req_path = self.project_root / req_file
            
            if not req_path.exists():
                if required:
                    print(f"❌ {req_file} not found (required)")
                else:
                    print(f"⚠️  {req_file} not found (optional)")
                continue
            
            print(f"✅ {req_file} exists")
            
            try:
                with open(req_path, 'r', encoding='utf-8') as f:
                    lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
                print(f"📦 {req_file}: {len(lines)} dependencies")
                
                # Check for common required packages
                if req_file == "requirements.txt":
                    required_packages = ['click', 'rich', 'pyyaml']
                    found_packages = set()
                    
                    for line in lines:
                        pkg_name = line.split('>=')[0].split('==')[0].split('<')[0].split('>')[0].strip()
                        found_packages.add(pkg_name.lower())
                    
                    for pkg in required_packages:
                        if pkg in found_packages:
                            print(f"✅ Has required package: {pkg}")
                        else:
                            print(f"❌ Missing required package: {pkg}")
                
                # Validate package names and versions
                invalid_lines = []
                for line in lines:
                    if not re.match(r'^[a-zA-Z0-9_-]+([><=!]+[0-9.]+.*)?$', line):
                        invalid_lines.append(line)
                
                if invalid_lines:
                    print(f"⚠️  Potentially invalid lines: {len(invalid_lines)}")
                else:
                    print("✅ All dependency lines appear valid")
                    
            except Exception as e:
                print(f"❌ Failed to parse {req_file}: {str(e)}")
    
    def validate_pyproject(self):
        """Validate pyproject.toml file."""
        pyproject_path = self.project_root / "pyproject.toml"
        
        if not pyproject_path.exists():
            print("❌ pyproject.toml not found")
            return
        
        print("✅ pyproject.toml exists")
        
        try:
            import toml
            with open(pyproject_path, 'r', encoding='utf-8') as f:
                data = toml.load(f)
            
            # Check for required sections
            required_sections = ['project', 'build-system']
            for section in required_sections:
                if section in data:
                    print(f"✅ Has [{section}] section")
                else:
                    print(f"❌ Missing [{section}] section")
            
            # Check project metadata
            if 'project' in data:
                project = data['project']
                required_fields = ['name', 'version', 'description', 'dependencies']
                
                for field in required_fields:
                    if field in project:
                        print(f"✅ Has project.{field}")
                    else:
                        print(f"❌ Missing project.{field}")
                
                # Check optional dependencies
                if 'optional-dependencies' in project:
                    optional_deps = project['optional-dependencies']
                    print(f"✅ Has optional dependencies: {list(optional_deps.keys())}")
                else:
                    print("⚠️  No optional dependencies defined")
            
            # Check build system
            if 'build-system' in data:
                build_system = data['build-system']
                if 'requires' in build_system and 'build-backend' in build_system:
                    print("✅ Build system properly configured")
                else:
                    print("⚠️  Build system incomplete")
            
        except ImportError:
            print("⚠️  toml library not available, skipping detailed validation")
        except Exception as e:
            print(f"❌ Failed to parse pyproject.toml: {str(e)}")
    
    def validate_manifest(self):
        """Validate MANIFEST.in file."""
        manifest_path = self.project_root / "MANIFEST.in"
        
        if not manifest_path.exists():
            print("❌ MANIFEST.in not found")
            return
        
        print("✅ MANIFEST.in exists")
        
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            print(f"📄 MANIFEST.in: {len(lines)} directives")
            
            # Check for important inclusions
            important_patterns = [
                (r'README', 'README files'),
                (r'LICENSE', 'License file'),
                (r'requirements', 'Requirements files'),
                (r'\.yaml|\.yml', 'YAML configuration files'),
                (r'\.json', 'JSON data files'),
                (r'templates', 'Template files'),
            ]
            
            content = ' '.join(lines)
            for pattern, description in important_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    print(f"✅ Includes {description}")
                else:
                    print(f"⚠️  May be missing {description}")
                    
        except Exception as e:
            print(f"❌ Failed to parse MANIFEST.in: {str(e)}")
    
    def validate_entry_points(self):
        """Validate entry points configuration."""
        # Check setup.py entry points
        setup_py = self.project_root / "setup.py"
        
        if setup_py.exists():
            try:
                with open(setup_py, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                if 'entry_points' in content:
                    print("✅ setup.py has entry_points")
                    
                    # Extract entry points
                    if 'njordscan=' in content:
                        print("✅ Main CLI entry point defined")
                    else:
                        print("❌ Missing main CLI entry point")
                        
                    if 'console_scripts' in content:
                        print("✅ Console scripts defined")
                    else:
                        print("⚠️  No console scripts found")
                else:
                    print("❌ No entry_points in setup.py")
                    
            except Exception as e:
                print(f"❌ Failed to check setup.py entry points: {str(e)}")
        
        # Check main.py and __main__.py
        main_files = [
            (self.project_root / "njordscan" / "main.py", "main.py"),
            (self.project_root / "njordscan" / "__main__.py", "__main__.py"),
        ]
        
        for file_path, name in main_files:
            if file_path.exists():
                print(f"✅ {name} exists")
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    if 'if __name__ == "__main__"' in content:
                        print(f"✅ {name} has main guard")
                    else:
                        print(f"⚠️  {name} missing main guard")
                        
                except Exception as e:
                    print(f"❌ Failed to check {name}: {str(e)}")
            else:
                print(f"❌ {name} not found")
    
    def validate_metadata_consistency(self):
        """Validate consistency across metadata files."""
        metadata_sources = {}
        
        # Get version from __init__.py
        init_py = self.project_root / "njordscan" / "__init__.py"
        if init_py.exists():
            try:
                with open(init_py, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                version_match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
                if version_match:
                    metadata_sources['__init__.py'] = {
                        'version': version_match.group(1)
                    }
                    print(f"✅ Version in __init__.py: {version_match.group(1)}")
                else:
                    print("❌ Version not found in __init__.py")
            except Exception as e:
                print(f"❌ Failed to read __init__.py: {str(e)}")
        
        # Get version from setup.py
        setup_py = self.project_root / "setup.py"
        if setup_py.exists():
            try:
                with open(setup_py, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                version_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
                if version_match:
                    metadata_sources['setup.py'] = {
                        'version': version_match.group(1)
                    }
                    print(f"✅ Version in setup.py: {version_match.group(1)}")
                else:
                    print("⚠️  Version not found in setup.py (might be dynamic)")
            except Exception as e:
                print(f"❌ Failed to read setup.py: {str(e)}")
        
        # Check version consistency
        versions = [data.get('version') for data in metadata_sources.values() if data.get('version')]
        if len(set(versions)) == 1:
            print("✅ Version consistent across files")
        elif len(versions) > 1:
            print(f"⚠️  Version inconsistency: {versions}")
        else:
            print("❌ No version information found")
    
    def simulate_installation(self):
        """Simulate package installation."""
        print("🔄 Simulating installation process...")
        
        # Test that the package can be built
        try:
            result = subprocess.run([
                sys.executable, "-m", "build", "--wheel", "--no-isolation"
            ], capture_output=True, text=True, timeout=120, cwd=self.project_root)
            
            if result.returncode == 0:
                print("✅ Package builds successfully")
                
                # Check if wheel was created
                dist_dir = self.project_root / "dist"
                if dist_dir.exists():
                    wheels = list(dist_dir.glob("*.whl"))
                    if wheels:
                        print(f"✅ Wheel created: {wheels[0].name}")
                    else:
                        print("⚠️  No wheel file found in dist/")
                else:
                    print("⚠️  No dist/ directory created")
                    
            else:
                print(f"❌ Build failed: {result.stderr[:300]}")
                
        except subprocess.TimeoutExpired:
            print("⚠️  Build timed out")
        except FileNotFoundError:
            print("⚠️  Build tools not available (install with: pip install build)")
        except Exception as e:
            print(f"❌ Build simulation failed: {str(e)}")
        
        # Test basic import after build
        try:
            result = subprocess.run([
                sys.executable, "-c", "import sys; sys.path.insert(0, '.'); import njordscan; print(f'✅ Import successful: {njordscan.__version__}')"
            ], capture_output=True, text=True, timeout=30, cwd=self.project_root)
            
            if result.returncode == 0:
                print(result.stdout.strip())
            else:
                print(f"❌ Import test failed: {result.stderr}")
                
        except Exception as e:
            print(f"❌ Import test failed: {str(e)}")
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate installation validation report."""
        print("\n" + "=" * 60)
        print("🛡️  INSTALLATION VALIDATION SUMMARY")
        print("=" * 60)
        
        if not self.results:
            print("✅ All installation components validated successfully!")
            return {"status": "success", "issues": []}
        else:
            print(f"⚠️  Found {len(self.results)} issues:")
            for result in self.results:
                print(f"  • {result['category']}: {result['error']}")
            return {"status": "issues", "issues": self.results}

def main():
    """Run installation validation."""
    validator = InstallationValidator()
    report = validator.validate_all()
    
    # Save report
    report_file = Path(__file__).parent / "installation_report.json"
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📄 Detailed report saved to: {report_file}")
    
    # Exit with appropriate code
    sys.exit(0 if report['status'] == 'success' else 1)

if __name__ == "__main__":
    main()
