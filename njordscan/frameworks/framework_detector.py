"""
Framework Detection System

Intelligently detects and analyzes web frameworks in projects.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class FrameworkDetectionResult:
    """Result of framework detection."""
    primary_framework: str
    confidence: float
    secondary_frameworks: List[Tuple[str, float]]
    framework_versions: Dict[str, str]
    build_tools: List[str]
    features_detected: Set[str]
    reasoning: List[str]

class FrameworkDetector:
    """Intelligent framework detection system."""
    
    def __init__(self):
        # Framework detection patterns
        self.framework_patterns = {
            'nextjs': {
                'package_dependencies': ['next'],
                'config_files': ['next.config.js', 'next.config.ts', 'next.config.mjs'],
                'directory_structure': ['pages/', 'app/', 'public/'],
                'file_patterns': ['pages/api/', 'pages/_app', 'pages/_document'],
                'code_patterns': [
                    r'from\s+[\'"]next/',
                    r'import.*from\s+[\'"]next/',
                    r'getServerSideProps',
                    r'getStaticProps',
                    r'getStaticPaths'
                ],
                'confidence_weights': {
                    'package_dependencies': 0.4,
                    'config_files': 0.3,
                    'directory_structure': 0.2,
                    'code_patterns': 0.1
                }
            },
            
            'react': {
                'package_dependencies': ['react', 'react-dom'],
                'config_files': ['webpack.config.js', 'craco.config.js'],
                'directory_structure': ['src/components/', 'src/pages/', 'public/'],
                'file_patterns': ['src/App.js', 'src/App.tsx', 'src/index.js'],
                'code_patterns': [
                    r'import\s+React',
                    r'from\s+[\'"]react[\'"]',
                    r'useState',
                    r'useEffect',
                    r'ReactDOM\.render',
                    r'createRoot'
                ],
                'confidence_weights': {
                    'package_dependencies': 0.4,
                    'directory_structure': 0.3,
                    'code_patterns': 0.2,
                    'config_files': 0.1
                }
            },
            
            'vite': {
                'package_dependencies': ['vite'],
                'config_files': ['vite.config.js', 'vite.config.ts', 'vite.config.mjs'],
                'directory_structure': ['src/', 'public/'],
                'file_patterns': ['index.html'],
                'code_patterns': [
                    r'import\.meta\.env',
                    r'import\.meta\.hot',
                    r'from\s+[\'"]vite'
                ],
                'confidence_weights': {
                    'package_dependencies': 0.5,
                    'config_files': 0.3,
                    'code_patterns': 0.1,
                    'directory_structure': 0.1
                }
            },
            
            'vue': {
                'package_dependencies': ['vue'],
                'config_files': ['vue.config.js', 'nuxt.config.js'],
                'directory_structure': ['src/components/', 'src/views/'],
                'file_patterns': ['src/App.vue', 'src/main.js'],
                'code_patterns': [
                    r'import\s+Vue',
                    r'from\s+[\'"]vue[\'"]',
                    r'createApp',
                    r'Vue\.createApp',
                    r'<template>',
                    r'<script.*setup>'
                ],
                'confidence_weights': {
                    'package_dependencies': 0.4,
                    'code_patterns': 0.3,
                    'directory_structure': 0.2,
                    'config_files': 0.1
                }
            },
            
            'svelte': {
                'package_dependencies': ['svelte'],
                'config_files': ['svelte.config.js', 'rollup.config.js'],
                'directory_structure': ['src/'],
                'file_patterns': ['src/App.svelte', 'src/main.js'],
                'code_patterns': [
                    r'from\s+[\'"]svelte',
                    r'<script>.*</script>',
                    r'\$:',  # Svelte reactive statements
                    r'export\s+let'
                ],
                'confidence_weights': {
                    'package_dependencies': 0.5,
                    'code_patterns': 0.3,
                    'config_files': 0.1,
                    'directory_structure': 0.1
                }
            },
            
            'angular': {
                'package_dependencies': ['@angular/core', '@angular/cli'],
                'config_files': ['angular.json', 'ng-package.json'],
                'directory_structure': ['src/app/', 'src/assets/'],
                'file_patterns': ['src/main.ts', 'src/app/app.module.ts'],
                'code_patterns': [
                    r'from\s+[\'"]@angular/',
                    r'@Component',
                    r'@Injectable',
                    r'@NgModule',
                    r'platformBrowserDynamic'
                ],
                'confidence_weights': {
                    'package_dependencies': 0.4,
                    'config_files': 0.3,
                    'code_patterns': 0.2,
                    'directory_structure': 0.1
                }
            },
            
            'nuxt': {
                'package_dependencies': ['nuxt'],
                'config_files': ['nuxt.config.js', 'nuxt.config.ts'],
                'directory_structure': ['pages/', 'components/', 'layouts/'],
                'file_patterns': ['nuxt.config.js', 'pages/index.vue'],
                'code_patterns': [
                    r'from\s+[\'"]nuxt',
                    r'asyncData',
                    r'fetch\s*\(',
                    r'\$nuxt',
                    r'useNuxt'
                ],
                'confidence_weights': {
                    'package_dependencies': 0.4,
                    'config_files': 0.3,
                    'directory_structure': 0.2,
                    'code_patterns': 0.1
                }
            }
        }
        
        # Build tool detection patterns
        self.build_tool_patterns = {
            'webpack': {
                'config_files': ['webpack.config.js', 'webpack.config.ts'],
                'package_dependencies': ['webpack', 'webpack-cli'],
                'indicators': ['webpack.config', 'webpack-dev-server']
            },
            'vite': {
                'config_files': ['vite.config.js', 'vite.config.ts'],
                'package_dependencies': ['vite'],
                'indicators': ['vite.config', 'import.meta.env']
            },
            'rollup': {
                'config_files': ['rollup.config.js', 'rollup.config.ts'],
                'package_dependencies': ['rollup'],
                'indicators': ['rollup.config']
            },
            'parcel': {
                'config_files': ['.parcelrc'],
                'package_dependencies': ['parcel'],
                'indicators': ['parcel-bundler']
            },
            'esbuild': {
                'config_files': ['esbuild.config.js'],
                'package_dependencies': ['esbuild'],
                'indicators': ['esbuild']
            }
        }
    
    def detect_frameworks(self, project_path: Path) -> FrameworkDetectionResult:
        """Detect frameworks in the given project."""
        
        logger.info(f"Detecting frameworks in {project_path}")
        
        # Load package.json for dependency analysis
        package_json = self._load_package_json(project_path)
        
        # Calculate confidence scores for each framework
        framework_scores = {}
        reasoning = []
        
        for framework_name, patterns in self.framework_patterns.items():
            score, framework_reasoning = self._calculate_framework_score(
                framework_name, patterns, project_path, package_json
            )
            
            if score > 0:
                framework_scores[framework_name] = score
                reasoning.extend(framework_reasoning)
        
        # Determine primary and secondary frameworks
        if not framework_scores:
            return FrameworkDetectionResult(
                primary_framework='unknown',
                confidence=0.0,
                secondary_frameworks=[],
                framework_versions={},
                build_tools=[],
                features_detected=set(),
                reasoning=['No frameworks detected']
            )
        
        # Sort by confidence score
        sorted_frameworks = sorted(framework_scores.items(), key=lambda x: x[1], reverse=True)
        
        primary_framework = sorted_frameworks[0][0]
        primary_confidence = sorted_frameworks[0][1]
        
        # Secondary frameworks (score > 0.3 and not primary)
        secondary_frameworks = [
            (name, score) for name, score in sorted_frameworks[1:]
            if score > 0.3
        ]
        
        # Get framework versions
        framework_versions = self._extract_framework_versions(package_json, framework_scores.keys())
        
        # Detect build tools
        build_tools = self._detect_build_tools(project_path, package_json)
        
        # Detect framework-specific features
        features_detected = self._detect_framework_features(
            project_path, primary_framework, package_json
        )
        
        result = FrameworkDetectionResult(
            primary_framework=primary_framework,
            confidence=primary_confidence,
            secondary_frameworks=secondary_frameworks,
            framework_versions=framework_versions,
            build_tools=build_tools,
            features_detected=features_detected,
            reasoning=reasoning
        )
        
        logger.info(f"Detected primary framework: {primary_framework} (confidence: {primary_confidence:.2f})")
        
        return result
    
    def _load_package_json(self, project_path: Path) -> Optional[Dict[str, Any]]:
        """Load and parse package.json."""
        
        package_json_path = project_path / 'package.json'
        
        if not package_json_path.exists():
            return None
        
        try:
            with open(package_json_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Could not load package.json: {e}")
            return None
    
    def _calculate_framework_score(self, framework_name: str, patterns: Dict[str, Any], 
                                  project_path: Path, package_json: Optional[Dict[str, Any]]) -> Tuple[float, List[str]]:
        """Calculate confidence score for a framework."""
        
        total_score = 0.0
        reasoning = []
        weights = patterns['confidence_weights']
        
        # Check package dependencies
        if package_json and 'package_dependencies' in patterns:
            dep_score = self._check_package_dependencies(
                patterns['package_dependencies'], package_json
            )
            
            if dep_score > 0:
                weighted_score = dep_score * weights.get('package_dependencies', 0.4)
                total_score += weighted_score
                reasoning.append(f"{framework_name}: Found package dependencies (score: {weighted_score:.2f})")
        
        # Check configuration files
        if 'config_files' in patterns:
            config_score = self._check_config_files(
                patterns['config_files'], project_path
            )
            
            if config_score > 0:
                weighted_score = config_score * weights.get('config_files', 0.3)
                total_score += weighted_score
                reasoning.append(f"{framework_name}: Found config files (score: {weighted_score:.2f})")
        
        # Check directory structure
        if 'directory_structure' in patterns:
            dir_score = self._check_directory_structure(
                patterns['directory_structure'], project_path
            )
            
            if dir_score > 0:
                weighted_score = dir_score * weights.get('directory_structure', 0.2)
                total_score += weighted_score
                reasoning.append(f"{framework_name}: Found directory structure (score: {weighted_score:.2f})")
        
        # Check file patterns
        if 'file_patterns' in patterns:
            file_score = self._check_file_patterns(
                patterns['file_patterns'], project_path
            )
            
            if file_score > 0:
                weighted_score = file_score * weights.get('file_patterns', 0.1)
                total_score += weighted_score
                reasoning.append(f"{framework_name}: Found file patterns (score: {weighted_score:.2f})")
        
        # Check code patterns
        if 'code_patterns' in patterns:
            code_score = self._check_code_patterns(
                patterns['code_patterns'], project_path
            )
            
            if code_score > 0:
                weighted_score = code_score * weights.get('code_patterns', 0.1)
                total_score += weighted_score
                reasoning.append(f"{framework_name}: Found code patterns (score: {weighted_score:.2f})")
        
        return min(1.0, total_score), reasoning
    
    def _check_package_dependencies(self, required_deps: List[str], package_json: Dict[str, Any]) -> float:
        """Check for required package dependencies."""
        
        all_deps = {
            **package_json.get('dependencies', {}),
            **package_json.get('devDependencies', {}),
            **package_json.get('peerDependencies', {})
        }
        
        found_deps = []
        for dep in required_deps:
            if dep in all_deps:
                found_deps.append(dep)
        
        if not found_deps:
            return 0.0
        
        # Return score based on percentage of required dependencies found
        return len(found_deps) / len(required_deps)
    
    def _check_config_files(self, config_files: List[str], project_path: Path) -> float:
        """Check for configuration files."""
        
        found_files = []
        
        for config_file in config_files:
            if (project_path / config_file).exists():
                found_files.append(config_file)
        
        if not found_files:
            return 0.0
        
        # Return score based on number of config files found
        return min(1.0, len(found_files) / len(config_files))
    
    def _check_directory_structure(self, required_dirs: List[str], project_path: Path) -> float:
        """Check for required directory structure."""
        
        found_dirs = []
        
        for required_dir in required_dirs:
            dir_path = project_path / required_dir
            if dir_path.exists() and dir_path.is_dir():
                found_dirs.append(required_dir)
        
        if not found_dirs:
            return 0.0
        
        # Return score based on percentage of directories found
        return len(found_dirs) / len(required_dirs)
    
    def _check_file_patterns(self, file_patterns: List[str], project_path: Path) -> float:
        """Check for specific file patterns."""
        
        found_patterns = []
        
        for pattern in file_patterns:
            # Use glob to find files matching the pattern
            matching_files = list(project_path.glob(pattern))
            if matching_files:
                found_patterns.append(pattern)
        
        if not found_patterns:
            return 0.0
        
        return len(found_patterns) / len(file_patterns)
    
    def _check_code_patterns(self, code_patterns: List[str], project_path: Path) -> float:
        """Check for code patterns in source files."""
        
        import re
        
        # Look for JavaScript/TypeScript files
        source_files = []
        for ext in ['*.js', '*.jsx', '*.ts', '*.tsx', '*.vue', '*.svelte']:
            source_files.extend(project_path.rglob(ext))
        
        if not source_files:
            return 0.0
        
        # Limit to first 20 files for performance
        source_files = source_files[:20]
        
        pattern_matches = {}
        
        for pattern in code_patterns:
            pattern_matches[pattern] = 0
            
            compiled_pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            
            for source_file in source_files:
                try:
                    content = source_file.read_text(encoding='utf-8')
                    if compiled_pattern.search(content):
                        pattern_matches[pattern] += 1
                        break  # Found in at least one file
                except Exception:
                    continue
        
        # Calculate score based on patterns found
        found_patterns = sum(1 for count in pattern_matches.values() if count > 0)
        
        if found_patterns == 0:
            return 0.0
        
        return found_patterns / len(code_patterns)
    
    def _extract_framework_versions(self, package_json: Optional[Dict[str, Any]], 
                                   detected_frameworks: List[str]) -> Dict[str, str]:
        """Extract version information for detected frameworks."""
        
        versions = {}
        
        if not package_json:
            return versions
        
        all_deps = {
            **package_json.get('dependencies', {}),
            **package_json.get('devDependencies', {})
        }
        
        # Framework to package name mapping
        framework_packages = {
            'nextjs': 'next',
            'react': 'react',
            'vite': 'vite',
            'vue': 'vue',
            'svelte': 'svelte',
            'angular': '@angular/core',
            'nuxt': 'nuxt'
        }
        
        for framework in detected_frameworks:
            package_name = framework_packages.get(framework)
            if package_name and package_name in all_deps:
                versions[framework] = all_deps[package_name]
        
        return versions
    
    def _detect_build_tools(self, project_path: Path, package_json: Optional[Dict[str, Any]]) -> List[str]:
        """Detect build tools used in the project."""
        
        detected_tools = []
        
        for tool_name, patterns in self.build_tool_patterns.items():
            tool_detected = False
            
            # Check config files
            for config_file in patterns.get('config_files', []):
                if (project_path / config_file).exists():
                    tool_detected = True
                    break
            
            # Check package dependencies
            if not tool_detected and package_json:
                all_deps = {
                    **package_json.get('dependencies', {}),
                    **package_json.get('devDependencies', {})
                }
                
                for dep in patterns.get('package_dependencies', []):
                    if dep in all_deps:
                        tool_detected = True
                        break
            
            if tool_detected:
                detected_tools.append(tool_name)
        
        return detected_tools
    
    def _detect_framework_features(self, project_path: Path, primary_framework: str, 
                                  package_json: Optional[Dict[str, Any]]) -> Set[str]:
        """Detect framework-specific features."""
        
        features = set()
        
        if not package_json:
            return features
        
        all_deps = {
            **package_json.get('dependencies', {}),
            **package_json.get('devDependencies', {})
        }
        
        # Framework-specific feature detection
        if primary_framework == 'nextjs':
            features.update(self._detect_nextjs_features(project_path, all_deps))
        elif primary_framework == 'react':
            features.update(self._detect_react_features(project_path, all_deps))
        elif primary_framework == 'vite':
            features.update(self._detect_vite_features(project_path, all_deps))
        elif primary_framework == 'vue':
            features.update(self._detect_vue_features(project_path, all_deps))
        elif primary_framework == 'svelte':
            features.update(self._detect_svelte_features(project_path, all_deps))
        
        return features
    
    def _detect_nextjs_features(self, project_path: Path, dependencies: Dict[str, str]) -> Set[str]:
        """Detect Next.js specific features."""
        features = set()
        
        # Check for App Router
        if (project_path / 'app').exists():
            features.add('app_router')
        
        # Check for Pages Router
        if (project_path / 'pages').exists():
            features.add('pages_router')
        
        # Check for API routes
        if (project_path / 'pages' / 'api').exists() or (project_path / 'app' / 'api').exists():
            features.add('api_routes')
        
        # Check for middleware
        if (project_path / 'middleware.js').exists() or (project_path / 'middleware.ts').exists():
            features.add('middleware')
        
        # Check for Next.js plugins
        nextjs_plugins = {
            'next-pwa': 'pwa',
            'next-auth': 'authentication',
            'next-i18next': 'internationalization',
            '@next/bundle-analyzer': 'bundle_analysis'
        }
        
        for plugin, feature in nextjs_plugins.items():
            if plugin in dependencies:
                features.add(feature)
        
        return features
    
    def _detect_react_features(self, project_path: Path, dependencies: Dict[str, str]) -> Set[str]:
        """Detect React specific features."""
        features = set()
        
        # Check for React Router
        if 'react-router-dom' in dependencies:
            features.add('routing')
        
        # Check for state management
        state_management = {
            'redux': 'redux',
            'react-redux': 'redux',
            'zustand': 'zustand',
            'recoil': 'recoil',
            'mobx': 'mobx'
        }
        
        for lib, feature in state_management.items():
            if lib in dependencies:
                features.add(f'state_management_{feature}')
        
        # Check for UI libraries
        ui_libraries = {
            '@mui/material': 'material_ui',
            'antd': 'ant_design',
            'react-bootstrap': 'bootstrap',
            'chakra-ui': 'chakra_ui'
        }
        
        for lib, feature in ui_libraries.items():
            if lib in dependencies:
                features.add(f'ui_library_{feature}')
        
        return features
    
    def _detect_vite_features(self, project_path: Path, dependencies: Dict[str, str]) -> Set[str]:
        """Detect Vite specific features."""
        features = set()
        
        # Check for Vite plugins
        vite_plugins = {
            '@vitejs/plugin-react': 'react_plugin',
            '@vitejs/plugin-vue': 'vue_plugin',
            'vite-plugin-pwa': 'pwa',
            'vite-plugin-windicss': 'windicss'
        }
        
        for plugin, feature in vite_plugins.items():
            if plugin in dependencies:
                features.add(feature)
        
        # Check for testing
        if 'vitest' in dependencies:
            features.add('vitest_testing')
        
        return features
    
    def _detect_vue_features(self, project_path: Path, dependencies: Dict[str, str]) -> Set[str]:
        """Detect Vue specific features."""
        features = set()
        
        # Check for Vue Router
        if 'vue-router' in dependencies:
            features.add('routing')
        
        # Check for Vuex
        if 'vuex' in dependencies:
            features.add('state_management_vuex')
        
        # Check for Pinia
        if 'pinia' in dependencies:
            features.add('state_management_pinia')
        
        return features
    
    def _detect_svelte_features(self, project_path: Path, dependencies: Dict[str, str]) -> Set[str]:
        """Detect Svelte specific features."""
        features = set()
        
        # Check for SvelteKit
        if '@sveltejs/kit' in dependencies:
            features.add('sveltekit')
        
        # Check for Svelte stores
        if (project_path / 'src' / 'stores').exists():
            features.add('stores')
        
        return features
    
    def get_framework_analyzer(self, framework_name: str):
        """Get the appropriate framework analyzer."""
        from .nextjs_analyzer import NextJSAnalyzer
        from .react_analyzer import ReactAnalyzer
        from .vite_analyzer import ViteAnalyzer
        
        analyzers = {
            'nextjs': NextJSAnalyzer,
            'react': ReactAnalyzer,
            'vite': ViteAnalyzer
        }
        
        analyzer_class = analyzers.get(framework_name.lower())
        if analyzer_class:
            return analyzer_class()
        
        return None
    
    def analyze_project_with_detected_framework(self, project_path: Path) -> Tuple[FrameworkDetectionResult, List[Any]]:
        """Detect framework and perform security analysis."""
        
        # Detect frameworks
        detection_result = self.detect_frameworks(project_path)
        
        # Get appropriate analyzer
        analyzer = self.get_framework_analyzer(detection_result.primary_framework)
        
        vulnerabilities = []
        if analyzer:
            try:
                vulnerabilities = analyzer.analyze_project(project_path)
                logger.info(f"Found {len(vulnerabilities)} vulnerabilities using {detection_result.primary_framework} analyzer")
            except Exception as e:
                logger.error(f"Framework analysis failed: {e}")
        else:
            logger.warning(f"No analyzer available for framework: {detection_result.primary_framework}")
        
        return detection_result, vulnerabilities
