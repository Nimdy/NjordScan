"""
🛡️ Security Scanning Modules for NjordScan v1.0.0

Comprehensive collection of security analysis modules including traditional
scanning modules and enhanced AI-powered analysis capabilities.
"""

# Core scanning modules (with graceful fallback for missing dependencies)
try:
    from .headers import HeadersModule
    HEADERS_AVAILABLE = True
except ImportError:
    HEADERS_AVAILABLE = False
    HeadersModule = None

try:
    from .configs import ConfigsModule
    CONFIGS_AVAILABLE = True
except ImportError:
    CONFIGS_AVAILABLE = False
    ConfigsModule = None

try:
    from .code_static import CodeStaticModule
    STATIC_AVAILABLE = True
except ImportError:
    STATIC_AVAILABLE = False
    CodeStaticModule = None

try:
    from .dependencies import DependenciesModule
    DEPENDENCIES_AVAILABLE = True
except ImportError:
    DEPENDENCIES_AVAILABLE = False
    DependenciesModule = None

try:
    from .runtime import RuntimeModule
    RUNTIME_AVAILABLE = True
except ImportError:
    RUNTIME_AVAILABLE = False
    RuntimeModule = None

try:
    from .ai_endpoints import AIEndpointsModule
    AI_ENDPOINTS_AVAILABLE = True
except ImportError:
    AI_ENDPOINTS_AVAILABLE = False
    AIEndpointsModule = None

# Enhanced modules (with fallback if not available)
try:
    from .code_static_enhanced import CodeStaticEnhancedModule
    ENHANCED_STATIC_AVAILABLE = True
except ImportError:
    ENHANCED_STATIC_AVAILABLE = False
    CodeStaticEnhancedModule = None

# All available modules
__all__ = [
    # Core modules
    'HeadersModule',
    'ConfigsModule', 
    'CodeStaticModule',
    'DependenciesModule',
    'RuntimeModule',
    'AIEndpointsModule'
]

# Add enhanced modules if available
if ENHANCED_STATIC_AVAILABLE:
    __all__.append('CodeStaticEnhancedModule')

# Module registry for dynamic loading (only include available modules)
MODULE_REGISTRY = {}

if HEADERS_AVAILABLE:
    MODULE_REGISTRY['headers'] = HeadersModule
if CONFIGS_AVAILABLE:
    MODULE_REGISTRY['configs'] = ConfigsModule
if STATIC_AVAILABLE:
    MODULE_REGISTRY['static'] = CodeStaticModule
if DEPENDENCIES_AVAILABLE:
    MODULE_REGISTRY['dependencies'] = DependenciesModule
if RUNTIME_AVAILABLE:
    MODULE_REGISTRY['runtime'] = RuntimeModule
if AI_ENDPOINTS_AVAILABLE:
    MODULE_REGISTRY['ai_endpoints'] = AIEndpointsModule
if ENHANCED_STATIC_AVAILABLE:
    MODULE_REGISTRY['static_enhanced'] = CodeStaticEnhancedModule

def get_available_modules():
    """Get list of available module names."""
    return list(MODULE_REGISTRY.keys())

def get_module_class(module_name: str):
    """Get module class by name."""
    return MODULE_REGISTRY.get(module_name)

def is_module_available(module_name: str) -> bool:
    """Check if a module is available."""
    return module_name in MODULE_REGISTRY

# Module categories for organization
MODULE_CATEGORIES = {
    'security': ['headers', 'configs', 'static', 'static_enhanced'],
    'dependencies': ['dependencies'],
    'runtime': ['runtime'],
    'ai': ['ai_endpoints'],
}

def get_modules_by_category(category: str):
    """Get modules by category."""
    return [name for name in MODULE_CATEGORIES.get(category, []) 
            if is_module_available(name)]

# Module metadata
MODULE_METADATA = {
    'headers': {
        'name': 'Security Headers Analysis',
        'description': 'Analyzes HTTP security headers and OWASP recommendations',
        'category': 'security',
        'frameworks': ['all'],
        'ai_enhanced': False
    },
    'configs': {
        'name': 'Configuration Security',
        'description': 'Scans configuration files for security issues and secrets',
        'category': 'security', 
        'frameworks': ['all'],
        'ai_enhanced': False
    },
    'static': {
        'name': 'Static Code Analysis',
        'description': 'Analyzes source code for security vulnerabilities',
        'category': 'security',
        'frameworks': ['nextjs', 'react', 'vite'],
        'ai_enhanced': False
    },
    'dependencies': {
        'name': 'Dependency Security',
        'description': 'Analyzes dependencies for known vulnerabilities',
        'category': 'dependencies',
        'frameworks': ['all'],
        'ai_enhanced': False
    },
    'runtime': {
        'name': 'Runtime Testing',
        'description': 'Dynamic application security testing (DAST)',
        'category': 'runtime',
        'frameworks': ['nextjs', 'react', 'vite'],
        'ai_enhanced': False
    },
    'ai_endpoints': {
        'name': 'AI Endpoint Security',
        'description': 'Specialized security analysis for AI-powered applications',
        'category': 'ai',
        'frameworks': ['all'],
        'ai_enhanced': True
    }
}

if ENHANCED_STATIC_AVAILABLE:
    MODULE_METADATA['static_enhanced'] = {
        'name': 'Enhanced Static Analysis',
        'description': 'AI-powered static code analysis with AST parsing',
        'category': 'security',
        'frameworks': ['nextjs', 'react', 'vite'],
        'ai_enhanced': True
    }

def get_module_metadata(module_name: str):
    """Get metadata for a module."""
    return MODULE_METADATA.get(module_name, {})

def get_framework_modules(framework: str):
    """Get modules that support a specific framework."""
    return [name for name, meta in MODULE_METADATA.items() 
            if framework in meta.get('frameworks', []) or 'all' in meta.get('frameworks', [])]

def get_ai_enhanced_modules():
    """Get modules that have AI enhancement."""
    return [name for name, meta in MODULE_METADATA.items() 
            if meta.get('ai_enhanced', False)]