"""
Base module for all scanning modules.
"""

import asyncio
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from pathlib import Path

from ..vulnerability import Vulnerability, VulnerabilityIdGenerator, Severity, Confidence
from ..vulnerability_types import VulnerabilityType, normalize_vulnerability_type, get_vulnerability_type_info

class BaseModule(ABC):
    """Abstract base class for all scanning modules."""
    
    def __init__(self, config, vuln_id_generator: VulnerabilityIdGenerator):
        self.config = config
        self.vuln_id_generator = vuln_id_generator
        self.name = self.__class__.__name__.replace('Module', '').lower()
    
    @abstractmethod
    async def scan(self, target: str) -> List[Vulnerability]:
        """
        Main scan method that must be implemented by all modules.
        
        Args:
            target: Target URL or directory path
            
        Returns:
            List of Vulnerability objects
        """
        pass
    
    def should_run(self, mode: str) -> bool:
        """
        Determine if this module should run based on scan mode.
        
        Args:
            mode: Scan mode (static, dynamic, full)
            
        Returns:
            Boolean indicating if module should run
        """
        mode_mappings = {
            'static': ['configs', 'code_static', 'dependencies'],
            'dynamic': ['headers', 'runtime', 'ai_endpoints'],
            'full': ['headers', 'configs', 'code_static', 'dependencies', 'runtime', 'ai_endpoints']
        }
        
        return self.name in mode_mappings.get(mode, [])
    
    def create_vulnerability(self, 
                           title: str,
                           description: str,
                           severity: str,
                           confidence: str = "medium",
                           vuln_type: str = "",
                           file_path: Optional[str] = None,
                           line_number: Optional[int] = None,
                           code_snippet: Optional[str] = None,
                           fix: Optional[str] = None,
                           reference: Optional[str] = None,
                           metadata: Optional[Dict[str, Any]] = None) -> Vulnerability:
        """
        Create a standardized vulnerability object with automatic type enhancement.
        
        Args:
            vuln_type: Must be a valid VulnerabilityType enum value (e.g., 'xss_reflected', 'sql_injection')
        """
        # Normalize vulnerability type
        normalized_type = normalize_vulnerability_type(vuln_type)
        if not normalized_type and vuln_type:
            # Log warning for invalid vulnerability types
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Invalid vulnerability type '{vuln_type}' in module {self.name}. "
                          f"Use standardized types from VulnerabilityType enum.")
            # Fall back to the original type string
            normalized_type = None
        
        if normalized_type:
            vuln_type = normalized_type.value
            # Get additional information from registry
            type_info = get_vulnerability_type_info(normalized_type)
            if type_info:
                # Use registry information if available
                if not fix:
                    fix = type_info.remediation
                if not reference and type_info.references:
                    reference = type_info.references[0]
                if not description:
                    description = type_info.description
                
                # Add CWE codes to metadata
                if metadata is None:
                    metadata = {}
                metadata['cwe_codes'] = [cwe.value for cwe in type_info.cwe_codes]
                metadata['owasp_category'] = type_info.category.value
                metadata['normalized_type'] = vuln_type
        
        vuln_id = self.vuln_id_generator.generate_id(self.name, vuln_type)
        
        return Vulnerability(
            id=vuln_id,
            title=title,
            severity=Severity(severity.lower()),
            confidence=Confidence(confidence.lower()),
            description=description,
            fix=fix or self._get_default_fix(title),
            reference=reference or self._get_default_reference(title),
            vuln_type=vuln_type,
            location=file_path or "Unknown",
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            framework=self.config.framework,
            module=self.name,
            metadata=metadata or {}
        )
    
    def _get_default_fix(self, title: str) -> str:
        """Get default fix recommendation when registry doesn't have specific guidance."""
        return 'Review and fix the identified security issue. Consult OWASP guidelines for best practices.'
    
    def _get_default_reference(self, title: str) -> str:
        """Get default reference when registry doesn't have specific guidance."""
        return 'https://owasp.org/www-community/'
    
    def is_framework_supported(self, framework: str) -> bool:
        """Check if this module supports the given framework."""
        return True  # Default: support all frameworks
    
    def get_file_content(self, file_path: str) -> Optional[str]:
        """Safely read file content."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except (IOError, UnicodeDecodeError):
            return None
    
    def find_files_by_pattern(self, directory: str, patterns: List[str]) -> List[Path]:
        """Find files matching given patterns."""
        found_files = []
        base_path = Path(directory)
        
        for pattern in patterns:
            found_files.extend(base_path.rglob(pattern))
        
        return found_files