"""
Software Bill of Materials (SBOM) Generator

Generates comprehensive SBOMs in multiple formats (SPDX, CycloneDX, SWID)
with detailed component information, relationships, and security metadata.
"""

import json
import time
import hashlib
import uuid
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from collections import defaultdict
import logging

from .dependency_analyzer import DependencyGraph, DependencyInfo

logger = logging.getLogger(__name__)

class SBOMFormat(Enum):
    """Supported SBOM formats."""
    SPDX_JSON = "spdx_json"
    CYCLONE_DX_JSON = "cyclone_dx_json"
    CYCLONE_DX_XML = "cyclone_dx_xml"
    SWID_JSON = "swid_json"

class ComponentType(Enum):
    """Component types in SBOM."""
    APPLICATION = "application"
    FRAMEWORK = "framework"
    LIBRARY = "library"
    CONTAINER = "container"
    OPERATING_SYSTEM = "operating-system"
    DEVICE = "device"
    FIRMWARE = "firmware"
    FILE = "file"

@dataclass
class SBOMComponent:
    """SBOM component representation."""
    bom_ref: str
    type: ComponentType
    name: str
    version: str
    
    # Identifiers
    purl: str = ""  # Package URL
    cpe: str = ""   # Common Platform Enumeration
    swid: str = ""  # Software Identification Tag
    
    # Metadata
    description: str = ""
    scope: str = "required"  # required, optional, excluded
    hashes: List[Dict[str, str]] = None
    licenses: List[Dict[str, str]] = None
    copyright: str = ""
    
    # Supply chain info
    supplier: Dict[str, str] = None
    author: str = ""
    publisher: str = ""
    
    # Security
    vulnerabilities: List[Dict[str, Any]] = None
    risk_rating: str = "unspecified"
    
    # Relationships
    dependencies: List[str] = None
    
    def __post_init__(self):
        if self.hashes is None:
            self.hashes = []
        if self.licenses is None:
            self.licenses = []
        if self.supplier is None:
            self.supplier = {}
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.dependencies is None:
            self.dependencies = []

@dataclass
class SBOMMetadata:
    """SBOM metadata information."""
    timestamp: str
    tools: List[Dict[str, str]]
    authors: List[Dict[str, str]]
    component: Dict[str, Any]
    
    # Generation info
    serial_number: str = ""
    version: int = 1
    
    # Lifecycle info
    lifecycle: str = "build"  # design, pre-build, build, post-build, operations, discovery, decommission
    
    def __post_init__(self):
        if not self.serial_number:
            self.serial_number = f"urn:uuid:{uuid.uuid4()}"

@dataclass
class SBOM:
    """Complete SBOM structure."""
    bom_format: str
    spec_version: str
    serial_number: str
    version: int
    metadata: SBOMMetadata
    components: List[SBOMComponent]
    services: List[Dict[str, Any]] = None
    external_references: List[Dict[str, Any]] = None
    dependencies: List[Dict[str, Any]] = None
    compositions: List[Dict[str, Any]] = None
    vulnerabilities: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.services is None:
            self.services = []
        if self.external_references is None:
            self.external_references = []
        if self.dependencies is None:
            self.dependencies = []
        if self.compositions is None:
            self.compositions = []
        if self.vulnerabilities is None:
            self.vulnerabilities = []

class SBOMGenerator:
    """Advanced SBOM generator supporting multiple formats and standards."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Generation configuration
        self.generation_config = {
            'include_transitive_deps': self.config.get('include_transitive_deps', True),
            'include_dev_deps': self.config.get('include_dev_deps', True),
            'include_vulnerabilities': self.config.get('include_vulnerabilities', True),
            'include_licenses': self.config.get('include_licenses', True),
            'include_hashes': self.config.get('include_hashes', True),
            'include_supplier_info': self.config.get('include_supplier_info', True),
            'generate_purls': self.config.get('generate_purls', True),
            'generate_cpes': self.config.get('generate_cpes', False)
        }
        
        # Tool information
        self.tool_info = {
            'vendor': 'NjordScan',
            'name': 'SBOM Generator',
            'version': '1.0.0',
            'hashes': []
        }
        
        # Statistics
        self.stats = {
            'sboms_generated': 0,
            'components_processed': 0,
            'vulnerabilities_included': 0,
            'formats_generated': defaultdict(int)
        }
    
    async def generate_sbom(self, dependency_graph: DependencyGraph, 
                           project_info: Dict[str, Any],
                           formats: List[SBOMFormat] = None) -> Dict[SBOMFormat, SBOM]:
        """Generate SBOM in specified formats."""
        
        if formats is None:
            formats = [SBOMFormat.CYCLONE_DX_JSON]
        
        logger.info(f"Generating SBOM in formats: {[f.value for f in formats]}")
        
        # Convert dependency graph to SBOM components
        components = await self._convert_dependencies_to_components(dependency_graph)
        
        # Create metadata
        metadata = await self._create_sbom_metadata(project_info, dependency_graph)
        
        # Generate SBOMs in requested formats
        sboms = {}
        
        for format_type in formats:
            if format_type == SBOMFormat.CYCLONE_DX_JSON:
                sbom = await self._generate_cyclone_dx_sbom(components, metadata, dependency_graph)
            elif format_type == SBOMFormat.SPDX_JSON:
                sbom = await self._generate_spdx_sbom(components, metadata, dependency_graph)
            elif format_type == SBOMFormat.SWID_JSON:
                sbom = await self._generate_swid_sbom(components, metadata, dependency_graph)
            else:
                logger.warning(f"Unsupported SBOM format: {format_type}")
                continue
            
            sboms[format_type] = sbom
            self.stats['formats_generated'][format_type.value] += 1
        
        # Update statistics
        self.stats['sboms_generated'] += 1
        self.stats['components_processed'] += len(components)
        
        logger.info(f"SBOM generation completed: {len(components)} components, {len(formats)} formats")
        
        return sboms
    
    async def _convert_dependencies_to_components(self, dependency_graph: DependencyGraph) -> List[SBOMComponent]:
        """Convert dependency graph to SBOM components."""
        
        components = []
        
        for dep_key, dep_info in dependency_graph.all_dependencies.items():
            # Skip dev dependencies if not configured to include them
            if (not self.generation_config['include_dev_deps'] and 
                dep_info.dependency_type.value == 'dev'):
                continue
            
            # Skip transitive dependencies if not configured to include them
            if (not self.generation_config['include_transitive_deps'] and 
                dep_info.dependency_type.value == 'transitive'):
                continue
            
            component = await self._create_sbom_component(dep_info, dependency_graph)
            components.append(component)
        
        return components
    
    async def _create_sbom_component(self, dep_info: DependencyInfo, 
                                   dependency_graph: DependencyGraph) -> SBOMComponent:
        """Create SBOM component from dependency info."""
        
        # Generate component reference
        bom_ref = f"{dep_info.package_manager.value}:{dep_info.name}@{dep_info.version}"
        
        # Determine component type
        component_type = ComponentType.LIBRARY
        if dep_info.name in ['react', 'vue', 'angular', 'express', 'django', 'spring']:
            component_type = ComponentType.FRAMEWORK
        
        # Create component
        component = SBOMComponent(
            bom_ref=bom_ref,
            type=component_type,
            name=dep_info.name,
            version=dep_info.version,
            description=dep_info.description,
            author=dep_info.author,
            scope="required" if dep_info.dependency_type.value in ['direct', 'transitive'] else "optional"
        )
        
        # Generate Package URL (PURL)
        if self.generation_config['generate_purls']:
            component.purl = self._generate_purl(dep_info)
        
        # Generate CPE if configured
        if self.generation_config['generate_cpes']:
            component.cpe = self._generate_cpe(dep_info)
        
        # Add hashes if configured
        if self.generation_config['include_hashes'] and dep_info.file_hash:
            component.hashes = [{
                'alg': 'SHA-256',
                'content': dep_info.file_hash
            }]
        
        # Add licenses if configured
        if self.generation_config['include_licenses'] and dep_info.license:
            component.licenses = [{
                'license': {
                    'id': dep_info.license if dep_info.license in self._get_spdx_licenses() else None,
                    'name': dep_info.license
                }
            }]
        
        # Add supplier information if configured
        if self.generation_config['include_supplier_info']:
            if dep_info.maintainers:
                component.supplier = {
                    'name': dep_info.maintainers[0],
                    'contact': []
                }
        
        # Add vulnerabilities if configured
        if self.generation_config['include_vulnerabilities'] and dep_info.known_vulnerabilities:
            component.vulnerabilities = []
            for vuln in dep_info.known_vulnerabilities:
                component.vulnerabilities.append({
                    'id': vuln.get('id', ''),
                    'source': {
                        'name': vuln.get('source', 'Unknown'),
                        'url': vuln.get('url', '')
                    },
                    'ratings': [{
                        'source': {'name': 'NVD'},
                        'severity': vuln.get('severity', 'unknown').upper(),
                        'method': 'CVSSv3'
                    }],
                    'description': vuln.get('description', ''),
                    'recommendation': vuln.get('recommendation', ''),
                    'advisories': []
                })
            
            # Set risk rating based on vulnerabilities
            if any(v.get('severity') == 'critical' for v in dep_info.known_vulnerabilities):
                component.risk_rating = "critical"
            elif any(v.get('severity') == 'high' for v in dep_info.known_vulnerabilities):
                component.risk_rating = "high"
            elif any(v.get('severity') == 'medium' for v in dep_info.known_vulnerabilities):
                component.risk_rating = "medium"
            else:
                component.risk_rating = "low"
        
        # Add dependency relationships
        component.dependencies = [
            f"{child_dep.split(':', 1)[1]}@{dependency_graph.all_dependencies[child_dep].version}"
            for child_dep in dep_info.child_dependencies
            if child_dep in dependency_graph.all_dependencies
        ]
        
        return component
    
    async def _create_sbom_metadata(self, project_info: Dict[str, Any], 
                                  dependency_graph: DependencyGraph) -> SBOMMetadata:
        """Create SBOM metadata."""
        
        # Create main component (the project itself)
        main_component = {
            'type': 'application',
            'bom-ref': project_info.get('name', 'unknown-project'),
            'name': project_info.get('name', 'Unknown Project'),
            'version': project_info.get('version', '1.0.0'),
            'description': project_info.get('description', ''),
            'scope': 'required'
        }
        
        # Create metadata
        metadata = SBOMMetadata(
            timestamp=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            tools=[self.tool_info],
            authors=[{
                'name': project_info.get('author', 'Unknown'),
                'email': project_info.get('email', '')
            }],
            component=main_component,
            lifecycle='build'
        )
        
        return metadata
    
    async def _generate_cyclone_dx_sbom(self, components: List[SBOMComponent], 
                                      metadata: SBOMMetadata,
                                      dependency_graph: DependencyGraph) -> SBOM:
        """Generate CycloneDX format SBOM."""
        
        # Create dependency relationships
        dependencies = []
        for component in components:
            if component.dependencies:
                dependencies.append({
                    'ref': component.bom_ref,
                    'dependsOn': component.dependencies
                })
        
        # Collect all vulnerabilities
        all_vulnerabilities = []
        for component in components:
            if component.vulnerabilities:
                for vuln in component.vulnerabilities:
                    vuln['affects'] = [{
                        'ref': component.bom_ref
                    }]
                    all_vulnerabilities.append(vuln)
        
        # Create SBOM
        sbom = SBOM(
            bom_format='CycloneDX',
            spec_version='1.5',
            serial_number=metadata.serial_number,
            version=metadata.version,
            metadata=metadata,
            components=components,
            dependencies=dependencies,
            vulnerabilities=all_vulnerabilities
        )
        
        return sbom
    
    async def _generate_spdx_sbom(self, components: List[SBOMComponent], 
                                metadata: SBOMMetadata,
                                dependency_graph: DependencyGraph) -> SBOM:
        """Generate SPDX format SBOM."""
        
        # SPDX has different structure - convert components to SPDX packages
        spdx_packages = []
        relationships = []
        
        for component in components:
            spdx_package = {
                'SPDXID': f"SPDXRef-Package-{component.name}",
                'name': component.name,
                'downloadLocation': component.purl if component.purl else 'NOASSERTION',
                'filesAnalyzed': False,
                'licenseConcluded': component.licenses[0]['license']['name'] if component.licenses else 'NOASSERTION',
                'licenseDeclared': component.licenses[0]['license']['name'] if component.licenses else 'NOASSERTION',
                'copyrightText': component.copyright if component.copyright else 'NOASSERTION',
                'versionInfo': component.version
            }
            
            if component.description:
                spdx_package['description'] = component.description
            
            if component.hashes:
                spdx_package['checksums'] = [{
                    'algorithm': component.hashes[0]['alg'].replace('-', ''),
                    'checksumValue': component.hashes[0]['content']
                }]
            
            spdx_packages.append(spdx_package)
            
            # Create relationships
            for dep in component.dependencies:
                relationships.append({
                    'spdxElementId': f"SPDXRef-Package-{component.name}",
                    'relationshipType': 'DEPENDS_ON',
                    'relatedSpdxElement': f"SPDXRef-Package-{dep.split('@')[0]}"
                })
        
        # Create SPDX document
        sbom = SBOM(
            bom_format='SPDX',
            spec_version='2.3',
            serial_number=metadata.serial_number,
            version=metadata.version,
            metadata=metadata,
            components=spdx_packages,  # Store as components for consistency
            dependencies=relationships
        )
        
        return sbom
    
    async def _generate_swid_sbom(self, components: List[SBOMComponent], 
                                metadata: SBOMMetadata,
                                dependency_graph: DependencyGraph) -> SBOM:
        """Generate SWID format SBOM."""
        
        # SWID (Software Identification) tags
        swid_tags = []
        
        for component in components:
            swid_tag = {
                'tagId': f"swid:{component.name}-{component.version}",
                'name': component.name,
                'version': component.version,
                'tagVersion': '1.0',
                'corpus': False,
                'patch': False,
                'supplemental': False,
                'entity': {
                    'name': component.supplier.get('name', 'Unknown') if component.supplier else 'Unknown',
                    'role': ['softwareCreator', 'tagCreator']
                }
            }
            
            if component.description:
                swid_tag['summary'] = component.description
            
            swid_tags.append(swid_tag)
        
        # Create SWID SBOM
        sbom = SBOM(
            bom_format='SWID',
            spec_version='1.0',
            serial_number=metadata.serial_number,
            version=metadata.version,
            metadata=metadata,
            components=swid_tags
        )
        
        return sbom
    
    def _generate_purl(self, dep_info: DependencyInfo) -> str:
        """Generate Package URL (PURL) for dependency."""
        
        # PURL format: pkg:type/namespace/name@version?qualifiers#subpath
        
        purl_types = {
            'npm': 'npm',
            'pip': 'pypi',
            'maven': 'maven',
            'cargo': 'cargo',
            'go': 'golang'
        }
        
        purl_type = purl_types.get(dep_info.package_manager.value, 'generic')
        
        # Handle Maven coordinates (groupId:artifactId)
        if ':' in dep_info.name and dep_info.package_manager.value == 'maven':
            group_id, artifact_id = dep_info.name.split(':', 1)
            return f"pkg:maven/{group_id}/{artifact_id}@{dep_info.version}"
        
        # Standard PURL
        return f"pkg:{purl_type}/{dep_info.name}@{dep_info.version}"
    
    def _generate_cpe(self, dep_info: DependencyInfo) -> str:
        """Generate Common Platform Enumeration (CPE) for dependency."""
        
        # CPE format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        
        # Simplified CPE generation
        vendor = dep_info.author.lower().replace(' ', '_') if dep_info.author else 'unknown'
        product = dep_info.name.lower().replace(' ', '_')
        version = dep_info.version.replace(' ', '_')
        
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    
    def _get_spdx_licenses(self) -> Set[str]:
        """Get list of SPDX license identifiers."""
        
        # Common SPDX license IDs (would be loaded from official list)
        return {
            'MIT', 'Apache-2.0', 'GPL-2.0', 'GPL-3.0', 'BSD-2-Clause', 'BSD-3-Clause',
            'ISC', 'MPL-2.0', 'LGPL-2.1', 'LGPL-3.0', 'CC0-1.0', 'Unlicense',
            'AGPL-3.0', 'EPL-2.0', 'EUPL-1.2'
        }
    
    async def export_sbom(self, sbom: SBOM, format_type: SBOMFormat, 
                         output_path: Path) -> bool:
        """Export SBOM to file."""
        
        try:
            if format_type == SBOMFormat.CYCLONE_DX_JSON:
                content = await self._export_cyclone_dx_json(sbom)
            elif format_type == SBOMFormat.SPDX_JSON:
                content = await self._export_spdx_json(sbom)
            elif format_type == SBOMFormat.SWID_JSON:
                content = await self._export_swid_json(sbom)
            elif format_type == SBOMFormat.CYCLONE_DX_XML:
                content = await self._export_cyclone_dx_xml(sbom)
            else:
                logger.error(f"Unsupported export format: {format_type}")
                return False
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logger.info(f"SBOM exported to: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export SBOM: {str(e)}")
            return False
    
    async def _export_cyclone_dx_json(self, sbom: SBOM) -> str:
        """Export SBOM in CycloneDX JSON format."""
        
        cyclone_dx = {
            'bomFormat': sbom.bom_format,
            'specVersion': sbom.spec_version,
            'serialNumber': sbom.serial_number,
            'version': sbom.version,
            'metadata': {
                'timestamp': sbom.metadata.timestamp,
                'tools': sbom.metadata.tools,
                'authors': sbom.metadata.authors,
                'component': sbom.metadata.component
            },
            'components': []
        }
        
        # Convert components
        for component in sbom.components:
            comp_dict = {
                'bom-ref': component.bom_ref,
                'type': component.type.value,
                'name': component.name,
                'version': component.version,
                'scope': component.scope
            }
            
            if component.description:
                comp_dict['description'] = component.description
            
            if component.purl:
                comp_dict['purl'] = component.purl
            
            if component.hashes:
                comp_dict['hashes'] = component.hashes
            
            if component.licenses:
                comp_dict['licenses'] = component.licenses
            
            if component.supplier:
                comp_dict['supplier'] = component.supplier
            
            cyclone_dx['components'].append(comp_dict)
        
        # Add dependencies
        if sbom.dependencies:
            cyclone_dx['dependencies'] = sbom.dependencies
        
        # Add vulnerabilities
        if sbom.vulnerabilities:
            cyclone_dx['vulnerabilities'] = sbom.vulnerabilities
        
        return json.dumps(cyclone_dx, indent=2, ensure_ascii=False)
    
    async def _export_spdx_json(self, sbom: SBOM) -> str:
        """Export SBOM in SPDX JSON format."""
        
        spdx_doc = {
            'spdxVersion': f'SPDX-{sbom.spec_version}',
            'dataLicense': 'CC0-1.0',
            'SPDXID': 'SPDXRef-DOCUMENT',
            'documentName': sbom.metadata.component.get('name', 'Unknown'),
            'documentNamespace': sbom.serial_number,
            'creationInfo': {
                'created': sbom.metadata.timestamp,
                'creators': [f"Tool: {tool['name']}-{tool['version']}" for tool in sbom.metadata.tools]
            },
            'packages': sbom.components,  # Already converted to SPDX format
            'relationships': sbom.dependencies
        }
        
        return json.dumps(spdx_doc, indent=2, ensure_ascii=False)
    
    async def _export_swid_json(self, sbom: SBOM) -> str:
        """Export SBOM in SWID JSON format."""
        
        swid_doc = {
            'SoftwareIdentity': {
                'tagId': sbom.serial_number,
                'name': sbom.metadata.component.get('name', 'Unknown'),
                'version': sbom.metadata.component.get('version', '1.0.0'),
                'tagVersion': sbom.version,
                'corpus': True,
                'patch': False,
                'supplemental': False,
                'Entity': {
                    'name': sbom.metadata.authors[0]['name'] if sbom.metadata.authors else 'Unknown',
                    'role': ['softwareCreator', 'tagCreator']
                },
                'Payload': {
                    'Directory': {
                        'name': sbom.metadata.component.get('name', 'Unknown'),
                        'File': sbom.components  # SWID tags
                    }
                }
            }
        }
        
        return json.dumps(swid_doc, indent=2, ensure_ascii=False)
    
    async def _export_cyclone_dx_xml(self, sbom: SBOM) -> str:
        """Export SBOM in CycloneDX XML format."""
        
        # Simplified XML generation (would use proper XML library)
        xml_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/{sbom.spec_version}" serialNumber="{sbom.serial_number}" version="{sbom.version}">
  <metadata>
    <timestamp>{sbom.metadata.timestamp}</timestamp>
    <tools>
      <tool>
        <vendor>{sbom.metadata.tools[0]['vendor']}</vendor>
        <name>{sbom.metadata.tools[0]['name']}</name>
        <version>{sbom.metadata.tools[0]['version']}</version>
      </tool>
    </tools>
    <component type="{sbom.metadata.component['type']}" bom-ref="{sbom.metadata.component['bom-ref']}">
      <name>{sbom.metadata.component['name']}</name>
      <version>{sbom.metadata.component['version']}</version>
    </component>
  </metadata>
  <components>
'''
        
        for component in sbom.components:
            xml_content += f'''    <component type="{component.type.value}" bom-ref="{component.bom_ref}">
      <name>{component.name}</name>
      <version>{component.version}</version>
      <scope>{component.scope}</scope>
'''
            if component.purl:
                xml_content += f'      <purl>{component.purl}</purl>\n'
            
            xml_content += '    </component>\n'
        
        xml_content += '''  </components>
</bom>'''
        
        return xml_content
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get SBOM generator statistics."""
        
        return dict(self.stats)
