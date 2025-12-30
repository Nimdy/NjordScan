"""
🛡️ Vulnerability Data Update System for NjordScan v1.0.0

Enhanced vulnerability database management with community integration,
AI-powered threat intelligence, and advanced update mechanisms.
"""

import asyncio
import aiohttp
import json
import hashlib
import time
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
import yaml

from .config import Config
from .utils import NjordScore

@dataclass
class UpdateSource:
    """Configuration for a vulnerability data source."""
    name: str
    url: str
    api_key: Optional[str] = None
    update_frequency: int = 24  # hours
    enabled: bool = True
    last_update: Optional[float] = None
    etag: Optional[str] = None

class VulnerabilityDataManager:
    """Main vulnerability data manager."""
    
    def __init__(self, config: Config):
        self.config = config
        self.data_dir = Path(__file__).parent / 'data'  # Fixed path
        self.sources_dir = self.data_dir / 'sources'
        self.processed_dir = self.data_dir / 'processed'
        self.cache_dir = self.data_dir / 'cache'
        self.metadata_dir = self.data_dir / 'metadata'
        self.backup_dir = self.data_dir / 'backup'
        
        # Create directories
        for directory in [self.sources_dir, self.processed_dir, self.cache_dir, 
                         self.metadata_dir, self.backup_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        self.sources = self._load_update_sources()
        
        # Integration with community features
        self.community_enabled = getattr(config, 'community_config', None) and config.community_config.enabled
        self.ai_enabled = getattr(config, 'ai_config', None) and config.ai_config.enabled
        
    def _load_update_sources(self) -> Dict[str, UpdateSource]:
        """Load vulnerability data sources configuration."""
        return {
            'nist_cve': UpdateSource(
                name='nist_cve',
                url='https://services.nvd.nist.gov/rest/json/cves/2.0',
                update_frequency=1  # Update every hour for critical CVE data
            ),
            'npm_security': UpdateSource(
                name='npm_security',
                url='https://api.github.com/advisories?ecosystem=npm&per_page=100',
                update_frequency=6  # Update every 6 hours
            ),
            'github_advisories': UpdateSource(
                name='github_advisories', 
                url='https://api.github.com/advisories',
                update_frequency=12
            ),
            # Snyk requires API key - disabled by default
            # To enable: set SNYK_API_TOKEN environment variable
            # 'snyk_js': UpdateSource(
            #     name='snyk_js',
            #     url='https://snyk.io/api/v1/vulnerabilities/npm',
            #     update_frequency=24,
            #     api_key=os.environ.get('SNYK_API_TOKEN'),
            #     enabled=bool(os.environ.get('SNYK_API_TOKEN'))
            # ),
            'mitre_attck': UpdateSource(
                name='mitre_attck',
                url='https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json',
                update_frequency=24  # Update daily
            ),
            'nextjs_security': UpdateSource(
                name='nextjs_security',
                url='https://api.github.com/repos/vercel/next.js/security-advisories',
                update_frequency=24
            ),
            'react_security': UpdateSource(
                name='react_security',
                url='https://api.github.com/repos/facebook/react/security-advisories',
                update_frequency=24
            ),
            'vite_security': UpdateSource(
                name='vite_security',
                url='https://api.github.com/repos/vitejs/vite/security-advisories', 
                update_frequency=24
            )
        }
    
    async def check_for_updates(self) -> Dict[str, bool]:
        """Check which sources have available updates."""
        update_status = {}
        
        for source_name, source in self.sources.items():
            if not source.enabled:
                continue
                
            needs_update = await self._source_needs_update(source)
            update_status[source_name] = needs_update
            
        return update_status
    
    async def _source_needs_update(self, source: UpdateSource) -> bool:
        """Check if a specific source needs updating."""
        if not source.last_update:
            return True
            
        hours_since_update = (time.time() - source.last_update) / 3600
        return hours_since_update >= source.update_frequency
    
    async def update_all_sources(self, force: bool = False) -> Dict[str, Any]:
        """Update all enabled vulnerability sources."""
        results = {}
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for source_name, source in self.sources.items():
                if source.enabled:
                    # Force update by clearing last_update timestamp
                    if force:
                        source.last_update = None
                        source.etag = None
                    
                    task = self._update_source(session, source)
                    tasks.append((source_name, task))
            
            for source_name, task in tasks:
                try:
                    result = await task
                    results[source_name] = result
                except Exception as e:
                    results[source_name] = {'error': str(e), 'success': False}
        
        # Process and merge all updated data
        await self._process_and_merge_data()
        
        return results
    
    async def _update_source(self, session: aiohttp.ClientSession, 
                           source: UpdateSource) -> Dict[str, Any]:
        """Update a single vulnerability source."""
        headers = {}
        if source.etag:
            headers['If-None-Match'] = source.etag
        if source.api_key:
            headers['Authorization'] = f'token {source.api_key}'
        
        try:
            async with session.get(source.url, headers=headers) as response:
                if response.status == 304:
                    return {'success': True, 'updated': False, 'message': 'No changes'}
                
                if response.status != 200:
                    return {'success': False, 'error': f'HTTP {response.status}'}
                
                # Handle different content types
                content_type = response.headers.get('Content-Type', '')
                
                if 'json' in content_type or source.name == 'mitre_attck':
                    # Try JSON first (MITRE returns text/plain but is actually JSON)
                    try:
                        data = await response.json()
                    except Exception as e:
                        # If JSON fails, try text
                        text_data = await response.text()
                        try:
                            data = json.loads(text_data)
                        except:
                            return {'success': False, 'error': f'Could not parse response: {str(e)}'}
                else:
                    # For other types, get text and try to parse
                    text_data = await response.text()
                    try:
                        data = json.loads(text_data)
                    except:
                        return {'success': False, 'error': 'Response is not JSON'}
                
                # Save raw data to cache
                cache_file = self.cache_dir / f'{source.name}_cache.json'
                with open(cache_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
                
                # Update source metadata
                source.last_update = time.time()
                source.etag = response.headers.get('ETag')
                
                return {
                    'success': True, 
                    'updated': True, 
                    'records': len(data) if isinstance(data, list) else 1
                }
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _process_and_merge_data(self):
        """Process raw vulnerability data and merge into usable databases."""
        processors = {
            'cve_database': self._process_cve_data,
            'mitre_attck': self._process_mitre_attck_data,
            'js_frameworks': self._process_js_frameworks,
            'npm_packages': self._process_npm_packages,
            'ai_libraries': self._process_ai_libraries,
            'framework_rules': self._process_framework_rules
        }
        
        for processor_name, processor_func in processors.items():
            try:
                processed_data = await processor_func()
                output_file = self.processed_dir / f'{processor_name}.json'
                
                # Backup existing file
                if output_file.exists():
                    backup_file = self.backup_dir / f'{processor_name}_{int(time.time())}.json'
                    output_file.rename(backup_file)
                
                # Write new processed data
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(processed_data, f, indent=2)
                    
            except Exception as e:
                print(f"Error processing {processor_name}: {e}")
    
    async def _process_cve_data(self) -> Dict[str, Any]:
        """Process NIST CVE data into usable format."""
        cve_data = {
            'vulnerabilities': {},
            'last_updated': datetime.now().isoformat(),
            'total_count': 0
        }
        
        # Process NIST CVE data
        nist_cache = self.cache_dir / 'nist_cve_cache.json'
        if nist_cache.exists():
            with open(nist_cache, 'r', encoding='utf-8') as f:
                nist_data = json.load(f)
                
                if 'vulnerabilities' in nist_data:
                    for vuln in nist_data['vulnerabilities']:
                        cve_id = vuln.get('cve', {}).get('id', '')
                        if cve_id:
                            # Extract relevant information
                            description = ""
                            if 'descriptions' in vuln.get('cve', {}):
                                for desc in vuln['cve']['descriptions']:
                                    if desc.get('lang') == 'en':
                                        description = desc.get('value', '')
                                        break
                            
                            # Extract CVSS score
                            cvss_score = 0.0
                            severity = 'unknown'
                            if 'metrics' in vuln:
                                if 'cvssMetricV31' in vuln['metrics']:
                                    cvss_data = vuln['metrics']['cvssMetricV31'][0]['cvssData']
                                    cvss_score = cvss_data.get('baseScore', 0.0)
                                    severity = self._cvss_to_severity(cvss_score)
                                elif 'cvssMetricV30' in vuln['metrics']:
                                    cvss_data = vuln['metrics']['cvssMetricV30'][0]['cvssData']
                                    cvss_score = cvss_data.get('baseScore', 0.0)
                                    severity = self._cvss_to_severity(cvss_score)
                                elif 'cvssMetricV2' in vuln['metrics']:
                                    cvss_data = vuln['metrics']['cvssMetricV2'][0]['cvssData']
                                    cvss_score = cvss_data.get('baseScore', 0.0)
                                    severity = self._cvss_to_severity(cvss_score)
                            
                            # Extract references
                            references = []
                            if 'references' in vuln.get('cve', {}):
                                for ref in vuln['cve']['references']:
                                    if ref.get('url'):
                                        references.append(ref['url'])
                            
                            # Extract CWE
                            cwe = []
                            if 'weaknesses' in vuln.get('cve', {}):
                                for weakness in vuln['cve']['weaknesses']:
                                    if 'description' in weakness:
                                        for desc in weakness['description']:
                                            if desc.get('value'):
                                                cwe.append(desc['value'])
                            
                            cve_data['vulnerabilities'][cve_id] = {
                                'id': cve_id,
                                'description': description,
                                'severity': severity,
                                'cvss_score': cvss_score,
                                'published_date': vuln.get('cve', {}).get('published', ''),
                                'last_modified': vuln.get('cve', {}).get('lastModified', ''),
                                'references': references,
                                'cwe': cwe,
                                'configurations': vuln.get('configurations', [])
                            }
                            cve_data['total_count'] += 1
        
        return cve_data
    
    async def _process_mitre_attck_data(self) -> Dict[str, Any]:
        """Process MITRE ATT&CK data into usable format."""
        mitre_data = {
            'techniques': {},
            'tactics': {},
            'actors': {},
            'campaigns': {},
            'last_updated': datetime.now().isoformat()
        }
        
        # Process MITRE ATT&CK data
        mitre_cache = self.cache_dir / 'mitre_attck_cache.json'
        if mitre_cache.exists():
            with open(mitre_cache, 'r', encoding='utf-8') as f:
                mitre_raw = json.load(f)
                
                if 'objects' in mitre_raw:
                    for obj in mitre_raw['objects']:
                        obj_type = obj.get('type', '')
                        obj_id = obj.get('id', '')
                        
                        if obj_type == 'attack-pattern' and obj_id.startswith('T'):
                            # Technique
                            mitre_data['techniques'][obj_id] = {
                                'id': obj_id,
                                'name': obj.get('name', ''),
                                'description': obj.get('description', ''),
                                'tactics': [tactic.get('phase_name', '') for tactic in obj.get('kill_chain_phases', [])],
                                'platforms': obj.get('x_mitre_platforms', []),
                                'permissions_required': obj.get('x_mitre_permissions_required', []),
                                'data_sources': obj.get('x_mitre_data_sources', []),
                                'references': [ref.get('url', '') for ref in obj.get('external_references', []) if ref.get('url')]
                            }
                        
                        elif obj_type == 'x-mitre-tactic' and obj_id.startswith('TA'):
                            # Tactic
                            mitre_data['tactics'][obj_id] = {
                                'id': obj_id,
                                'name': obj.get('name', ''),
                                'description': obj.get('description', ''),
                                'url': next((ref.get('url', '') for ref in obj.get('external_references', []) if ref.get('source_name') == 'mitre-attack'), '')
                            }
                        
                        elif obj_type == 'intrusion-set' and obj_id.startswith('G'):
                            # Threat Actor
                            mitre_data['actors'][obj_id] = {
                                'id': obj_id,
                                'name': obj.get('name', ''),
                                'description': obj.get('description', ''),
                                'aliases': obj.get('aliases', []),
                                'sophistication': obj.get('sophistication', ''),
                                'resource_level': obj.get('resource_level', ''),
                                'primary_motivation': obj.get('primary_motivation', ''),
                                'goals': obj.get('goals', [])
                            }
                        
                        elif obj_type == 'campaign' and obj_id.startswith('C'):
                            # Campaign
                            mitre_data['campaigns'][obj_id] = {
                                'id': obj_id,
                                'name': obj.get('name', ''),
                                'description': obj.get('description', ''),
                                'aliases': obj.get('aliases', []),
                                'first_seen': obj.get('first_seen', ''),
                                'last_seen': obj.get('last_seen', ''),
                                'objective': obj.get('objective', '')
                            }
        
        return mitre_data
    
    def _cvss_to_severity(self, cvss_score: float) -> str:
        """Convert CVSS score to severity level."""
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        elif cvss_score >= 0.1:
            return 'low'
        else:
            return 'info'
    
    async def _process_js_frameworks(self) -> Dict[str, Any]:
        """Process framework-specific vulnerabilities."""
        frameworks_data = {
            'nextjs': [],
            'react': [],
            'vite': [],
            'last_updated': datetime.now().isoformat()
        }
        
        # Process Next.js vulnerabilities
        nextjs_cache = self.cache_dir / 'nextjs_security_cache.json'
        if nextjs_cache.exists():
            with open(nextjs_cache, 'r', encoding='utf-8') as f:
                nextjs_data = json.load(f)
                frameworks_data['nextjs'] = self._normalize_github_advisories(nextjs_data)
        
        # Process React vulnerabilities
        react_cache = self.cache_dir / 'react_security_cache.json'
        if react_cache.exists():
            with open(react_cache, 'r', encoding='utf-8') as f:
                react_data = json.load(f)
                frameworks_data['react'] = self._normalize_github_advisories(react_data)
        
        # Process Vite vulnerabilities
        vite_cache = self.cache_dir / 'vite_security_cache.json'
        if vite_cache.exists():
            with open(vite_cache, 'r', encoding='utf-8') as f:
                vite_data = json.load(f)
                frameworks_data['vite'] = self._normalize_github_advisories(vite_data)
        
        return frameworks_data
    
    async def _process_npm_packages(self) -> Dict[str, Any]:
        """Process npm package vulnerabilities."""
        npm_data = {
            'packages': {},
            'last_updated': datetime.now().isoformat()
        }
        
        # Process npm security data
        npm_cache = self.cache_dir / 'npm_security_cache.json'
        if npm_cache.exists():
            with open(npm_cache, 'r', encoding='utf-8') as f:
                npm_advisories = json.load(f)
                npm_data['packages'] = self._normalize_npm_advisories(npm_advisories)
        
        # Process Snyk data
        snyk_cache = self.cache_dir / 'snyk_js_cache.json'
        if snyk_cache.exists():
            with open(snyk_cache, 'r', encoding='utf-8') as f:
                snyk_data = json.load(f)
                snyk_packages = self._normalize_snyk_data(snyk_data)
                
                # Merge with npm data
                for package_name, vulns in snyk_packages.items():
                    if package_name in npm_data['packages']:
                        npm_data['packages'][package_name]['vulnerabilities'].extend(vulns)
                    else:
                        npm_data['packages'][package_name] = {'vulnerabilities': vulns}
        
        return npm_data
    
    async def _process_ai_libraries(self) -> Dict[str, Any]:
        """Process AI library-specific vulnerabilities."""
        ai_data = {
            'libraries': {
                'openai': [],
                'anthropic': [],
                'langchain': [],
                'huggingface': []
            },
            'patterns': {
                'api_key_exposure': [],
                'prompt_injection': [],
                'unsafe_execution': []
            },
            'last_updated': datetime.now().isoformat()
        }
        
        # Process GitHub advisories for AI libraries
        github_cache = self.cache_dir / 'github_advisories_cache.json'
        if github_cache.exists():
            with open(github_cache, 'r', encoding='utf-8') as f:
                github_data = json.load(f)
                ai_advisories = self._filter_ai_advisories(github_data)
                
                for advisory in ai_advisories:
                    package_name = advisory.get('package', {}).get('name', '')
                    if 'openai' in package_name.lower():
                        ai_data['libraries']['openai'].append(advisory)
                    elif 'anthropic' in package_name.lower():
                        ai_data['libraries']['anthropic'].append(advisory)
                    elif 'langchain' in package_name.lower():
                        ai_data['libraries']['langchain'].append(advisory)
                    elif 'huggingface' in package_name.lower():
                        ai_data['libraries']['huggingface'].append(advisory)
        
        return ai_data
    
    async def _process_framework_rules(self) -> Dict[str, Any]:
        """Process and update framework-specific detection rules."""
        rules_data = {
            'nextjs': {
                'ssrf_patterns': [],
                'xss_patterns': [],
                'secrets_patterns': [],
                'api_security': []
            },
            'react': {
                'xss_patterns': [],
                'component_security': [],
                'hooks_security': []
            },
            'vite': {
                'build_security': [],
                'dev_server': [],
                'plugin_security': []
            },
            'last_updated': datetime.now().isoformat()
        }
        
        # Load existing rules and enhance with new vulnerability data
        existing_rules = self.data_dir / 'rules.yaml'
        if existing_rules.exists():
            with open(existing_rules, 'r', encoding='utf-8') as f:
                base_rules = yaml.safe_load(f)
                
            # Merge base rules with new intelligence
            rules_data.update(base_rules)
        
        return rules_data
    
    def _normalize_github_advisories(self, advisories: List[Dict]) -> List[Dict]:
        """Normalize GitHub security advisories format."""
        normalized = []
        for advisory in advisories:
            normalized.append({
                'id': advisory.get('ghsa_id'),
                'cve_id': advisory.get('cve_id'),
                'summary': advisory.get('summary'),
                'severity': advisory.get('severity', 'unknown').lower(),
                'published_at': advisory.get('published_at'),
                'updated_at': advisory.get('updated_at'),
                'references': advisory.get('references', []),
                'vulnerabilities': advisory.get('vulnerabilities', [])
            })
        return normalized
    
    def _normalize_npm_advisories(self, advisories) -> Dict[str, Any]:
        """Normalize npm audit advisories format (handles both dict and list formats)."""
        packages = {}
        
        # Handle GitHub Advisory format (list)
        if isinstance(advisories, list):
            for advisory in advisories:
                # Extract package name from affected packages
                affected = advisory.get('vulnerabilities', [])
                if not affected:
                    continue
                    
                for vuln_pkg in affected:
                    # Handle both dict and other formats
                    if isinstance(vuln_pkg, dict):
                        pkg_info = vuln_pkg.get('package', {})
                        package_name = pkg_info.get('name') if isinstance(pkg_info, dict) else None
                    else:
                        continue
                        
                    if not package_name:
                        continue
                    
                    vuln = {
                        'id': advisory.get('ghsa_id') or advisory.get('id'),
                        'cve_ids': [advisory.get('cve_id')] if advisory.get('cve_id') else [],
                        'title': advisory.get('summary'),
                        'severity': advisory.get('severity', 'unknown').lower(),
                        'vulnerable_versions': vuln_pkg.get('vulnerable_version_range'),
                        'patched_versions': [vuln_pkg.get('first_patched_version')] if vuln_pkg.get('first_patched_version') else [],
                        'published_at': advisory.get('published_at'),
                        'references': advisory.get('references', [])
                    }
                    
                    if package_name not in packages:
                        packages[package_name] = {'vulnerabilities': []}
                    
                    packages[package_name]['vulnerabilities'].append(vuln)
        
        # Handle original npm advisories format (dict)
        elif isinstance(advisories, dict):
            for advisory_id, advisory in advisories.items():
                package_name = advisory.get('module_name')
                if not package_name:
                    continue
                    
                vuln = {
                    'id': advisory_id,
                    'cve_ids': advisory.get('cves', []),
                    'title': advisory.get('title'),
                    'severity': advisory.get('severity', 'unknown').lower(),
                    'vulnerable_versions': advisory.get('vulnerable_versions'),
                    'patched_versions': advisory.get('patched_versions'),
                    'published_at': advisory.get('created'),
                    'references': [advisory.get('url')] if advisory.get('url') else []
                }
                
                if package_name not in packages:
                    packages[package_name] = {'vulnerabilities': []}
                
                packages[package_name]['vulnerabilities'].append(vuln)
        
        return packages
    
    def _normalize_snyk_data(self, snyk_data: Dict) -> Dict[str, List[Dict]]:
        """Normalize Snyk vulnerability data format."""
        packages = {}
        
        for vuln in snyk_data.get('vulnerabilities', []):
            package_name = vuln.get('package')
            if not package_name:
                continue
                
            normalized_vuln = {
                'id': vuln.get('id'),
                'title': vuln.get('title'),
                'severity': vuln.get('severity', 'unknown').lower(),
                'vulnerable_versions': vuln.get('semver', {}).get('vulnerable'),
                'patched_versions': vuln.get('semver', {}).get('patched'),
                'published_at': vuln.get('publicationTime'),
                'references': vuln.get('references', [])
            }
            
            if package_name not in packages:
                packages[package_name] = []
                
            packages[package_name].append(normalized_vuln)
        
        return packages
    
    def _filter_ai_advisories(self, advisories: List[Dict]) -> List[Dict]:
        """Filter advisories related to AI libraries."""
        ai_keywords = [
            'openai', 'anthropic', 'langchain', 'huggingface', 'transformers',
            'ai', 'llm', 'gpt', 'claude', 'prompt', 'completion'
        ]
        
        filtered = []
        for advisory in advisories:
            summary = advisory.get('summary', '').lower()
            package_name = advisory.get('package', {}).get('name', '').lower()
            
            if any(keyword in summary or keyword in package_name for keyword in ai_keywords):
                filtered.append(advisory)
        
        return filtered
    
    def get_update_metadata(self) -> Dict[str, Any]:
        """Get metadata about last updates."""
        metadata = {
            'sources': {},
            'last_full_update': None,
            'update_history': []
        }
        
        for source_name, source in self.sources.items():
            metadata['sources'][source_name] = {
                'enabled': source.enabled,
                'last_update': source.last_update,
                'update_frequency': source.update_frequency,
                'next_update': source.last_update + (source.update_frequency * 3600) if source.last_update else None
            }
        
        return metadata
    
    def rollback_to_backup(self, backup_timestamp: int) -> bool:
        """Rollback to a previous backup."""
        try:
            backup_files = list(self.backup_dir.glob(f'*_{backup_timestamp}.json'))
            
            for backup_file in backup_files:
                # Extract original filename
                original_name = backup_file.name.replace(f'_{backup_timestamp}', '')
                target_file = self.processed_dir / original_name
                
                # Copy backup to processed directory
                with open(backup_file) as src, open(target_file, 'w') as dst:
                    dst.write(src.read())
            
            return True
            
        except Exception as e:
            print(f"Rollback failed: {e}")
            return False