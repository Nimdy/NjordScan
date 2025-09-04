#!/usr/bin/env python3
"""
🔧 Custom Rule Creation System
Allow users to create and manage custom security rules.
"""

import re
import json
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass, asdict
from datetime import datetime
import sqlite3

from ..vulnerability import Vulnerability
from ..modules.base import BaseModule

@dataclass
class CustomRule:
    """Custom security rule definition."""
    id: str
    name: str
    description: str
    vuln_type: str
    severity: str
    patterns: List[str]
    file_extensions: List[str]
    frameworks: List[str]
    enabled: bool = True
    created_at: str = None
    updated_at: str = None
    author: str = "user"
    tags: List[str] = None
    fix_guide: str = ""
    reference: str = ""
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now().isoformat()
        if self.updated_at is None:
            self.updated_at = datetime.now().isoformat()
        if self.tags is None:
            self.tags = []

@dataclass
class RuleMatch:
    """Result of a custom rule match."""
    rule: CustomRule
    matches: List[Dict[str, Any]]
    confidence: float
    line_numbers: List[int]

class CustomRuleManager:
    """Manages custom security rules."""
    
    def __init__(self, rules_dir: Path = None):
        self.rules_dir = rules_dir or Path.home() / '.njordscan' / 'custom_rules'
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        
        self.db_path = self.rules_dir / 'rules.db'
        self._init_database()
        
        self.rules: Dict[str, CustomRule] = {}
        self.load_rules()

    def _init_database(self):
        """Initialize the custom rules database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS custom_rules (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        description TEXT,
                        vuln_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        patterns TEXT NOT NULL,
                        file_extensions TEXT,
                        frameworks TEXT,
                        enabled INTEGER DEFAULT 1,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        author TEXT DEFAULT 'user',
                        tags TEXT,
                        fix_guide TEXT,
                        reference TEXT
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS rule_matches (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        rule_id TEXT NOT NULL,
                        file_path TEXT NOT NULL,
                        line_number INTEGER NOT NULL,
                        match_text TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (rule_id) REFERENCES custom_rules (id)
                    )
                ''')
                
                conn.commit()
        except Exception as e:
            print(f"Warning: Could not initialize custom rules database: {e}")

    def create_rule(self, rule: CustomRule) -> bool:
        """Create a new custom rule."""
        try:
            # Validate rule
            if not self._validate_rule(rule):
                return False
                
            # Save to database
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO custom_rules 
                    (id, name, description, vuln_type, severity, patterns, file_extensions,
                     frameworks, enabled, created_at, updated_at, author, tags, fix_guide, reference)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    rule.id, rule.name, rule.description, rule.vuln_type, rule.severity,
                    json.dumps(rule.patterns), json.dumps(rule.file_extensions),
                    json.dumps(rule.frameworks), rule.enabled, rule.created_at,
                    rule.updated_at, rule.author, json.dumps(rule.tags),
                    rule.fix_guide, rule.reference
                ))
                
                conn.commit()
                
            # Save to file
            self._save_rule_to_file(rule)
            
            # Update in-memory rules
            self.rules[rule.id] = rule
            
            return True
            
        except Exception as e:
            print(f"Error creating custom rule: {e}")
            return False

    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing custom rule."""
        try:
            if rule_id not in self.rules:
                return False
                
            rule = self.rules[rule_id]
            
            # Update fields
            for key, value in updates.items():
                if hasattr(rule, key):
                    setattr(rule, key, value)
                    
            rule.updated_at = datetime.now().isoformat()
            
            # Save updated rule
            return self.create_rule(rule)
            
        except Exception as e:
            print(f"Error updating custom rule: {e}")
            return False

    def delete_rule(self, rule_id: str) -> bool:
        """Delete a custom rule."""
        try:
            # Remove from database
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('DELETE FROM custom_rules WHERE id = ?', (rule_id,))
                conn.execute('DELETE FROM rule_matches WHERE rule_id = ?', (rule_id,))
                conn.commit()
                
            # Remove from file
            rule_file = self.rules_dir / f"{rule_id}.json"
            if rule_file.exists():
                rule_file.unlink()
                
            # Remove from memory
            if rule_id in self.rules:
                del self.rules[rule_id]
                
            return True
            
        except Exception as e:
            print(f"Error deleting custom rule: {e}")
            return False

    def get_rule(self, rule_id: str) -> Optional[CustomRule]:
        """Get a custom rule by ID."""
        return self.rules.get(rule_id)

    def get_all_rules(self) -> List[CustomRule]:
        """Get all custom rules."""
        return list(self.rules.values())

    def get_rules_by_type(self, vuln_type: str) -> List[CustomRule]:
        """Get custom rules by vulnerability type."""
        return [rule for rule in self.rules.values() if rule.vuln_type == vuln_type]

    def get_enabled_rules(self) -> List[CustomRule]:
        """Get all enabled custom rules."""
        return [rule for rule in self.rules.values() if rule.enabled]

    def load_rules(self):
        """Load custom rules from database and files."""
        try:
            # Load from database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('SELECT * FROM custom_rules')
                
                for row in cursor.fetchall():
                    rule = CustomRule(
                        id=row[0],
                        name=row[1],
                        description=row[2],
                        vuln_type=row[3],
                        severity=row[4],
                        patterns=json.loads(row[5]),
                        file_extensions=json.loads(row[6]) if row[6] else [],
                        frameworks=json.loads(row[7]) if row[7] else [],
                        enabled=bool(row[8]),
                        created_at=row[9],
                        updated_at=row[10],
                        author=row[11],
                        tags=json.loads(row[12]) if row[12] else [],
                        fix_guide=row[13] or "",
                        reference=row[14] or ""
                    )
                    
                    self.rules[rule.id] = rule
                    
        except Exception as e:
            print(f"Error loading custom rules: {e}")

    def _save_rule_to_file(self, rule: CustomRule):
        """Save a rule to a JSON file."""
        try:
            rule_file = self.rules_dir / f"{rule.id}.json"
            with open(rule_file, 'w', encoding='utf-8') as f:
                json.dump(asdict(rule), f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save rule to file: {e}")

    def _validate_rule(self, rule: CustomRule) -> bool:
        """Validate a custom rule."""
        # Check required fields
        if not rule.id or not rule.name or not rule.vuln_type or not rule.severity:
            return False
            
        # Check severity
        valid_severities = ['low', 'medium', 'high', 'critical']
        if rule.severity not in valid_severities:
            return False
            
        # Check patterns
        if not rule.patterns or not isinstance(rule.patterns, list):
            return False
            
        # Validate regex patterns
        for pattern in rule.patterns:
            try:
                re.compile(pattern)
            except re.error:
                print(f"Invalid regex pattern: {pattern}")
                return False
                
        return True

    def scan_file_with_custom_rules(self, file_path: Path) -> List[Vulnerability]:
        """Scan a file using custom rules."""
        vulnerabilities = []
        
        try:
            if not file_path.exists():
                return vulnerabilities
                
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            file_extension = file_path.suffix.lower()
            
            # Get enabled rules that apply to this file
            applicable_rules = self._get_applicable_rules(file_path, file_extension)
            
            for rule in applicable_rules:
                rule_vulns = self._apply_rule_to_file(rule, content, file_path)
                vulnerabilities.extend(rule_vulns)
                
        except Exception as e:
            print(f"Error scanning file with custom rules: {e}")
            
        return vulnerabilities

    def _get_applicable_rules(self, file_path: Path, file_extension: str) -> List[CustomRule]:
        """Get rules that apply to the given file."""
        applicable_rules = []
        
        for rule in self.get_enabled_rules():
            # Check file extension
            if rule.file_extensions and file_extension not in rule.file_extensions:
                continue
                
            # Check framework
            if rule.frameworks:
                # Simple framework detection
                framework_detected = False
                for framework in rule.frameworks:
                    if framework.lower() in str(file_path).lower():
                        framework_detected = True
                        break
                if not framework_detected:
                    continue
                    
            applicable_rules.append(rule)
            
        return applicable_rules

    def _apply_rule_to_file(self, rule: CustomRule, content: str, file_path: Path) -> List[Vulnerability]:
        """Apply a custom rule to file content."""
        vulnerabilities = []
        
        for pattern in rule.patterns:
            try:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    line_number = content[:match.start()].count('\n') + 1
                    code_snippet = self._extract_code_snippet(content, match.start(), match.end())
                    
                    vulnerability = Vulnerability(
                        title=f"Custom Rule: {rule.name}",
                        description=rule.description,
                        severity=rule.severity,
                        vuln_type=rule.vuln_type,
                        location=str(file_path),
                        file_path=str(file_path),
                        line_number=line_number,
                        code_snippet=code_snippet,
                        fix=rule.fix_guide,
                        reference=rule.reference
                    )
                    
                    vulnerabilities.append(vulnerability)
                    
                    # Store match in database
                    self._store_rule_match(rule, file_path, line_number, match.group(), 1.0)
                    
            except Exception as e:
                print(f"Error applying rule {rule.id}: {e}")
                
        return vulnerabilities

    def _extract_code_snippet(self, content: str, start: int, end: int, context: int = 3) -> str:
        """Extract code snippet with context."""
        lines = content.split('\n')
        start_line = max(0, content[:start].count('\n') - context)
        end_line = min(len(lines), content[:end].count('\n') + context + 1)
        
        snippet_lines = []
        for i in range(start_line, end_line):
            prefix = ">>> " if i == content[:start].count('\n') else "    "
            snippet_lines.append(f"{prefix}{lines[i]}")
            
        return '\n'.join(snippet_lines)

    def _store_rule_match(self, rule: CustomRule, file_path: Path, line_number: int, match_text: str, confidence: float):
        """Store a rule match in the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO rule_matches 
                    (rule_id, file_path, line_number, match_text, confidence, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    rule.id, str(file_path), line_number, match_text, confidence,
                    datetime.now().isoformat()
                ))
                conn.commit()
        except Exception as e:
            print(f"Warning: Could not store rule match: {e}")

    def export_rules(self, output_path: Path, format: str = 'json') -> bool:
        """Export custom rules to file."""
        try:
            rules_data = [asdict(rule) for rule in self.rules.values()]
            
            if format.lower() == 'json':
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(rules_data, f, indent=2)
            elif format.lower() == 'yaml':
                with open(output_path, 'w', encoding='utf-8') as f:
                    yaml.dump(rules_data, f, default_flow_style=False, indent=2)
            else:
                print(f"Unsupported format: {format}")
                return False
                
            return True
            
        except Exception as e:
            print(f"Error exporting rules: {e}")
            return False

    def import_rules(self, input_path: Path, format: str = 'json') -> bool:
        """Import custom rules from file."""
        try:
            if format.lower() == 'json':
                with open(input_path, 'r', encoding='utf-8') as f:
                    rules_data = json.load(f)
            elif format.lower() == 'yaml':
                with open(input_path, 'r', encoding='utf-8') as f:
                    rules_data = yaml.safe_load(f)
            else:
                print(f"Unsupported format: {format}")
                return False
                
            imported_count = 0
            for rule_data in rules_data:
                # Generate unique ID if not present
                if 'id' not in rule_data:
                    rule_data['id'] = f"imported_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{imported_count}"
                    
                # Create rule object
                rule = CustomRule(**rule_data)
                
                # Save rule
                if self.create_rule(rule):
                    imported_count += 1
                    
            print(f"Imported {imported_count} rules successfully")
            return True
            
        except Exception as e:
            print(f"Error importing rules: {e}")
            return False

    def get_rule_statistics(self) -> Dict[str, Any]:
        """Get statistics about custom rules."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Rule counts
                total_rules = len(self.rules)
                enabled_rules = len(self.get_enabled_rules())
                
                # Match counts
                cursor = conn.execute('SELECT COUNT(*) FROM rule_matches')
                total_matches = cursor.fetchone()[0]
                
                # Rule type distribution
                type_counts = {}
                for rule in self.rules.values():
                    type_counts[rule.vuln_type] = type_counts.get(rule.vuln_type, 0) + 1
                    
                # Severity distribution
                severity_counts = {}
                for rule in self.rules.values():
                    severity_counts[rule.severity] = severity_counts.get(rule.severity, 0) + 1
                    
                return {
                    'total_rules': total_rules,
                    'enabled_rules': enabled_rules,
                    'disabled_rules': total_rules - enabled_rules,
                    'total_matches': total_matches,
                    'type_distribution': type_counts,
                    'severity_distribution': severity_counts,
                    'rules_by_author': self._get_rules_by_author()
                }
                
        except Exception as e:
            print(f"Error getting rule statistics: {e}")
            return {}

    def _get_rules_by_author(self) -> Dict[str, int]:
        """Get count of rules by author."""
        author_counts = {}
        for rule in self.rules.values():
            author_counts[rule.author] = author_counts.get(rule.author, 0) + 1
        return author_counts

    def create_rule_template(self, vuln_type: str = None) -> CustomRule:
        """Create a template for a new custom rule."""
        template = CustomRule(
            id=f"rule_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            name="New Custom Rule",
            description="Description of the vulnerability this rule detects",
            vuln_type=vuln_type or "custom",
            severity="medium",
            patterns=["example_pattern"],
            file_extensions=[".js", ".jsx", ".ts", ".tsx"],
            frameworks=["react", "nextjs"],
            fix_guide="How to fix this vulnerability",
            reference="Reference link or documentation",
            tags=["custom", "security"]
        )
        
        return template

    def validate_pattern(self, pattern: str) -> bool:
        """Validate a regex pattern."""
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False

    def test_pattern(self, pattern: str, test_text: str) -> List[Dict[str, Any]]:
        """Test a regex pattern against test text."""
        try:
            matches = list(re.finditer(pattern, test_text, re.IGNORECASE | re.MULTILINE))
            return [
                {
                    'start': match.start(),
                    'end': match.end(),
                    'text': match.group(),
                    'groups': match.groups()
                }
                for match in matches
            ]
        except re.error as e:
            return [{'error': str(e)}]
