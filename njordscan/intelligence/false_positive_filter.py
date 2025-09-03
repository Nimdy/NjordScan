#!/usr/bin/env python3
"""
🧠 False Positive Filtering System
Intelligent filtering to reduce false positives and improve scan accuracy.
"""

import re
import json
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import sqlite3
from datetime import datetime, timedelta

from ..vulnerability import Vulnerability
from ..vulnerability_types import normalize_vulnerability_type, get_vulnerability_type_info

@dataclass
class FalsePositiveConfig:
    """Configuration for false positive filtering."""
    enable_ai_filtering: bool = True
    enable_pattern_filtering: bool = True
    enable_context_analysis: bool = True
    enable_historical_learning: bool = True
    confidence_threshold: float = 0.7
    max_false_positive_rate: float = 0.1

@dataclass
class FilterResult:
    """Result of false positive filtering."""
    is_false_positive: bool
    confidence: float
    reason: str
    evidence: Dict[str, Any]

class FalsePositiveFilter:
    """Advanced false positive filtering system."""
    
    def __init__(self, config: FalsePositiveConfig = None):
        self.config = config or FalsePositiveConfig()
        self.db_path = Path.home() / '.njordscan' / 'false_positives.db'
        self.db_path.parent.mkdir(exist_ok=True)
        self._init_database()
        
        # Common false positive patterns using standardized vulnerability types
        self.false_positive_patterns = {
            'xss_reflected': [
                # Safe HTML usage
                r'innerHTML\s*=\s*["\']\s*$',  # Empty innerHTML
                r'textContent\s*=',  # Safe text content
                r'innerText\s*=',  # Safe inner text
                r'createTextNode\s*\(',  # Safe text creation
                r'DOMPurify\.sanitize\s*\(',  # HTML sanitization
                r'escapeHtml\s*\(',  # HTML escaping
                r'htmlEscape\s*\(',  # HTML escaping
            ],
            'xss_stored': [
                # Safe HTML usage
                r'innerHTML\s*=\s*["\']\s*$',  # Empty innerHTML
                r'textContent\s*=',  # Safe text content
                r'innerText\s*=',  # Safe inner text
                r'createTextNode\s*\(',  # Safe text creation
                r'DOMPurify\.sanitize\s*\(',  # HTML sanitization
                r'escapeHtml\s*\(',  # HTML escaping
                r'htmlEscape\s*\(',  # HTML escaping
            ],
            'xss_dom': [
                # Safe HTML usage
                r'innerHTML\s*=\s*["\']\s*$',  # Empty innerHTML
                r'textContent\s*=',  # Safe text content
                r'innerText\s*=',  # Safe inner text
                r'createTextNode\s*\(',  # Safe text creation
                r'DOMPurify\.sanitize\s*\(',  # HTML sanitization
                r'escapeHtml\s*\(',  # HTML escaping
                r'htmlEscape\s*\(',  # HTML escaping
            ],
            'sql_injection': [
                # Valid SQL queries
                r'SELECT\s+.*\s+FROM\s+\w+',
                r'INSERT\s+INTO\s+\w+',
                r'UPDATE\s+\w+\s+SET',
                r'DELETE\s+FROM\s+\w+',
                # Parameterized queries
                r'\?\s*\)',  # Placeholder parameters
                r':\w+\s*\)',  # Named parameters
                r'\$\d+\s*\)',  # Positional parameters
            ],
            'command_injection': [
                # Safe command execution
                r'subprocess\.run\s*\([^)]*,\s*shell=False',
                r'os\.system\s*\([^)]*\)',  # Limited scope
                r'commands\.getoutput\s*\([^)]*\)',  # Limited scope
            ],
            'path_traversal': [
                # Safe path handling
                r'os\.path\.normpath\s*\(',
                r'os\.path\.abspath\s*\(',
                r'pathlib\.Path\.resolve\s*\(',
                r'path\.normalize\s*\(',
            ]
        }
        
        # Context indicators for false positives using standardized vulnerability types
        self.context_indicators = {
            'xss_reflected': {
                'safe_contexts': [
                    'test', 'example', 'demo', 'sandbox',
                    'development', 'staging', 'localhost'
                ],
                'safe_functions': [
                    'escape', 'sanitize', 'validate', 'clean',
                    'filter', 'strip', 'encode'
                ]
            },
            'xss_stored': {
                'safe_contexts': [
                    'test', 'example', 'demo', 'sandbox',
                    'development', 'staging', 'localhost'
                ],
                'safe_functions': [
                    'escape', 'sanitize', 'validate', 'clean',
                    'filter', 'strip', 'encode'
                ]
            },
            'xss_dom': {
                'safe_contexts': [
                    'test', 'example', 'demo', 'sandbox',
                    'development', 'staging', 'localhost'
                ],
                'safe_functions': [
                    'escape', 'sanitize', 'validate', 'clean',
                    'filter', 'strip', 'encode'
                ]
            },
            'sql_injection': {
                'safe_contexts': [
                    'migration', 'seed', 'fixture', 'test',
                    'development', 'staging'
                ],
                'safe_functions': [
                    'execute', 'query', 'prepare', 'bind',
                    'parameterize', 'escape'
                ]
            }
        }

    def _init_database(self):
        """Initialize the false positive database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS false_positives (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        vulnerability_hash TEXT UNIQUE,
                        vuln_type TEXT,
                        file_path TEXT,
                        line_number INTEGER,
                        confidence REAL,
                        reason TEXT,
                        evidence TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS filter_stats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        date TEXT,
                        total_vulnerabilities INTEGER,
                        false_positives INTEGER,
                        true_positives INTEGER,
                        accuracy REAL
                    )
                ''')
                
                conn.commit()
        except Exception as e:
            print(f"Warning: Could not initialize false positive database: {e}")

    def filter_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> Tuple[List[Vulnerability], List[Vulnerability]]:
        """
        Filter vulnerabilities to separate true positives from false positives.
        
        Returns:
            Tuple of (true_positives, false_positives)
        """
        if not self.config.enable_ai_filtering:
            return vulnerabilities, []
            
        true_positives = []
        false_positives = []
        
        for vuln in vulnerabilities:
            filter_result = self._analyze_vulnerability(vuln)
            
            if filter_result.is_false_positive:
                false_positives.append(vuln)
                self._store_false_positive(vuln, filter_result)
            else:
                true_positives.append(vuln)
                
        # Update statistics
        self._update_statistics(len(vulnerabilities), len(false_positives))
        
        return true_positives, false_positives

    def _analyze_vulnerability(self, vuln: Vulnerability) -> FilterResult:
        """Analyze a single vulnerability for false positive indicators."""
        confidence = 0.0
        reasons = []
        evidence = {}
        
        # Pattern-based filtering
        if self.config.enable_pattern_filtering:
            pattern_score = self._check_pattern_indicators(vuln)
            confidence += pattern_score * 0.4
            if pattern_score > 0.5:
                reasons.append("Pattern indicates false positive")
            evidence['pattern_score'] = pattern_score
        
        # Context analysis
        if self.config.enable_context_analysis:
            context_score = self._analyze_context(vuln)
            confidence += context_score * 0.3
            if context_score > 0.5:
                reasons.append("Context suggests false positive")
            evidence['context_score'] = context_score
        
        # Historical learning
        if self.config.enable_historical_learning:
            historical_score = self._check_historical_data(vuln)
            confidence += historical_score * 0.3
            if historical_score > 0.5:
                reasons.append("Historical data indicates false positive")
            evidence['historical_score'] = historical_score
        
        # Determine if it's a false positive
        is_false_positive = confidence >= self.config.confidence_threshold
        
        return FilterResult(
            is_false_positive=is_false_positive,
            confidence=confidence,
            reason="; ".join(reasons) if reasons else "No false positive indicators found",
            evidence=evidence
        )

    def _check_pattern_indicators(self, vuln: Vulnerability) -> float:
        """Check for false positive patterns in the vulnerability."""
        score = 0.0
        
        # Normalize vulnerability type for pattern matching
        normalized_type = normalize_vulnerability_type(vuln.vuln_type)
        vuln_type_key = normalized_type.value if normalized_type else vuln.vuln_type
        
        if vuln_type_key in self.false_positive_patterns:
            patterns = self.false_positive_patterns[vuln_type_key]
            
            # Check code snippet for safe patterns
            if vuln.code_snippet:
                for pattern in patterns:
                    if re.search(pattern, vuln.code_snippet, re.IGNORECASE):
                        score += 0.3
                        
            # Check description for safe indicators
            if vuln.description:
                safe_indicators = ['test', 'example', 'demo', 'safe', 'sanitized']
                for indicator in safe_indicators:
                    if indicator.lower() in vuln.description.lower():
                        score += 0.2
                        
            # Check file path for safe contexts
            if vuln.file_path:
                safe_paths = ['test', 'example', 'demo', 'mock', 'fixture']
                for safe_path in safe_paths:
                    if safe_path in vuln.file_path.lower():
                        score += 0.2
                        
        return min(score, 1.0)

    def _analyze_context(self, vuln: Vulnerability) -> float:
        """Analyze the context around the vulnerability."""
        score = 0.0
        
        # Normalize vulnerability type for context analysis
        normalized_type = normalize_vulnerability_type(vuln.vuln_type)
        vuln_type_key = normalized_type.value if normalized_type else vuln.vuln_type
        
        if vuln_type_key in self.context_indicators:
            indicators = self.context_indicators[vuln_type_key]
            
            # Check file path context
            if vuln.file_path:
                for safe_context in indicators['safe_contexts']:
                    if safe_context in vuln.file_path.lower():
                        score += 0.3
                        
            # Check code snippet for safe functions
            if vuln.code_snippet:
                for safe_function in indicators['safe_functions']:
                    if safe_function in vuln.code_snippet.lower():
                        score += 0.2
                        
            # Check surrounding code context
            if vuln.code_snippet:
                # Look for safety indicators in surrounding code
                safety_indicators = [
                    'try', 'catch', 'finally', 'if', 'else',
                    'validate', 'check', 'assert', 'require'
                ]
                for indicator in safety_indicators:
                    if indicator in vuln.code_snippet.lower():
                        score += 0.1
                        
        return min(score, 1.0)

    def _check_historical_data(self, vuln: Vulnerability) -> float:
        """Check historical data for similar false positives."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Create a hash of the vulnerability for comparison
                vuln_hash = self._create_vulnerability_hash(vuln)
                
                # Check if this exact vulnerability was marked as false positive
                cursor = conn.execute('''
                    SELECT confidence, reason FROM false_positives 
                    WHERE vulnerability_hash = ?
                ''', (vuln_hash,))
                
                result = cursor.fetchone()
                if result:
                    return result[0]  # Return historical confidence
                    
                # Check for similar vulnerabilities
                similar_vulns = conn.execute('''
                    SELECT confidence FROM false_positives 
                    WHERE vuln_type = ? AND file_path LIKE ?
                ''', (vuln.vuln_type, f"%{Path(vuln.file_path).name}%"))
                
                similar_results = similar_vulns.fetchall()
                if similar_results:
                    avg_confidence = sum(r[0] for r in similar_results) / len(similar_results)
                    return avg_confidence * 0.8  # Slightly reduce confidence for similar cases
                    
        except Exception as e:
            print(f"Warning: Could not check historical data: {e}")
            
        return 0.0

    def _create_vulnerability_hash(self, vuln: Vulnerability) -> str:
        """Create a hash for the vulnerability for comparison."""
        # Create a unique identifier based on key characteristics
        identifier = f"{vuln.vuln_type}:{vuln.file_path}:{vuln.line_number}:{hash(vuln.code_snippet or '')}"
        return hashlib.md5(identifier.encode()).hexdigest()

    def _store_false_positive(self, vuln: Vulnerability, filter_result: FilterResult):
        """Store false positive information in the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                vuln_hash = self._create_vulnerability_hash(vuln)
                
                conn.execute('''
                    INSERT OR REPLACE INTO false_positives 
                    (vulnerability_hash, vuln_type, file_path, line_number, 
                     confidence, reason, evidence, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    vuln_hash,
                    vuln.vuln_type,
                    vuln.file_path,
                    vuln.line_number,
                    filter_result.confidence,
                    filter_result.reason,
                    json.dumps(filter_result.evidence),
                    datetime.now().isoformat()
                ))
                
                conn.commit()
        except Exception as e:
            print(f"Warning: Could not store false positive: {e}")

    def _update_statistics(self, total_vulns: int, false_positives: int):
        """Update filtering statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                today = datetime.now().date().isoformat()
                
                # Check if stats exist for today
                cursor = conn.execute('SELECT id FROM filter_stats WHERE date = ?', (today,))
                existing = cursor.fetchone()
                
                if existing:
                    # Update existing stats
                    conn.execute('''
                        UPDATE filter_stats 
                        SET total_vulnerabilities = total_vulnerabilities + ?,
                            false_positives = false_positives + ?,
                            true_positives = true_positives + ?,
                            accuracy = (true_positives * 1.0) / (total_vulnerabilities * 1.0)
                        WHERE date = ?
                    ''', (total_vulns, false_positives, total_vulns - false_positives, today))
                else:
                    # Insert new stats
                    conn.execute('''
                        INSERT INTO filter_stats 
                        (date, total_vulnerabilities, false_positives, true_positives, accuracy)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (today, total_vulns, false_positives, total_vulns - false_positives, 
                          (total_vulns - false_positives) / total_vulns if total_vulns > 0 else 0))
                          
                conn.commit()
        except Exception as e:
            print(f"Warning: Could not update statistics: {e}")

    def get_filtering_statistics(self, days: int = 30) -> Dict[str, Any]:
        """Get filtering statistics for the specified number of days."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cutoff_date = (datetime.now() - timedelta(days=days)).date().isoformat()
                
                cursor = conn.execute('''
                    SELECT 
                        SUM(total_vulnerabilities) as total,
                        SUM(false_positives) as false_pos,
                        SUM(true_positives) as true_pos,
                        AVG(accuracy) as avg_accuracy
                    FROM filter_stats 
                    WHERE date >= ?
                ''', (cutoff_date,))
                
                result = cursor.fetchone()
                
                if result and result[0]:
                    total, false_pos, true_pos, avg_accuracy = result
                    return {
                        'total_vulnerabilities': total,
                        'false_positives': false_pos,
                        'true_positives': true_pos,
                        'false_positive_rate': false_pos / total if total > 0 else 0,
                        'accuracy': avg_accuracy or 0,
                        'period_days': days
                    }
                    
        except Exception as e:
            print(f"Warning: Could not get filtering statistics: {e}")
            
        return {
            'total_vulnerabilities': 0,
            'false_positives': 0,
            'true_positives': 0,
            'false_positive_rate': 0,
            'accuracy': 0,
            'period_days': days
        }

    def train_on_feedback(self, vuln: Vulnerability, is_false_positive: bool, confidence: float = 1.0):
        """Train the filter based on user feedback."""
        if is_false_positive:
            # Store as false positive
            filter_result = FilterResult(
                is_false_positive=True,
                confidence=confidence,
                reason="User feedback - marked as false positive",
                evidence={'user_feedback': True, 'confidence': confidence}
            )
            self._store_false_positive(vuln, filter_result)
        else:
            # Remove from false positives if it was there
            try:
                with sqlite3.connect(self.db_path) as conn:
                    vuln_hash = self._create_vulnerability_hash(vuln)
                    conn.execute('DELETE FROM false_positives WHERE vulnerability_hash = ?', (vuln_hash,))
                    conn.commit()
            except Exception as e:
                print(f"Warning: Could not remove false positive: {e}")

    def export_false_positives(self, output_path: Path) -> bool:
        """Export false positive data for analysis."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT vuln_type, file_path, line_number, confidence, reason, evidence, created_at
                    FROM false_positives
                    ORDER BY created_at DESC
                ''')
                
                data = []
                for row in cursor.fetchall():
                    data.append({
                        'vuln_type': row[0],
                        'file_path': row[1],
                        'line_number': row[2],
                        'confidence': row[3],
                        'reason': row[4],
                        'evidence': json.loads(row[5]) if row[5] else {},
                        'created_at': row[6]
                    })
                
                with open(output_path, 'w') as f:
                    json.dump(data, f, indent=2)
                    
                return True
                
        except Exception as e:
            print(f"Error exporting false positives: {e}")
            return False

    def import_false_positives(self, input_path: Path) -> bool:
        """Import false positive data from external source."""
        try:
            with open(input_path, 'r') as f:
                data = json.load(f)
                
            with sqlite3.connect(self.db_path) as conn:
                for item in data:
                    # Create a mock vulnerability for hashing
                    mock_vuln = Vulnerability(
                        title="Imported",
                        description=item.get('reason', ''),
                        severity='low',
                        vuln_type=item.get('vuln_type', ''),
                        file_path=item.get('file_path', ''),
                        line_number=item.get('line_number', 0)
                    )
                    
                    vuln_hash = self._create_vulnerability_hash(mock_vuln)
                    
                    conn.execute('''
                        INSERT OR REPLACE INTO false_positives 
                        (vulnerability_hash, vuln_type, file_path, line_number, 
                         confidence, reason, evidence, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        vuln_hash,
                        item.get('vuln_type', ''),
                        item.get('file_path', ''),
                        item.get('line_number', 0),
                        item.get('confidence', 0.5),
                        item.get('reason', ''),
                        json.dumps(item.get('evidence', {})),
                        item.get('created_at', datetime.now().isoformat()),
                        datetime.now().isoformat()
                    ))
                    
                conn.commit()
                return True
                
        except Exception as e:
            print(f"Error importing false positives: {e}")
            return False
