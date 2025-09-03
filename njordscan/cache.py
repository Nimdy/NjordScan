"""
🛡️ Advanced Cache Management for NjordScan v1.0.0

Enhanced caching system compatible with performance orchestrator
and intelligent cache strategies.
"""

import sqlite3
import json
import hashlib
import time
import os
from pathlib import Path
from typing import Dict, List, Any, Optional

class CacheManager:
    """Advanced caching system with file change detection."""
    
    def __init__(self, enabled: bool = True, cache_dir: str = None):
        self.enabled = enabled
        if not self.enabled:
            return
        
        # Setup cache directory
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path.home() / '.njordscan' / 'cache'
        
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / 'scan_cache.db'
        
        # Initialize database
        self._init_database()
    
    def _init_database(self):
        """Initialize the cache database with enhanced schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS scan_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cache_key TEXT UNIQUE NOT NULL,
                    target TEXT NOT NULL,
                    framework TEXT NOT NULL,
                    scan_mode TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    config_hash TEXT NOT NULL,
                    results TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    access_count INTEGER DEFAULT 0,
                    last_accessed REAL NOT NULL
                )
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_cache_key 
                ON scan_cache(cache_key)
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_expires_at 
                ON scan_cache(expires_at)
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_target_framework 
                ON scan_cache(target, framework)
            ''')
    
    def _generate_file_hash(self, target: str) -> str:
        """Generate hash of all relevant files in target directory."""
        if target.startswith(('http://', 'https://')):
            return "url_target"
        
        target_path = Path(target)
        if not target_path.exists():
            return "missing_target"
        
        file_hashes = []
        
        # Get hash of relevant files
        for file_path in target_path.rglob("*"):
            if file_path.is_file() and self._is_relevant_file(file_path):
                try:
                    stat = file_path.stat()
                    file_info = f"{file_path}:{stat.st_mtime}:{stat.st_size}"
                    file_hashes.append(file_info)
                except (OSError, IOError):
                    continue
        
        # Sort for consistent hashing
        file_hashes.sort()
        combined = "|".join(file_hashes)
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def list_recent_scans(self) -> List[Dict[str, Any]]:
        """List recent scan results from cache."""
        if not self.enabled:
            return []
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Get recent scans ordered by timestamp
                cursor = conn.execute('''
                    SELECT target, framework, scan_mode, timestamp, access_count
                    FROM scan_cache 
                    ORDER BY timestamp DESC 
                    LIMIT 20
                ''')
                
                recent_scans = []
                for row in cursor.fetchall():
                    recent_scans.append({
                        'target': row[0],
                        'framework': row[1],
                        'scan_mode': row[2],
                        'date': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(row[3])),
                        'total_issues': 0  # This would need to be calculated from results
                    })
                
                return recent_scans
        except Exception as e:
            return []
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics and status."""
        if not self.enabled:
            return {'status': 'Disabled'}
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Get total cache entries
                total_entries = conn.execute('SELECT COUNT(*) FROM scan_cache').fetchone()[0]
                
                # Get expired entries
                current_time = time.time()
                expired_entries = conn.execute(
                    'SELECT COUNT(*) FROM scan_cache WHERE expires_at < ?', 
                    (current_time,)
                ).fetchone()[0]
                
                # Get cache size
                cache_size = self.db_path.stat().st_size if self.db_path.exists() else 0
                
                # Get oldest and newest entries
                oldest = conn.execute('SELECT MIN(timestamp) FROM scan_cache').fetchone()[0]
                newest = conn.execute('SELECT MAX(timestamp) FROM scan_cache').fetchone()[0]
                
                return {
                    'status': 'Active',
                    'total_entries': total_entries,
                    'expired_entries': expired_entries,
                    'cache_size_bytes': cache_size,
                    'oldest_entry': oldest,
                    'newest_entry': newest,
                    'cache_directory': str(self.cache_dir)
                }
        except Exception as e:
            return {'status': f'Error: {str(e)}'}
    
    def _is_relevant_file(self, file_path: Path) -> bool:
        """Check if file is relevant for caching."""
        relevant_extensions = {
            '.js', '.jsx', '.ts', '.tsx', '.json', '.yaml', '.yml',
            '.env', '.config', '.py', '.html', '.css', '.scss'
        }
        
        skip_dirs = {'node_modules', '.git', '.next', 'dist', 'build', '__pycache__'}
        
        # Check if file is in a skip directory
        for part in file_path.parts:
            if part in skip_dirs:
                return False
        
        return file_path.suffix in relevant_extensions
    
    def get_cached_results(self, cache_key: str) -> Optional[List[Dict[str, Any]]]:
        """Get cached scan results if available and valid."""
        if not self.enabled:
            return None
        
        current_time = time.time()
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT results, file_hash, timestamp FROM scan_cache 
                    WHERE cache_key = ? AND expires_at > ?
                    ORDER BY timestamp DESC LIMIT 1
                ''', (cache_key, current_time))
                
                row = cursor.fetchone()
                if row:
                    results_json, cached_file_hash, timestamp = row
                    
                    # Update access statistics
                    conn.execute('''
                        UPDATE scan_cache 
                        SET access_count = access_count + 1, last_accessed = ?
                        WHERE cache_key = ?
                    ''', (current_time, cache_key))
                    
                    return json.loads(results_json)
        
        except (sqlite3.Error, json.JSONDecodeError) as e:
            print(f"Cache read error: {e}")
        
        return None
    
    def cache_results(self, cache_key: str, results: List[Dict[str, Any]], 
                     target: str = "", framework: str = "", scan_mode: str = "",
                     config_hash: str = "", cache_duration: int = 3600):
        """Cache scan results with metadata."""
        if not self.enabled:
            return
        
        file_hash = self._generate_file_hash(target)
        current_time = time.time()
        expires_at = current_time + cache_duration
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO scan_cache 
                    (cache_key, target, framework, scan_mode, file_hash, config_hash, 
                     results, timestamp, expires_at, last_accessed)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cache_key, target, framework, scan_mode, file_hash, config_hash,
                    json.dumps(results), current_time, expires_at, current_time
                ))
        
        except (sqlite3.Error, json.JSONDecodeError) as e:
            print(f"Cache write error: {e}")
    
    def should_invalidate(self, cache_key: str, target: str) -> bool:
        """Check if cache should be invalidated based on file changes."""
        if not self.enabled:
            return True
        
        current_file_hash = self._generate_file_hash(target)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT file_hash FROM scan_cache WHERE cache_key = ?
                ''', (cache_key,))
                
                row = cursor.fetchone()
                if row:
                    cached_file_hash = row[0]
                    return current_file_hash != cached_file_hash
        
        except sqlite3.Error:
            pass
        
        return True
    
    def clear_expired_cache(self):
        """Clear expired cache entries."""
        if not self.enabled:
            return
        
        current_time = time.time()
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    DELETE FROM scan_cache WHERE expires_at < ?
                ''', (current_time,))
                
                return cursor.rowcount
        
        except sqlite3.Error as e:
            print(f"Cache cleanup error: {e}")
            return 0
    
    def clear_all_cache(self):
        """Clear all cache entries."""
        if not self.enabled:
            return
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('DELETE FROM scan_cache')
        
        except sqlite3.Error as e:
            print(f"Cache clear error: {e}")
    
    def clear_cache(self):
        """Clear all cache entries (alias for clear_all_cache)."""
        self.clear_all_cache()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics."""
        if not self.enabled:
            return {'enabled': False}
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Basic stats
                cursor = conn.execute('SELECT COUNT(*) FROM scan_cache')
                total_entries = cursor.fetchone()[0]
                
                cursor = conn.execute('SELECT COUNT(*) FROM scan_cache WHERE expires_at > ?', (time.time(),))
                valid_entries = cursor.fetchone()[0]
                
                cursor = conn.execute('SELECT MIN(timestamp), MAX(timestamp) FROM scan_cache')
                min_time, max_time = cursor.fetchone()
                
                # Usage stats
                cursor = conn.execute('SELECT SUM(access_count) FROM scan_cache')
                total_hits = cursor.fetchone()[0] or 0
                
                cursor = conn.execute('SELECT AVG(access_count) FROM scan_cache')
                avg_hits = cursor.fetchone()[0] or 0
                
                # Size stats
                cache_size = self.db_path.stat().st_size if self.db_path.exists() else 0
                
                return {
                    'enabled': True,
                    'total_entries': total_entries,
                    'valid_entries': valid_entries,
                    'expired_entries': total_entries - valid_entries,
                    'oldest_entry': min_time,
                    'newest_entry': max_time,
                    'total_cache_hits': total_hits,
                    'avg_hits_per_entry': round(avg_hits, 2),
                    'cache_size_bytes': cache_size,
                    'cache_file': str(self.db_path)
                }
        
        except sqlite3.Error:
            return {
                'enabled': True,
                'error': 'Unable to read cache statistics'
            }