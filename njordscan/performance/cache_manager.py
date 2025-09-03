"""
Advanced Cache Manager

High-performance caching system with:
- Multi-level caching (memory, disk, distributed)
- Intelligent cache eviction policies
- Cache warming and preloading
- Compression and serialization optimization
- Cache analytics and monitoring
- Distributed cache coordination
"""

import asyncio
import time
import hashlib
import json
import pickle
import gzip
import lz4.frame
import sqlite3
import threading
from typing import Dict, List, Any, Optional, Union, Tuple, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging
from concurrent.futures import ThreadPoolExecutor
import weakref
import psutil
from collections import OrderedDict, defaultdict
import heapq

logger = logging.getLogger(__name__)

class CacheLevel(Enum):
    """Cache storage levels."""
    MEMORY = "memory"
    DISK = "disk"
    DISTRIBUTED = "distributed"

class EvictionPolicy(Enum):
    """Cache eviction policies."""
    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    FIFO = "fifo"  # First In First Out
    TTL = "ttl"  # Time To Live
    ADAPTIVE = "adaptive"  # Machine learning based
    SIZE_BASED = "size_based"  # Based on entry size

class CompressionType(Enum):
    """Compression algorithms."""
    NONE = "none"
    GZIP = "gzip"
    LZ4 = "lz4"
    ADAPTIVE = "adaptive"  # Choose best based on data

class SerializationType(Enum):
    """Serialization formats."""
    PICKLE = "pickle"
    JSON = "json"
    MSGPACK = "msgpack"
    ADAPTIVE = "adaptive"  # Choose best based on data type

@dataclass
class CacheEntry:
    """Cache entry with metadata."""
    key: str
    value: Any
    created_at: float
    last_accessed: float
    access_count: int = 0
    size_bytes: int = 0
    ttl: Optional[float] = None
    compression: CompressionType = CompressionType.NONE
    serialization: SerializationType = SerializationType.PICKLE
    tags: Set[str] = field(default_factory=set)
    priority: int = 0
    checksum: str = ""
    
    def __post_init__(self):
        if not self.checksum and self.value is not None:
            self.checksum = self._calculate_checksum()
    
    def _calculate_checksum(self) -> str:
        """Calculate checksum for cache validation."""
        try:
            if isinstance(self.value, (str, bytes)):
                data = self.value.encode() if isinstance(self.value, str) else self.value
            else:
                data = str(self.value).encode()
            return hashlib.md5(data).hexdigest()
        except Exception:
            return ""
    
    @property
    def is_expired(self) -> bool:
        """Check if entry is expired."""
        if self.ttl is None:
            return False
        return time.time() - self.created_at > self.ttl
    
    @property
    def age_seconds(self) -> float:
        """Get entry age in seconds."""
        return time.time() - self.created_at
    
    @property
    def last_access_age(self) -> float:
        """Get time since last access in seconds."""
        return time.time() - self.last_accessed
    
    def touch(self):
        """Update last accessed time and increment access count."""
        self.last_accessed = time.time()
        self.access_count += 1

@dataclass
class CacheStats:
    """Cache statistics."""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    entries: int = 0
    total_size_bytes: int = 0
    memory_usage_bytes: int = 0
    disk_usage_bytes: int = 0
    
    # Performance metrics
    average_hit_time_ms: float = 0.0
    average_miss_time_ms: float = 0.0
    average_write_time_ms: float = 0.0
    
    # Advanced metrics
    hit_rate_by_level: Dict[CacheLevel, float] = field(default_factory=dict)
    compression_ratio: float = 1.0
    cache_efficiency: float = 0.0
    
    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0
    
    @property
    def miss_rate(self) -> float:
        """Calculate cache miss rate."""
        return 1.0 - self.hit_rate

@dataclass
class CacheConfig:
    """Cache configuration."""
    
    # Memory cache settings
    memory_max_size_mb: int = 512
    memory_max_entries: int = 10000
    memory_eviction_policy: EvictionPolicy = EvictionPolicy.LRU
    
    # Disk cache settings
    disk_max_size_mb: int = 2048
    disk_max_entries: int = 100000
    disk_eviction_policy: EvictionPolicy = EvictionPolicy.LFU
    disk_cache_dir: str = ".njordscan_cache"
    
    # Compression settings
    compression_type: CompressionType = CompressionType.ADAPTIVE
    compression_threshold_bytes: int = 1024
    compression_level: int = 6
    
    # Serialization settings
    serialization_type: SerializationType = SerializationType.ADAPTIVE
    
    # TTL settings
    default_ttl_seconds: Optional[float] = None
    max_ttl_seconds: float = 86400 * 7  # 7 days
    
    # Performance settings
    enable_async_writes: bool = True
    write_batch_size: int = 100
    write_batch_timeout_ms: int = 1000
    
    # Cache warming
    enable_cache_warming: bool = True
    warming_batch_size: int = 50
    
    # Analytics
    enable_analytics: bool = True
    analytics_sample_rate: float = 0.1
    
    # Cleanup settings
    cleanup_interval_seconds: int = 300
    cleanup_threshold_percent: float = 0.9

class MemoryCache:
    """High-performance in-memory cache."""
    
    def __init__(self, config: CacheConfig):
        self.config = config
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.lock = threading.RLock()
        
        # LFU tracking
        self.frequencies: Dict[str, int] = defaultdict(int)
        self.freq_to_keys: Dict[int, Set[str]] = defaultdict(set)
        self.min_frequency = 0
        
        # Size tracking
        self.current_size_bytes = 0
        self.current_entries = 0
        
        # Statistics
        self.stats = CacheStats()
    
    def get(self, key: str) -> Optional[CacheEntry]:
        """Get entry from memory cache."""
        start_time = time.time()
        
        try:
            with self.lock:
                if key not in self.cache:
                    self.stats.misses += 1
                    self.stats.average_miss_time_ms = self._update_average_time(
                        self.stats.average_miss_time_ms, start_time, self.stats.misses
                    )
                    return None
                
                entry = self.cache[key]
                
                # Check if expired
                if entry.is_expired:
                    self._remove_entry(key)
                    self.stats.misses += 1
                    return None
                
                # Update access tracking
                entry.touch()
                self._update_access_tracking(key)
                
                # Move to end for LRU
                if self.config.memory_eviction_policy == EvictionPolicy.LRU:
                    self.cache.move_to_end(key)
                
                self.stats.hits += 1
                self.stats.average_hit_time_ms = self._update_average_time(
                    self.stats.average_hit_time_ms, start_time, self.stats.hits
                )
                
                return entry
                
        except Exception as e:
            logger.error(f"Memory cache get error: {str(e)}")
            return None
    
    def put(self, key: str, entry: CacheEntry) -> bool:
        """Put entry into memory cache."""
        start_time = time.time()
        
        try:
            with self.lock:
                # Check if we need to evict entries
                while self._should_evict():
                    if not self._evict_one():
                        break
                
                # Remove existing entry if present
                if key in self.cache:
                    self._remove_entry(key)
                
                # Add new entry
                self.cache[key] = entry
                self.current_size_bytes += entry.size_bytes
                self.current_entries += 1
                
                # Update tracking
                self._update_access_tracking(key)
                
                # Update statistics
                self.stats.entries = self.current_entries
                self.stats.total_size_bytes = self.current_size_bytes
                self.stats.memory_usage_bytes = self.current_size_bytes
                
                write_time_ms = (time.time() - start_time) * 1000
                self.stats.average_write_time_ms = self._update_average_time(
                    self.stats.average_write_time_ms, start_time, self.current_entries
                )
                
                return True
                
        except Exception as e:
            logger.error(f"Memory cache put error: {str(e)}")
            return False
    
    def remove(self, key: str) -> bool:
        """Remove entry from memory cache."""
        try:
            with self.lock:
                return self._remove_entry(key)
        except Exception as e:
            logger.error(f"Memory cache remove error: {str(e)}")
            return False
    
    def clear(self):
        """Clear all entries from memory cache."""
        try:
            with self.lock:
                self.cache.clear()
                self.frequencies.clear()
                self.freq_to_keys.clear()
                self.min_frequency = 0
                self.current_size_bytes = 0
                self.current_entries = 0
                self.stats = CacheStats()
        except Exception as e:
            logger.error(f"Memory cache clear error: {str(e)}")
    
    def _should_evict(self) -> bool:
        """Check if eviction is needed."""
        return (self.current_entries >= self.config.memory_max_entries or
                self.current_size_bytes >= self.config.memory_max_size_mb * 1024 * 1024)
    
    def _evict_one(self) -> bool:
        """Evict one entry based on policy."""
        if not self.cache:
            return False
        
        try:
            if self.config.memory_eviction_policy == EvictionPolicy.LRU:
                key = next(iter(self.cache))  # First item (oldest)
            elif self.config.memory_eviction_policy == EvictionPolicy.LFU:
                key = self._get_lfu_key()
            elif self.config.memory_eviction_policy == EvictionPolicy.FIFO:
                key = next(iter(self.cache))
            elif self.config.memory_eviction_policy == EvictionPolicy.TTL:
                key = self._get_expired_key()
            else:  # ADAPTIVE
                key = self._get_adaptive_eviction_key()
            
            if key:
                self._remove_entry(key)
                self.stats.evictions += 1
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Memory cache eviction error: {str(e)}")
            return False
    
    def _remove_entry(self, key: str) -> bool:
        """Remove entry and update tracking."""
        if key not in self.cache:
            return False
        
        entry = self.cache[key]
        del self.cache[key]
        
        self.current_size_bytes -= entry.size_bytes
        self.current_entries -= 1
        
        # Update frequency tracking
        if key in self.frequencies:
            freq = self.frequencies[key]
            self.freq_to_keys[freq].discard(key)
            if not self.freq_to_keys[freq] and freq == self.min_frequency:
                self.min_frequency += 1
            del self.frequencies[key]
        
        return True
    
    def _update_access_tracking(self, key: str):
        """Update access frequency tracking for LFU."""
        if self.config.memory_eviction_policy != EvictionPolicy.LFU:
            return
        
        # Remove from old frequency set
        if key in self.frequencies:
            old_freq = self.frequencies[key]
            self.freq_to_keys[old_freq].discard(key)
            if not self.freq_to_keys[old_freq] and old_freq == self.min_frequency:
                self.min_frequency += 1
        else:
            self.min_frequency = 1
        
        # Add to new frequency
        new_freq = self.frequencies[key] + 1
        self.frequencies[key] = new_freq
        self.freq_to_keys[new_freq].add(key)
    
    def _get_lfu_key(self) -> Optional[str]:
        """Get least frequently used key."""
        if not self.freq_to_keys[self.min_frequency]:
            return None
        return next(iter(self.freq_to_keys[self.min_frequency]))
    
    def _get_expired_key(self) -> Optional[str]:
        """Get first expired key."""
        for key, entry in self.cache.items():
            if entry.is_expired:
                return key
        return next(iter(self.cache)) if self.cache else None
    
    def _get_adaptive_eviction_key(self) -> Optional[str]:
        """Get key using adaptive eviction strategy."""
        # Combine multiple factors for intelligent eviction
        best_key = None
        best_score = float('-inf')
        
        for key, entry in self.cache.items():
            # Calculate eviction score based on multiple factors
            score = 0
            
            # Age factor (older = higher score)
            score += entry.age_seconds / 3600  # Hours
            
            # Access frequency factor (less frequent = higher score)
            freq = self.frequencies.get(key, 1)
            score += 1.0 / freq
            
            # Size factor (larger = higher score)
            score += entry.size_bytes / (1024 * 1024)  # MB
            
            # Last access factor (longer ago = higher score)
            score += entry.last_access_age / 3600  # Hours
            
            # Priority factor (lower priority = higher score)
            score += (10 - entry.priority) / 10
            
            if score > best_score:
                best_score = score
                best_key = key
        
        return best_key
    
    def _update_average_time(self, current_avg: float, start_time: float, count: int) -> float:
        """Update running average time."""
        elapsed_ms = (time.time() - start_time) * 1000
        if count == 1:
            return elapsed_ms
        return ((current_avg * (count - 1)) + elapsed_ms) / count

class DiskCache:
    """High-performance disk-based cache using SQLite."""
    
    def __init__(self, config: CacheConfig):
        self.config = config
        self.cache_dir = Path(config.disk_cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        
        self.db_path = self.cache_dir / "cache.db"
        self.connection_pool = []
        self.pool_lock = threading.Lock()
        
        # Statistics
        self.stats = CacheStats()
        
        # Initialize database
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database."""
        try:
            conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache_entries (
                    key TEXT PRIMARY KEY,
                    value BLOB,
                    created_at REAL,
                    last_accessed REAL,
                    access_count INTEGER,
                    size_bytes INTEGER,
                    ttl REAL,
                    compression TEXT,
                    serialization TEXT,
                    tags TEXT,
                    priority INTEGER,
                    checksum TEXT
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_last_accessed ON cache_entries(last_accessed)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_created_at ON cache_entries(created_at)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_access_count ON cache_entries(access_count)
            """)
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to initialize disk cache database: {str(e)}")
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection from pool."""
        with self.pool_lock:
            if self.connection_pool:
                return self.connection_pool.pop()
            else:
                return sqlite3.connect(str(self.db_path), check_same_thread=False)
    
    def _return_connection(self, conn: sqlite3.Connection):
        """Return connection to pool."""
        with self.pool_lock:
            if len(self.connection_pool) < 10:  # Max pool size
                self.connection_pool.append(conn)
            else:
                conn.close()
    
    def get(self, key: str) -> Optional[CacheEntry]:
        """Get entry from disk cache."""
        start_time = time.time()
        conn = None
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT value, created_at, last_accessed, access_count, size_bytes,
                       ttl, compression, serialization, tags, priority, checksum
                FROM cache_entries WHERE key = ?
            """, (key,))
            
            row = cursor.fetchone()
            if not row:
                self.stats.misses += 1
                return None
            
            # Deserialize entry
            entry = self._deserialize_entry(key, row)
            
            # Check if expired
            if entry.is_expired:
                self.remove(key)
                self.stats.misses += 1
                return None
            
            # Update access tracking
            entry.touch()
            cursor.execute("""
                UPDATE cache_entries 
                SET last_accessed = ?, access_count = ?
                WHERE key = ?
            """, (entry.last_accessed, entry.access_count, key))
            conn.commit()
            
            self.stats.hits += 1
            self.stats.average_hit_time_ms = self._update_average_time(
                self.stats.average_hit_time_ms, start_time, self.stats.hits
            )
            
            return entry
            
        except Exception as e:
            logger.error(f"Disk cache get error: {str(e)}")
            self.stats.misses += 1
            return None
        finally:
            if conn:
                self._return_connection(conn)
    
    def put(self, key: str, entry: CacheEntry) -> bool:
        """Put entry into disk cache."""
        start_time = time.time()
        conn = None
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Serialize entry
            serialized_data = self._serialize_entry(entry)
            
            # Insert or replace entry
            cursor.execute("""
                INSERT OR REPLACE INTO cache_entries 
                (key, value, created_at, last_accessed, access_count, size_bytes,
                 ttl, compression, serialization, tags, priority, checksum)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                key, serialized_data, entry.created_at, entry.last_accessed,
                entry.access_count, entry.size_bytes, entry.ttl,
                entry.compression.value, entry.serialization.value,
                ','.join(entry.tags), entry.priority, entry.checksum
            ))
            
            conn.commit()
            
            # Check if eviction is needed
            self._maybe_evict(conn)
            
            self.stats.average_write_time_ms = self._update_average_time(
                self.stats.average_write_time_ms, start_time, self.stats.entries
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Disk cache put error: {str(e)}")
            return False
        finally:
            if conn:
                self._return_connection(conn)
    
    def remove(self, key: str) -> bool:
        """Remove entry from disk cache."""
        conn = None
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM cache_entries WHERE key = ?", (key,))
            conn.commit()
            
            return cursor.rowcount > 0
            
        except Exception as e:
            logger.error(f"Disk cache remove error: {str(e)}")
            return False
        finally:
            if conn:
                self._return_connection(conn)
    
    def clear(self):
        """Clear all entries from disk cache."""
        conn = None
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM cache_entries")
            conn.commit()
            
            self.stats = CacheStats()
            
        except Exception as e:
            logger.error(f"Disk cache clear error: {str(e)}")
        finally:
            if conn:
                self._return_connection(conn)
    
    def _serialize_entry(self, entry: CacheEntry) -> bytes:
        """Serialize cache entry value."""
        try:
            # Choose serialization method
            if entry.serialization == SerializationType.JSON:
                data = json.dumps(entry.value).encode()
            elif entry.serialization == SerializationType.ADAPTIVE:
                # Try JSON first, fall back to pickle
                try:
                    data = json.dumps(entry.value).encode()
                    entry.serialization = SerializationType.JSON
                except (TypeError, ValueError):
                    data = pickle.dumps(entry.value)
                    entry.serialization = SerializationType.PICKLE
            else:  # PICKLE
                data = pickle.dumps(entry.value)
            
            # Apply compression if needed
            if (entry.compression != CompressionType.NONE and 
                len(data) > self.config.compression_threshold_bytes):
                
                if entry.compression == CompressionType.GZIP:
                    data = gzip.compress(data, compresslevel=self.config.compression_level)
                elif entry.compression == CompressionType.LZ4:
                    data = lz4.frame.compress(data, compression_level=self.config.compression_level)
                elif entry.compression == CompressionType.ADAPTIVE:
                    # Choose best compression
                    gzip_data = gzip.compress(data, compresslevel=self.config.compression_level)
                    lz4_data = lz4.frame.compress(data, compression_level=self.config.compression_level)
                    
                    if len(lz4_data) < len(gzip_data):
                        data = lz4_data
                        entry.compression = CompressionType.LZ4
                    else:
                        data = gzip_data
                        entry.compression = CompressionType.GZIP
            
            # Update size
            entry.size_bytes = len(data)
            
            return data
            
        except Exception as e:
            logger.error(f"Entry serialization error: {str(e)}")
            return pickle.dumps(entry.value)
    
    def _deserialize_entry(self, key: str, row: Tuple) -> CacheEntry:
        """Deserialize cache entry from database row."""
        try:
            (value_data, created_at, last_accessed, access_count, size_bytes,
             ttl, compression_str, serialization_str, tags_str, priority, checksum) = row
            
            compression = CompressionType(compression_str)
            serialization = SerializationType(serialization_str)
            
            # Decompress if needed
            if compression == CompressionType.GZIP:
                value_data = gzip.decompress(value_data)
            elif compression == CompressionType.LZ4:
                value_data = lz4.frame.decompress(value_data)
            
            # Deserialize
            if serialization == SerializationType.JSON:
                value = json.loads(value_data.decode())
            else:  # PICKLE
                value = pickle.loads(value_data)
            
            # Parse tags
            tags = set(tags_str.split(',')) if tags_str else set()
            
            return CacheEntry(
                key=key,
                value=value,
                created_at=created_at,
                last_accessed=last_accessed,
                access_count=access_count,
                size_bytes=size_bytes,
                ttl=ttl,
                compression=compression,
                serialization=serialization,
                tags=tags,
                priority=priority,
                checksum=checksum
            )
            
        except Exception as e:
            logger.error(f"Entry deserialization error: {str(e)}")
            # Return dummy entry to prevent crashes
            return CacheEntry(key=key, value=None, created_at=time.time(), last_accessed=time.time())
    
    def _maybe_evict(self, conn: sqlite3.Connection):
        """Check if eviction is needed and perform it."""
        try:
            cursor = conn.cursor()
            
            # Check current size and count
            cursor.execute("SELECT COUNT(*), SUM(size_bytes) FROM cache_entries")
            count, total_size = cursor.fetchone()
            
            if (count >= self.config.disk_max_entries or
                (total_size and total_size >= self.config.disk_max_size_mb * 1024 * 1024)):
                
                # Perform eviction based on policy
                if self.config.disk_eviction_policy == EvictionPolicy.LRU:
                    cursor.execute("""
                        DELETE FROM cache_entries 
                        WHERE key IN (
                            SELECT key FROM cache_entries 
                            ORDER BY last_accessed ASC 
                            LIMIT ?
                        )
                    """, (max(1, count // 10),))  # Remove 10% of entries
                
                elif self.config.disk_eviction_policy == EvictionPolicy.LFU:
                    cursor.execute("""
                        DELETE FROM cache_entries 
                        WHERE key IN (
                            SELECT key FROM cache_entries 
                            ORDER BY access_count ASC 
                            LIMIT ?
                        )
                    """, (max(1, count // 10),))
                
                elif self.config.disk_eviction_policy == EvictionPolicy.FIFO:
                    cursor.execute("""
                        DELETE FROM cache_entries 
                        WHERE key IN (
                            SELECT key FROM cache_entries 
                            ORDER BY created_at ASC 
                            LIMIT ?
                        )
                    """, (max(1, count // 10),))
                
                conn.commit()
                self.stats.evictions += cursor.rowcount
                
        except Exception as e:
            logger.error(f"Disk cache eviction error: {str(e)}")
    
    def _update_average_time(self, current_avg: float, start_time: float, count: int) -> float:
        """Update running average time."""
        elapsed_ms = (time.time() - start_time) * 1000
        if count == 1:
            return elapsed_ms
        return ((current_avg * (count - 1)) + elapsed_ms) / count

class CacheManager:
    """Advanced multi-level cache manager."""
    
    def __init__(self, config: CacheConfig = None):
        self.config = config or CacheConfig()
        
        # Initialize cache levels
        self.memory_cache = MemoryCache(self.config)
        self.disk_cache = DiskCache(self.config)
        
        # Cache warming
        self.cache_warmer = CacheWarmer(self) if self.config.enable_cache_warming else None
        
        # Analytics
        self.analytics = CacheAnalytics(self) if self.config.enable_analytics else None
        
        # Background tasks
        self.cleanup_task: Optional[asyncio.Task] = None
        self.running = False
        
        # Thread pool for async operations
        self.thread_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="cache")
        
        # Statistics
        self.global_stats = CacheStats()
        
        logger.info("Advanced Cache Manager initialized")
    
    async def initialize(self):
        """Initialize cache manager."""
        self.running = True
        
        # Start background cleanup task
        if self.config.cleanup_interval_seconds > 0:
            self.cleanup_task = asyncio.create_task(self._cleanup_worker())
        
        # Initialize cache warmer
        if self.cache_warmer:
            await self.cache_warmer.initialize()
        
        # Initialize analytics
        if self.analytics:
            await self.analytics.initialize()
        
        logger.info("Cache Manager initialization completed")
    
    async def get(self, key: str, tags: Set[str] = None) -> Any:
        """Get value from cache with multi-level lookup."""
        
        # Try memory cache first
        entry = self.memory_cache.get(key)
        if entry and (not tags or tags.intersection(entry.tags)):
            self.global_stats.hits += 1
            if self.analytics:
                await self.analytics.record_hit(CacheLevel.MEMORY, key, entry)
            return entry.value
        
        # Try disk cache
        entry = await asyncio.get_event_loop().run_in_executor(
            self.thread_pool, self.disk_cache.get, key
        )
        
        if entry and (not tags or tags.intersection(entry.tags)):
            # Promote to memory cache
            await self._promote_to_memory(key, entry)
            
            self.global_stats.hits += 1
            if self.analytics:
                await self.analytics.record_hit(CacheLevel.DISK, key, entry)
            return entry.value
        
        # Cache miss
        self.global_stats.misses += 1
        if self.analytics:
            await self.analytics.record_miss(key, tags)
        
        return None
    
    async def put(self, key: str, value: Any, ttl: Optional[float] = None, 
                  tags: Set[str] = None, priority: int = 0,
                  compression: CompressionType = None,
                  serialization: SerializationType = None) -> bool:
        """Put value into cache with intelligent placement."""
        
        # Create cache entry
        entry = CacheEntry(
            key=key,
            value=value,
            created_at=time.time(),
            last_accessed=time.time(),
            ttl=ttl or self.config.default_ttl_seconds,
            tags=tags or set(),
            priority=priority,
            compression=compression or self.config.compression_type,
            serialization=serialization or self.config.serialization_type
        )
        
        # Estimate size
        entry.size_bytes = self._estimate_size(value)
        
        success = True
        
        # Always try to put in memory cache first
        if not self.memory_cache.put(key, entry):
            logger.warning(f"Failed to put entry in memory cache: {key}")
        
        # Put in disk cache asynchronously if configured
        if self.config.enable_async_writes:
            asyncio.create_task(self._async_disk_put(key, entry))
        else:
            disk_success = await asyncio.get_event_loop().run_in_executor(
                self.thread_pool, self.disk_cache.put, key, entry
            )
            success = success and disk_success
        
        if self.analytics:
            await self.analytics.record_write(key, entry)
        
        return success
    
    async def remove(self, key: str) -> bool:
        """Remove entry from all cache levels."""
        
        memory_removed = self.memory_cache.remove(key)
        disk_removed = await asyncio.get_event_loop().run_in_executor(
            self.thread_pool, self.disk_cache.remove, key
        )
        
        if self.analytics:
            await self.analytics.record_removal(key)
        
        return memory_removed or disk_removed
    
    async def clear(self, tags: Set[str] = None):
        """Clear cache entries, optionally filtered by tags."""
        
        if not tags:
            # Clear all
            self.memory_cache.clear()
            await asyncio.get_event_loop().run_in_executor(
                self.thread_pool, self.disk_cache.clear
            )
        else:
            # Clear by tags (would need implementation)
            logger.warning("Tag-based clearing not yet implemented")
    
    async def warm_cache(self, warming_data: List[Tuple[str, Any]]):
        """Warm cache with predefined data."""
        if self.cache_warmer:
            await self.cache_warmer.warm(warming_data)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics."""
        
        memory_stats = self.memory_cache.stats
        disk_stats = self.disk_cache.stats
        
        return {
            'global': {
                'hits': self.global_stats.hits,
                'misses': self.global_stats.misses,
                'hit_rate': self.global_stats.hit_rate,
                'miss_rate': self.global_stats.miss_rate
            },
            'memory': {
                'hits': memory_stats.hits,
                'misses': memory_stats.misses,
                'hit_rate': memory_stats.hit_rate,
                'entries': memory_stats.entries,
                'size_mb': memory_stats.memory_usage_bytes / (1024 * 1024),
                'evictions': memory_stats.evictions,
                'avg_hit_time_ms': memory_stats.average_hit_time_ms
            },
            'disk': {
                'hits': disk_stats.hits,
                'misses': disk_stats.misses,
                'hit_rate': disk_stats.hit_rate,
                'entries': disk_stats.entries,
                'size_mb': disk_stats.disk_usage_bytes / (1024 * 1024),
                'evictions': disk_stats.evictions,
                'avg_hit_time_ms': disk_stats.average_hit_time_ms
            }
        }
    
    # Private methods
    
    async def _promote_to_memory(self, key: str, entry: CacheEntry):
        """Promote disk cache entry to memory cache."""
        try:
            self.memory_cache.put(key, entry)
        except Exception as e:
            logger.error(f"Failed to promote entry to memory: {str(e)}")
    
    async def _async_disk_put(self, key: str, entry: CacheEntry):
        """Asynchronously put entry in disk cache."""
        try:
            await asyncio.get_event_loop().run_in_executor(
                self.thread_pool, self.disk_cache.put, key, entry
            )
        except Exception as e:
            logger.error(f"Async disk cache put failed: {str(e)}")
    
    def _estimate_size(self, value: Any) -> int:
        """Estimate memory size of value."""
        try:
            if isinstance(value, (str, bytes)):
                return len(value)
            elif isinstance(value, (list, tuple)):
                return sum(self._estimate_size(item) for item in value)
            elif isinstance(value, dict):
                return sum(self._estimate_size(k) + self._estimate_size(v) 
                          for k, v in value.items())
            else:
                return len(pickle.dumps(value))
        except Exception:
            return 1024  # Default estimate
    
    async def _cleanup_worker(self):
        """Background cleanup worker."""
        while self.running:
            try:
                await asyncio.sleep(self.config.cleanup_interval_seconds)
                
                # Cleanup expired entries
                await self._cleanup_expired_entries()
                
                # Cleanup based on size thresholds
                await self._cleanup_size_based()
                
            except Exception as e:
                logger.error(f"Cache cleanup error: {str(e)}")
    
    async def _cleanup_expired_entries(self):
        """Clean up expired cache entries."""
        # This would implement TTL-based cleanup
        pass
    
    async def _cleanup_size_based(self):
        """Clean up entries based on size thresholds."""
        # This would implement size-based cleanup
        pass
    
    async def shutdown(self):
        """Shutdown cache manager."""
        self.running = False
        
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        if self.cache_warmer:
            await self.cache_warmer.shutdown()
        
        if self.analytics:
            await self.analytics.shutdown()
        
        self.thread_pool.shutdown(wait=True)
        
        logger.info("Cache Manager shutdown completed")


# Helper classes

class CacheWarmer:
    """Intelligent cache warming system."""
    
    def __init__(self, cache_manager: CacheManager):
        self.cache_manager = cache_manager
        self.warming_patterns = []
    
    async def initialize(self):
        """Initialize cache warmer."""
        pass
    
    async def warm(self, warming_data: List[Tuple[str, Any]]):
        """Warm cache with data."""
        for key, value in warming_data:
            await self.cache_manager.put(key, value)
    
    async def shutdown(self):
        """Shutdown cache warmer."""
        pass


class CacheAnalytics:
    """Cache performance analytics and monitoring."""
    
    def __init__(self, cache_manager: CacheManager):
        self.cache_manager = cache_manager
        self.metrics = []
    
    async def initialize(self):
        """Initialize analytics."""
        pass
    
    async def record_hit(self, level: CacheLevel, key: str, entry: CacheEntry):
        """Record cache hit."""
        pass
    
    async def record_miss(self, key: str, tags: Set[str]):
        """Record cache miss."""
        pass
    
    async def record_write(self, key: str, entry: CacheEntry):
        """Record cache write."""
        pass
    
    async def record_removal(self, key: str):
        """Record cache removal."""
        pass
    
    async def shutdown(self):
        """Shutdown analytics."""
        pass
