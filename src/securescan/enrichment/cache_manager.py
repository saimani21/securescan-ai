"""Cache manager for CVE data (7-day TTL)."""

import json
import time
from pathlib import Path
from typing import Optional, Any, Dict
from datetime import datetime, timedelta

from ..utils.logger import get_logger

logger = get_logger(__name__)


class CacheManager:
    """
    Disk-based cache for CVE data with TTL.
    
    Features:
    - 7-day default TTL
    - Atomic writes
    - Automatic cleanup
    - JSON serialization
    """
    
    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        ttl_days: int = 7
    ):
        """
        Initialize cache manager.
        
        Args:
            cache_dir: Cache directory (default: .securescan/cache)
            ttl_days: Time to live in days (default: 7)
        """
        self.cache_dir = cache_dir or Path.home() / ".securescan" / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.ttl_seconds = ttl_days * 24 * 60 * 60
        
        logger.debug(f"Cache initialized: {self.cache_dir} (TTL: {ttl_days} days)")
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if expired/not found
        """
        cache_file = self._get_cache_file(key)
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r') as f:
                cached = json.load(f)
            
            # Check if expired
            cached_time = cached.get("timestamp", 0)
            age = time.time() - cached_time
            
            if age > self.ttl_seconds:
                logger.debug(f"Cache expired: {key} (age: {age/3600:.1f}h)")
                cache_file.unlink()
                return None
            
            logger.debug(f"Cache hit: {key} (age: {age/3600:.1f}h)")
            return cached.get("data")
        
        except Exception as e:
            logger.warning(f"Cache read error for {key}: {e}")
            return None
    
    def set(self, key: str, value: Any) -> None:
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache (must be JSON-serializable)
        """
        cache_file = self._get_cache_file(key)
        
        try:
            # Atomic write
            temp_file = cache_file.with_suffix(".tmp")
            
            with open(temp_file, 'w') as f:
                json.dump({
                    "timestamp": time.time(),
                    "data": value
                }, f, indent=2)
            
            temp_file.replace(cache_file)
            
            logger.debug(f"Cache set: {key}")
        
        except Exception as e:
            logger.warning(f"Cache write error for {key}: {e}")
    
    def delete(self, key: str) -> None:
        """Delete value from cache."""
        cache_file = self._get_cache_file(key)
        
        if cache_file.exists():
            cache_file.unlink()
            logger.debug(f"Cache deleted: {key}")
    
    def clear(self) -> int:
        """
        Clear all cache.
        
        Returns:
            Number of files deleted
        """
        count = 0
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()
            count += 1
        
        logger.info(f"Cache cleared: {count} files deleted")
        return count
    
    def cleanup_expired(self) -> int:
        """
        Remove expired cache entries.
        
        Returns:
            Number of expired entries removed
        """
        count = 0
        current_time = time.time()
        
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, 'r') as f:
                    cached = json.load(f)
                
                cached_time = cached.get("timestamp", 0)
                age = current_time - cached_time
                
                if age > self.ttl_seconds:
                    cache_file.unlink()
                    count += 1
            
            except Exception as e:
                logger.debug(f"Error checking cache file {cache_file}: {e}")
        
        if count > 0:
            logger.info(f"Cleanup: {count} expired entries removed")
        
        return count
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        cache_files = list(self.cache_dir.glob("*.json"))
        total_size = sum(f.stat().st_size for f in cache_files)
        
        expired = 0
        current_time = time.time()
        
        for cache_file in cache_files:
            try:
                with open(cache_file, 'r') as f:
                    cached = json.load(f)
                age = current_time - cached.get("timestamp", 0)
                if age > self.ttl_seconds:
                    expired += 1
            except:
                pass
        
        return {
            "total_entries": len(cache_files),
            "expired_entries": expired,
            "total_size_bytes": total_size,
            "total_size_mb": total_size / (1024 * 1024),
            "cache_dir": str(self.cache_dir),
            "ttl_days": self.ttl_seconds / (24 * 60 * 60),
        }
    
    def _get_cache_file(self, key: str) -> Path:
        """Get cache file path for key."""
        # Sanitize key for filename
        safe_key = "".join(c if c.isalnum() or c in ".-_" else "_" for c in key)
        return self.cache_dir / f"{safe_key}.json"
