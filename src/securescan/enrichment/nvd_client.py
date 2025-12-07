"""NVD API v2.0 client for CVE data."""

import os
import time
from typing import List, Dict, Any, Optional
import requests
from datetime import datetime

from .cache_manager import CacheManager
from ..utils.logger import get_logger

logger = get_logger(__name__)


class NVDClient:
    """
    NIST National Vulnerability Database (NVD) API v2.0 client.
    
    Features:
    - CVE lookup by ID
    - CVE search by CWE
    - CVSS score retrieval
    - 7-day cache (reduces API calls)
    - Rate limiting (with/without API key)
    
    Rate limits:
    - Without API key: 5 requests / 30 seconds
    - With API key: 50 requests / 30 seconds
    
    API key: Get free at https://nvd.nist.gov/developers/request-an-api-key
    """
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_manager: Optional[CacheManager] = None
    ):
        """
        Initialize NVD client.
        
        Args:
            api_key: NVD API key (optional, increases rate limit)
            cache_manager: Cache manager (default: new instance)
        """
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.cache = cache_manager or CacheManager()
        
        # Rate limiting
        self.requests_per_window = 50 if self.api_key else 5
        self.window_seconds = 30
        self.request_times: List[float] = []
        
        if self.api_key:
            logger.info("NVD client initialized with API key (50 req/30s)")
        else:
            logger.info("NVD client initialized without API key (5 req/30s)")
            logger.info("Get free API key: https://nvd.nist.gov/developers/request-an-api-key")
    
    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get CVE details by ID.
        
        Args:
            cve_id: CVE ID (e.g., "CVE-2023-12345")
            
        Returns:
            CVE data dictionary or None if not found
        """
        # Check cache first
        cache_key = f"cve_{cve_id}"
        cached = self.cache.get(cache_key)
        if cached:
            logger.debug(f"Cache hit: {cve_id}")
            return cached
        
        # Rate limit
        self._wait_for_rate_limit()
        
        # Call API
        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key
            
            response = requests.get(
                self.BASE_URL,
                params={"cveId": cve_id},
                headers=headers,
                timeout=10
            )
            
            self._record_request()
            
            if response.status_code == 404:
                logger.debug(f"CVE not found: {cve_id}")
                return None
            
            response.raise_for_status()
            data = response.json()
            
            # Extract CVE from response
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return None
            
            cve_data = vulnerabilities[0].get("cve", {})
            
            # Parse relevant data
            parsed = self._parse_cve(cve_data)
            
            # Cache it
            self.cache.set(cache_key, parsed)
            
            return parsed
        
        except Exception as e:
            logger.error(f"Failed to fetch CVE {cve_id}: {e}")
            return None
    
    def search_by_cwe(
        self,
        cwe_id: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Search CVEs by CWE ID.
        
        Args:
            cwe_id: CWE ID (e.g., "CWE-89" or "89" or "CWE-89: SQL Injection")
            limit: Maximum results (default: 100)
            
        Returns:
            List of CVE dictionaries
        """
        # Clean and normalize CWE ID
        # Remove description if present (e.g., "CWE-78: Description" -> "CWE-78")
        if ":" in cwe_id:
            cwe_id = cwe_id.split(":")[0].strip()
        
        # Remove any parentheses and their content
        if "(" in cwe_id:
            cwe_id = cwe_id.split("(")[0].strip()
        
        # Normalize to CWE-XXX format
        if not cwe_id.startswith("CWE-"):
            # Extract just numbers
            cwe_number = ''.join(filter(str.isdigit, cwe_id))
            if cwe_number:
                cwe_id = f"CWE-{cwe_number}"
            else:
                logger.error(f"Invalid CWE ID format: {cwe_id}")
                return []
        
        logger.debug(f"Normalized CWE ID: {cwe_id}")
        
        # Check cache
        cache_key = f"cwe_{cwe_id}_limit{limit}"
        cached = self.cache.get(cache_key)
        if cached:
            logger.debug(f"Cache hit: {cwe_id}")
            return cached
        
        # Rate limit
        self._wait_for_rate_limit()
        
        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key
            
            response = requests.get(
                self.BASE_URL,
                params={
                    "cweId": cwe_id,
                    "resultsPerPage": min(limit, 2000),  # API max
                },
                headers=headers,
                timeout=30  # Longer timeout for searches
            )
            
            self._record_request()
            
            # Handle 404 gracefully (CWE might not have CVEs)
            if response.status_code == 404:
                logger.debug(f"No CVEs found for {cwe_id}")
                return []
            
            response.raise_for_status()
            data = response.json()
            
            # Parse CVEs
            cves = []
            for vuln in data.get("vulnerabilities", [])[:limit]:
                cve_data = vuln.get("cve", {})
                parsed = self._parse_cve(cve_data)
                if parsed:
                    cves.append(parsed)
            
            logger.info(f"Found {len(cves)} CVEs for {cwe_id}")
            
            # Cache results
            self.cache.set(cache_key, cves)
            
            return cves
        
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.debug(f"No CVEs found for {cwe_id} (404)")
                return []
            logger.error(f"HTTP error searching CVEs for {cwe_id}: {e}")
            return []
        
        except Exception as e:
            logger.error(f"Failed to search CVEs for {cwe_id}: {e}")
            return []
    
    def _parse_cve(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse CVE data from NVD API response."""
        cve_id = cve_data.get("id", "")
        
        # Extract description
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        # Extract CVSS scores
        metrics = cve_data.get("metrics", {})
        
        # Try CVSS v3.1 first
        cvss_v31 = metrics.get("cvssMetricV31", [])
        cvss_v30 = metrics.get("cvssMetricV30", [])
        cvss_v2 = metrics.get("cvssMetricV2", [])
        
        cvss_score = None
        cvss_severity = None
        cvss_vector = None
        
        if cvss_v31:
            cvss_data = cvss_v31[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity")
            cvss_vector = cvss_data.get("vectorString")
        elif cvss_v30:
            cvss_data = cvss_v30[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity")
            cvss_vector = cvss_data.get("vectorString")
        elif cvss_v2:
            cvss_data = cvss_v2[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = self._cvss_v2_to_severity(cvss_score)
            cvss_vector = cvss_data.get("vectorString")
        
        # Extract CWEs
        weaknesses = cve_data.get("weaknesses", [])
        cwe_ids = []
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                cwe_id = desc.get("value", "")
                if cwe_id.startswith("CWE-"):
                    cwe_ids.append(cwe_id)
        
        # Extract references
        references = []
        for ref in cve_data.get("references", []):
            references.append({
                "url": ref.get("url", ""),
                "source": ref.get("source", ""),
                "tags": ref.get("tags", [])
            })
        
        # Published/Modified dates
        published = cve_data.get("published", "")
        modified = cve_data.get("lastModified", "")
        
        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "cvss_vector": cvss_vector,
            "cwe_ids": cwe_ids,
            "references": references,
            "published": published,
            "modified": modified,
        }
    
    def _cvss_v2_to_severity(self, score: Optional[float]) -> Optional[str]:
        """Convert CVSS v2 score to severity."""
        if score is None:
            return None
        if score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _wait_for_rate_limit(self) -> None:
        """Wait if rate limit would be exceeded."""
        current_time = time.time()
        
        # Remove old requests outside window
        self.request_times = [
            t for t in self.request_times
            if current_time - t < self.window_seconds
        ]
        
        # Check if we're at limit
        if len(self.request_times) >= self.requests_per_window:
            # Wait until oldest request is outside window
            wait_time = self.window_seconds - (current_time - self.request_times[0])
            if wait_time > 0:
                logger.debug(f"Rate limit: waiting {wait_time:.1f}s")
                time.sleep(wait_time + 0.1)  # Add small buffer
    
    def _record_request(self) -> None:
        """Record request time for rate limiting."""
        self.request_times.append(time.time())
