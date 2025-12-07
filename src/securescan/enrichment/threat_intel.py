"""Threat intelligence from CISA KEV and exploit databases."""

import requests
from typing import Dict, Any, List, Optional, Set
from datetime import datetime
from .cache_manager import CacheManager
from ..utils.logger import get_logger

logger = get_logger(__name__)


class ThreatIntel:
    """
    Aggregate threat intelligence from multiple sources.
    
    Sources:
    - CISA KEV (Known Exploited Vulnerabilities)
    - NVD references (exploit tags)
    - ExploitDB patterns
    """
    
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    def __init__(self, cache_manager: Optional[CacheManager] = None):
        """
        Initialize threat intelligence.
        
        Args:
            cache_manager: Cache manager instance
        """
        self.cache = cache_manager or CacheManager()
        self._kev_cache: Optional[Set[str]] = None
    
    def enrich_finding_with_threats(
        self,
        finding: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Enrich finding with threat intelligence.
        
        Args:
            finding: Finding dictionary with CVE data
            
        Returns:
            Finding enriched with threat data
        """
        if not finding.get("cve_enriched"):
            return finding
        
        related_cves = finding.get("related_cves", [])
        
        # Check CISA KEV
        kev_cves = []
        for cve in related_cves:
            if self.check_cisa_kev(cve["cve_id"]):
                kev_cves.append(cve["cve_id"])
        
        # Check exploit availability
        exploit_count = 0
        for cve in related_cves:
            if self.check_exploit_available(cve):
                exploit_count += 1
        
        # Add threat data
        finding["cisa_kev"] = len(kev_cves) > 0
        finding["cisa_kev_cves"] = kev_cves
        finding["exploit_available"] = exploit_count > 0
        finding["exploit_count"] = exploit_count
        
        # Calculate threat level
        finding["threat_level"] = self._calculate_threat_level(finding)
        
        logger.info(
            f"Threat intel: KEV={finding['cisa_kev']}, "
            f"Exploits={exploit_count}, "
            f"Level={finding['threat_level']}"
        )
        
        return finding
    
    def check_cisa_kev(self, cve_id: str) -> bool:
        """
        Check if CVE is in CISA Known Exploited Vulnerabilities.
        
        Args:
            cve_id: CVE ID (e.g., "CVE-2021-44228")
            
        Returns:
            True if in CISA KEV catalog
        """
        # Load KEV catalog (cached)
        if self._kev_cache is None:
            self._load_kev_catalog()
        
        return cve_id in self._kev_cache if self._kev_cache else False
    
    def _load_kev_catalog(self) -> None:
        """Load CISA KEV catalog from API."""
        # Check cache first (1-day TTL for KEV)
        cache_key = "cisa_kev_catalog"
        cached = self.cache.get(cache_key)
        
        if cached:
            logger.debug("CISA KEV catalog loaded from cache")
            self._kev_cache = set(cached)
            return
        
        try:
            logger.info("Downloading CISA KEV catalog...")
            response = requests.get(self.CISA_KEV_URL, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            # Extract CVE IDs
            kev_ids = [vuln.get("cveID") for vuln in vulnerabilities]
            kev_ids = [cve_id for cve_id in kev_ids if cve_id]
            
            logger.info(f"Loaded {len(kev_ids)} CVEs from CISA KEV catalog")
            
            # Cache for 1 day
            self.cache.set(cache_key, kev_ids)
            self._kev_cache = set(kev_ids)
        
        except Exception as e:
            logger.error(f"Failed to load CISA KEV catalog: {e}")
            self._kev_cache = set()
    
    def check_exploit_available(self, cve_data: Dict[str, Any]) -> bool:
        """
        Check if public exploit is available for CVE.
        
        Args:
            cve_data: CVE dictionary with references
            
        Returns:
            True if exploit likely available
        """
        # Check NVD references for exploit tags
        references = cve_data.get("references", [])
        
        exploit_indicators = [
            "exploit",
            "exploitdb",
            "metasploit",
            "poc",
            "proof-of-concept",
            "github.com/exploit",
        ]
        
        for ref in references:
            # Check tags
            tags = ref.get("tags", [])
            if "Exploit" in tags or "exploit" in tags:
                return True
            
            # Check URL
            url = ref.get("url", "").lower()
            if any(indicator in url for indicator in exploit_indicators):
                return True
        
        return False
    
    def _calculate_threat_level(self, finding: Dict[str, Any]) -> str:
        """
        Calculate overall threat level for finding.
        
        Factors:
        - CVSS score
        - CISA KEV status
        - Exploit availability
        - Finding severity
        
        Args:
            finding: Enriched finding dictionary
            
        Returns:
            Threat level: CRITICAL, HIGH, MEDIUM, LOW
        """
        # Base score from CVSS
        max_cvss = finding.get("max_cvss", 0) or 0
        avg_cvss = finding.get("avg_cvss", 0) or 0
        
        # Modifiers
        is_kev = finding.get("cisa_kev", False)
        has_exploit = finding.get("exploit_available", False)
        
        # Calculate threat score (0-100)
        threat_score = 0
        
        # CVSS contributes up to 60 points
        threat_score += (max_cvss * 6)
        
        # CISA KEV adds 30 points (actively exploited!)
        if is_kev:
            threat_score += 30
        
        # Public exploit adds 10 points
        if has_exploit:
            threat_score += 10
        
        # Determine level
        if threat_score >= 85 or is_kev:
            return "CRITICAL"
        elif threat_score >= 70:
            return "HIGH"
        elif threat_score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
    
    def get_threat_summary(self, finding: Dict[str, Any]) -> str:
        """
        Get human-readable threat summary.
        
        Args:
            finding: Enriched finding
            
        Returns:
            Threat summary string
        """
        parts = []
        
        if finding.get("cisa_kev"):
            kev_count = len(finding.get("cisa_kev_cves", []))
            parts.append(f"⚠️  {kev_count} CVE(s) in CISA KEV (actively exploited)")
        
        if finding.get("exploit_available"):
            exploit_count = finding.get("exploit_count", 0)
            parts.append(f"💥 {exploit_count} CVE(s) with public exploits")
        
        max_cvss = finding.get("max_cvss")
        if max_cvss:
            parts.append(f"📊 Max CVSS: {max_cvss:.1f}")
        
        threat_level = finding.get("threat_level", "UNKNOWN")
        parts.append(f"🎯 Threat Level: {threat_level}")
        
        return " | ".join(parts) if parts else "No threat data available"
