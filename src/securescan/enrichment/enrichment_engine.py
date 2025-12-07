"""Main enrichment engine that orchestrates all enrichment."""

from typing import List, Dict, Any
from .nvd_client import NVDClient
from .cve_mapper import CVEMapper
from .cvss_calculator import CVSSCalculator
from .threat_intel import ThreatIntel
from .cache_manager import CacheManager
from ..utils.logger import get_logger

logger = get_logger(__name__)


class EnrichmentEngine:
    """
    Orchestrates all CVE enrichment and threat intelligence.
    
    Pipeline:
    1. Map CWE → CVEs (NVD API)
    2. Calculate CVSS statistics
    3. Check CISA KEV
    4. Check exploit availability
    5. Calculate threat level
    """
    
    def __init__(
        self,
        nvd_api_key: str = None,
        max_cves_per_finding: int = 10
    ):
        """
        Initialize enrichment engine.
        
        Args:
            nvd_api_key: Optional NVD API key
            max_cves_per_finding: Max CVEs to fetch per finding
        """
        self.cache = CacheManager()
        self.nvd_client = NVDClient(api_key=nvd_api_key, cache_manager=self.cache)
        self.cve_mapper = CVEMapper(self.nvd_client)
        self.cvss_calc = CVSSCalculator()
        self.threat_intel = ThreatIntel(cache_manager=self.cache)
        self.max_cves = max_cves_per_finding
        
        logger.info("Enrichment engine initialized")
    
    def enrich_findings(
        self,
        findings: List[Dict[str, Any]],
        show_progress: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Enrich all findings with CVE data and threat intelligence.
        
        Args:
            findings: List of finding dictionaries
            show_progress: Show progress messages
            
        Returns:
            List of enriched findings
        """
        if not findings:
            return []
        
        enrichable = [f for f in findings if f.get("cwe_id")]
        
        if show_progress:
            logger.info(
                f"Enriching {len(enrichable)}/{len(findings)} findings "
                f"with CVE data..."
            )
        
        enriched = []
        
        for i, finding in enumerate(findings, 1):
            if not finding.get("cwe_id"):
                logger.debug(f"Skipping finding without CWE: {finding.get('title')}")
                enriched.append(finding)
                continue
            
            try:
                # Step 1: Map CWE → CVEs
                finding = self.cve_mapper.enrich_finding(
                    finding,
                    max_cves=self.max_cves
                )
                
                # Step 2: Add threat intelligence
                if finding.get("cve_enriched"):
                    finding = self.threat_intel.enrich_finding_with_threats(finding)
                
                enriched.append(finding)
                
                if show_progress and i % 5 == 0:
                    logger.info(f"Enriched {i}/{len(enrichable)} findings...")
            
            except Exception as e:
                logger.error(f"Failed to enrich finding: {e}")
                enriched.append(finding)
        
        # Summary
        enriched_count = sum(1 for f in enriched if f.get("cve_enriched"))
        kev_count = sum(1 for f in enriched if f.get("cisa_kev"))
        exploit_count = sum(1 for f in enriched if f.get("exploit_available"))
        
        if show_progress:
            logger.info(
                f"Enrichment complete: {enriched_count} enriched, "
                f"{kev_count} in CISA KEV, {exploit_count} with exploits"
            )
        
        return enriched
    
    def get_enrichment_stats(
        self,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Get enrichment statistics."""
        enriched = [f for f in findings if f.get("cve_enriched")]
        
        total_cves = sum(f.get("cve_count", 0) for f in enriched)
        avg_cvss_scores = [f.get("avg_cvss") for f in enriched if f.get("avg_cvss")]
        max_cvss_scores = [f.get("max_cvss") for f in enriched if f.get("max_cvss")]
        
        return {
            "total_findings": len(findings),
            "enriched_findings": len(enriched),
            "enrichment_rate": len(enriched) / len(findings) if findings else 0,
            "total_cves_found": total_cves,
            "avg_cves_per_finding": total_cves / len(enriched) if enriched else 0,
            "findings_in_cisa_kev": sum(1 for f in enriched if f.get("cisa_kev")),
            "findings_with_exploits": sum(1 for f in enriched if f.get("exploit_available")),
            "avg_cvss": sum(avg_cvss_scores) / len(avg_cvss_scores) if avg_cvss_scores else None,
            "max_cvss": max(max_cvss_scores) if max_cvss_scores else None,
            "threat_levels": {
                "CRITICAL": sum(1 for f in enriched if f.get("threat_level") == "CRITICAL"),
                "HIGH": sum(1 for f in enriched if f.get("threat_level") == "HIGH"),
                "MEDIUM": sum(1 for f in enriched if f.get("threat_level") == "MEDIUM"),
                "LOW": sum(1 for f in enriched if f.get("threat_level") == "LOW"),
            }
        }
