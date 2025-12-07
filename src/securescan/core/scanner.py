"""Main scanner orchestrator with LLM validation and CVE enrichment support."""

import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import uuid

from .semgrep_runner import SemgrepRunner
from .secrets_detector import SecretsDetector
from ..utils.logger import get_logger
from ..utils.config import Config

logger = get_logger(__name__)


@dataclass
class ScanResult:
    """Complete scan result with metadata and findings."""
    
    # Scan metadata
    scan_id: str
    target: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    
    # Results
    findings: List[Dict[str, Any]] = field(default_factory=list)
    files_scanned: int = 0
    total_findings: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    
    # Status
    success: bool = True
    errors: List[str] = field(default_factory=list)
    
    # Configuration used
    config: Dict[str, Any] = field(default_factory=dict)


class Scanner:
    """Main security scanner orchestrator."""
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize scanner.
        
        Args:
            config: Configuration object (uses default if None)
        """
        self.config = config or Config()
        self.semgrep = SemgrepRunner(
            timeout=self.config.get("scan.timeout", 300)
        )
        self.secrets_detector = SecretsDetector()
        logger.info("Scanner initialized")
    
    def scan(
        self,
        target: Path,
        severity_filter: Optional[List[str]] = None,
        enable_secrets: bool = True,
        enable_llm: bool = False,
        llm_provider: str = "openai",
        llm_model: str = "gpt-4o",
        llm_confidence_threshold: float = 0.7,
        enable_cve_enrichment: bool = False,
        cve_max_per_finding: int = 10,
    ) -> ScanResult:
        """
        Run complete security scan.
        
        Args:
            target: Path to scan (file or directory)
            severity_filter: Only include these severities (e.g., ["HIGH", "CRITICAL"])
            enable_secrets: Run extra secrets detection
            enable_llm: Enable LLM validation (Phase 2)
            llm_provider: LLM provider ("openai" or "ollama")
            llm_model: Model to use (e.g., "gpt-4o")
            llm_confidence_threshold: Minimum confidence to keep finding (0.0-1.0)
            enable_cve_enrichment: Enable CVE enrichment (Phase 3)
            cve_max_per_finding: Max CVEs to fetch per finding (default: 10)
            
        Returns:
            ScanResult with all findings and metadata
        """
        target = Path(target).resolve()
        scan_id = str(uuid.uuid4())[:8]
        started_at = datetime.now()
        
        logger.info(f"Starting scan {scan_id} on {target}")
        
        # Initialize result
        result = ScanResult(
            scan_id=scan_id,
            target=str(target),
            started_at=started_at,
            config={
                "severity_filter": severity_filter,
                "enable_secrets": enable_secrets,
                "enable_llm": enable_llm,
                "llm_provider": llm_provider if enable_llm else None,
                "llm_model": llm_model if enable_llm else None,
                "enable_cve_enrichment": enable_cve_enrichment,
                "cve_max_per_finding": cve_max_per_finding if enable_cve_enrichment else None,
            }
        )
        
        try:
            # === STAGE 1a: Run Semgrep ===
            logger.info("Running Semgrep scan...")
            semgrep_output = self.semgrep.scan(target)
            semgrep_findings = self.semgrep.convert_findings(semgrep_output)
            findings_dicts = self.semgrep.to_dict_list(semgrep_findings)
            
            logger.info(f"Semgrep found {len(findings_dicts)} findings")
            
            # === STAGE 1b: Run Secrets Detector ===
            if enable_secrets:
                logger.info("Running additional secrets detection...")
                if target.is_dir():
                    secrets_findings = self.secrets_detector.scan_directory(target)
                else:
                    secrets_findings = self.secrets_detector.scan_file(target)
                
                logger.info(f"Secrets detector found {len(secrets_findings)} findings")
                
                # Merge secrets findings with Semgrep findings
                findings_dicts.extend(secrets_findings)
                logger.info(f"Total findings after merge: {len(findings_dicts)}")
            
            # === STAGE 1c: LLM Validation (Optional - Phase 2) ===
            if enable_llm and findings_dicts:
                logger.info(f"Running LLM validation with {llm_provider}/{llm_model}...")
                
                try:
                    # Import here to avoid dependency if not using LLM
                    from ..llm.validator import Validator
                    
                    # Initialize LLM client based on provider
                    if llm_provider.lower() == "openai":
                        from ..llm.openai_client import OpenAIClient
                        llm_client = OpenAIClient(model=llm_model)
                    elif llm_provider.lower() == "ollama":
                        from ..llm.ollama_client import OllamaClient
                        llm_client = OllamaClient(model=llm_model)
                    else:
                        raise ValueError(
                            f"Unsupported LLM provider: {llm_provider}. "
                            "Use 'openai' or 'ollama'"
                        )
                    
                    # Run validation
                    validator = Validator(
                        llm_client,
                        confidence_threshold=llm_confidence_threshold,
                        max_workers=3  # Parallel validation
                    )
                    
                    original_count = len(findings_dicts)
                    findings_dicts = validator.validate_findings(
                        findings_dicts,
                        show_progress=True
                    )
                    
                    # Store validation stats
                    val_stats = validator.get_stats()
                    result.config["llm_validation"] = {
                        "provider": llm_provider,
                        "model": llm_model,
                        "confidence_threshold": llm_confidence_threshold,
                        "original_findings": original_count,
                        "validated": val_stats.validated,
                        "confirmed_vulnerable": val_stats.confirmed_vulnerable,
                        "false_positives": val_stats.false_positives,
                        "filtered_out": original_count - len(findings_dicts),
                        "avg_confidence": val_stats.avg_confidence,
                        "total_tokens": val_stats.total_tokens,
                        "total_cost_usd": val_stats.total_cost_usd,
                        "failed": val_stats.failed,
                    }
                    
                    logger.info(
                        f"LLM validation complete: {val_stats.confirmed_vulnerable} confirmed, "
                        f"{val_stats.false_positives} false positives filtered, "
                        f"${val_stats.total_cost_usd:.4f} cost"
                    )
                
                except ImportError as e:
                    error_msg = f"LLM libraries not installed: {e}"
                    logger.error(error_msg)
                    result.errors.append(error_msg)
                except Exception as e:
                    error_msg = f"LLM validation failed: {e}"
                    logger.error(error_msg, exc_info=True)
                    result.errors.append(error_msg)
                    # Continue with unvalidated findings
            
            # === STAGE 1d: CVE Enrichment (Optional - Phase 3) ===
            if enable_cve_enrichment and findings_dicts:
                logger.info("Running CVE enrichment...")
                
                try:
                    from ..enrichment.enrichment_engine import EnrichmentEngine
                    
                    enrichment_engine = EnrichmentEngine(
                        nvd_api_key=os.getenv("NVD_API_KEY"),
                        max_cves_per_finding=cve_max_per_finding
                    )
                    
                    findings_dicts = enrichment_engine.enrich_findings(
                        findings_dicts,
                        show_progress=True
                    )
                    
                    # Get enrichment stats
                    enrichment_stats = enrichment_engine.get_enrichment_stats(findings_dicts)
                    
                    logger.info(
                        f"CVE enrichment complete: {enrichment_stats['enriched_findings']} enriched, "
                        f"{enrichment_stats['findings_in_cisa_kev']} in CISA KEV, "
                        f"{enrichment_stats['findings_with_exploits']} with exploits"
                    )
                    
                    result.config["cve_enrichment"] = enrichment_stats
                
                except ImportError as e:
                    error_msg = f"CVE enrichment libraries not available: {e}"
                    logger.error(error_msg)
                    result.errors.append(error_msg)
                except Exception as e:
                    error_msg = f"CVE enrichment failed: {e}"
                    logger.error(error_msg, exc_info=True)
                    result.errors.append(error_msg)
                    result.config["cve_enrichment"] = {"error": str(e)}
            
            # === STAGE 2: Apply Filters ===
            if severity_filter:
                logger.info(f"Applying severity filter: {severity_filter}")
                findings_dicts = [
                    f for f in findings_dicts
                    if f.get("severity") in severity_filter
                ]
                logger.info(f"{len(findings_dicts)} findings after filter")
            
            # === STAGE 3: Sort by Severity (and Threat Level if enriched) ===
            findings_dicts = self._sort_findings(findings_dicts)
            
            # === STAGE 4: Compute Statistics ===
            result.findings = findings_dicts
            result.total_findings = len(findings_dicts)
            result.findings_by_severity = self._count_by_severity(findings_dicts)
            result.files_scanned = len(set(f.get("file") for f in findings_dicts))
            
            # === STAGE 5: Enhanced Statistics ===
            result.config["findings_by_source"] = self._count_by_source(findings_dicts)
            result.config["findings_by_category"] = self._count_by_category(findings_dicts)
            result.config["top_files"] = self._get_top_files(findings_dicts, limit=5)
            result.config["coverage"] = {
                "total_files_scanned": result.files_scanned,
                "files_with_findings": len(set(f.get("file") for f in findings_dicts)),
                "total_lines_scanned": self._estimate_lines_scanned(target),
            }
            
            result.success = True
            
            logger.info(
                f"Scan {scan_id} complete: {result.total_findings} findings "
                f"in {result.files_scanned} files"
            )
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            result.success = False
            result.errors.append(str(e))
        
        finally:
            # Finalize timing
            result.completed_at = datetime.now()
            result.duration_seconds = (
                result.completed_at - result.started_at
            ).total_seconds()
        
        return result
    
    def _sort_findings(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Sort findings by threat level (if enriched) or severity.
        
        Order: CRITICAL > HIGH > MEDIUM > LOW > INFO
        """
        threat_order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
        }
        
        severity_order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4,
        }
        
        def sort_key(f):
            # Primary: threat level (if available)
            threat = f.get("threat_level", "")
            if threat in threat_order:
                primary = threat_order[threat]
            else:
                primary = 99
            
            # Secondary: severity
            severity = f.get("severity", "MEDIUM")
            secondary = severity_order.get(severity, 2)
            
            # Tertiary: CISA KEV (active exploits first)
            tertiary = 0 if f.get("cisa_kev") else 1
            
            return (primary, secondary, tertiary)
        
        return sorted(findings, key=sort_key)
    
    def _count_by_severity(
        self,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """Count findings by severity level."""
        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }
        
        for finding in findings:
            severity = finding.get("severity", "MEDIUM")
            if severity in counts:
                counts[severity] += 1
        
        return counts
    
    def _count_by_source(
        self,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """Count findings by detection source."""
        counts = {}
        for finding in findings:
            source = finding.get("source", "unknown")
            counts[source] = counts.get(source, 0) + 1
        return counts
    
    def _count_by_category(
        self,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """Count findings by category."""
        counts = {}
        for finding in findings:
            category = finding.get("category", "unknown")
            counts[category] = counts.get(category, 0) + 1
        return counts
    
    def _get_top_files(
        self,
        findings: List[Dict[str, Any]],
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Get files with most findings."""
        file_counts = {}
        for finding in findings:
            file_path = finding.get("file", "unknown")
            file_counts[file_path] = file_counts.get(file_path, 0) + 1
        
        sorted_files = sorted(
            file_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return [
            {"file": Path(f).name, "path": f, "findings": count}
            for f, count in sorted_files[:limit]
        ]
    
    def _estimate_lines_scanned(self, target: Path) -> int:
        """Estimate total lines scanned (rough estimate)."""
        if not target.is_dir():
            try:
                return len(target.read_text(errors="ignore").splitlines())
            except:
                return 0
        
        total_lines = 0
        scannable_extensions = {
            ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go",
            ".rb", ".php", ".c", ".cpp", ".cs", ".rs", ".kt", ".swift"
        }
        
        try:
            for filepath in target.rglob("*"):
                if filepath.is_file() and filepath.suffix in scannable_extensions:
                    try:
                        content = filepath.read_text(errors="ignore")
                        total_lines += len(content.splitlines())
                    except:
                        pass
        except:
            pass
        
        return total_lines
    
    def get_summary(self, result: ScanResult) -> Dict[str, Any]:
        """
        Get scan summary for display.
        
        Args:
            result: ScanResult to summarize
            
        Returns:
            Dictionary with summary information
        """
        summary = {
            "scan_id": result.scan_id,
            "target": result.target,
            "duration": f"{result.duration_seconds:.2f}s",
            "files_scanned": result.files_scanned,
            "total_findings": result.total_findings,
            "by_severity": result.findings_by_severity,
            "success": result.success,
            "errors": result.errors,
        }
        
        # Add enhanced stats if available
        if "findings_by_source" in result.config:
            summary["by_source"] = result.config["findings_by_source"]
        
        if "findings_by_category" in result.config:
            summary["by_category"] = result.config["findings_by_category"]
        
        if "top_files" in result.config:
            summary["top_files"] = result.config["top_files"]
        
        if "coverage" in result.config:
            summary["coverage"] = result.config["coverage"]
        
        if "llm_validation" in result.config:
            summary["llm_validation"] = result.config["llm_validation"]
        
        if "cve_enrichment" in result.config:
            summary["cve_enrichment"] = result.config["cve_enrichment"]
        
        return summary
