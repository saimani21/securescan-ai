
"""Validator engine for processing findings with LLM."""

from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from .base_client import BaseLLMClient, ValidationResult
from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ValidationStats:
    """Statistics for validation run."""
    total_findings: int = 0
    validated: int = 0
    confirmed_vulnerable: int = 0
    false_positives: int = 0
    avg_confidence: float = 0.0
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    failed: int = 0


class Validator:
    """Orchestrates LLM validation of security findings."""
    
    def __init__(
        self,
        llm_client: BaseLLMClient,
        confidence_threshold: float = 0.7,
        max_workers: int = 3
    ):
        """Initialize validator."""
        self.llm_client = llm_client
        self.confidence_threshold = confidence_threshold
        self.max_workers = max_workers
        self.stats = ValidationStats()
    
    def validate_findings(
        self,
        findings: List[Dict[str, Any]],
        show_progress: bool = True
    ) -> List[Dict[str, Any]]:
        """Validate list of findings."""
        if not findings:
            logger.info("No findings to validate")
            return []
        
        self.stats.total_findings = len(findings)
        
        if show_progress:
            logger.info(f"Validating {len(findings)} findings with LLM...")
        
        # Process findings in parallel
        validated_findings = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [
                executor.submit(self._validate_single, finding, i, len(findings))
                for i, finding in enumerate(findings, 1)
            ]
            
            for future in futures:
                try:
                    validated_finding = future.result()
                    validated_findings.append(validated_finding)
                    self.stats.validated += 1
                except Exception as e:
                    logger.error(f"Validation failed: {e}")
                    self.stats.failed += 1
        
        # Compute statistics
        self._compute_stats(validated_findings)
        
        # Filter by confidence threshold
        filtered = self._filter_by_confidence(validated_findings)
        
        if show_progress:
            logger.info(
                f"Validation complete: {self.stats.confirmed_vulnerable} confirmed, "
                f"{self.stats.false_positives} false positives"
            )
        
        return filtered
    
    def _validate_single(
        self,
        finding: Dict[str, Any],
        index: int,
        total: int
    ) -> Dict[str, Any]:
        """Validate a single finding."""
        logger.debug(f"Validating {index}/{total}: {finding.get('title', 'Unknown')}")
        
        try:
            # Call LLM
            validation = self.llm_client.validate_finding(finding)
            
            # Enrich finding
            finding["llm_validated"] = True
            finding["llm_is_vulnerable"] = validation.is_vulnerable
            finding["llm_confidence"] = validation.confidence
            finding["llm_reasoning"] = validation.reasoning
            finding["llm_exploitability"] = validation.exploitability
            finding["llm_attack_vector"] = validation.attack_vector
            finding["llm_model"] = validation.model_used
            finding["llm_tokens"] = validation.tokens_used
            finding["llm_cost"] = validation.cost_usd
            
            # Update stats
            self.stats.total_tokens += validation.tokens_used
            self.stats.total_cost_usd += validation.cost_usd
            
            if validation.is_vulnerable:
                self.stats.confirmed_vulnerable += 1
            else:
                self.stats.false_positives += 1
        
        except Exception as e:
            logger.error(f"Failed to validate finding: {e}")
            finding["llm_validated"] = False
            finding["llm_error"] = str(e)
        
        return finding
    
    def _compute_stats(self, findings: List[Dict[str, Any]]) -> None:
        """Compute validation statistics."""
        validated = [f for f in findings if f.get("llm_validated")]
        
        if validated:
            confidences = [f.get("llm_confidence", 0.0) for f in validated]
            self.stats.avg_confidence = sum(confidences) / len(confidences)
    
    def _filter_by_confidence(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Filter findings by confidence threshold."""
        filtered = []
        
        for finding in findings:
            if not finding.get("llm_validated"):
                # Keep unvalidated findings (fail-open)
                filtered.append(finding)
                continue
            
            is_vulnerable = finding.get("llm_is_vulnerable", True)
            confidence = finding.get("llm_confidence", 0.0)
            
            if is_vulnerable and confidence >= self.confidence_threshold:
                filtered.append(finding)
            else:
                logger.debug(
                    f"Filtered out: {finding.get('title')} "
                    f"(confidence: {confidence:.2f})"
                )
        
        return filtered
    
    def get_stats(self) -> ValidationStats:
        """Get validation statistics."""
        return self.stats

