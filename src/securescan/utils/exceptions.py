"""Enhanced exception hierarchy with detailed error handling."""

from typing import Optional, Dict, Any


class SecureScanError(Exception):
    """Base exception for all SecureScan errors."""
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        suggestion: Optional[str] = None
    ):
        """
        Initialize exception with context.
        
        Args:
            message: Error message
            details: Additional error details
            suggestion: Suggested fix for the user
        """
        self.message = message
        self.details = details or {}
        self.suggestion = suggestion
        super().__init__(self.format_message())
    
    def format_message(self) -> str:
        """Format complete error message."""
        parts = [self.message]
        
        if self.details:
            parts.append("\nDetails:")
            for key, value in self.details.items():
                parts.append(f"  {key}: {value}")
        
        if self.suggestion:
            parts.append(f"\n💡 Suggestion: {self.suggestion}")
        
        return "\n".join(parts)


# Scan errors
class ScanError(SecureScanError):
    """Error during scanning operation."""
    pass


class ScanTimeoutError(ScanError):
    """Scan operation timed out."""
    pass


class InvalidTargetError(ScanError):
    """Invalid scan target."""
    pass


# Configuration errors
class ConfigError(SecureScanError):
    """Configuration-related error."""
    pass


class InvalidConfigError(ConfigError):
    """Invalid configuration value."""
    pass


class MissingConfigError(ConfigError):
    """Required configuration is missing."""
    pass


# LLM errors
class LLMError(SecureScanError):
    """LLM operation error."""
    pass


class LLMAPIError(LLMError):
    """LLM API call failed."""
    pass


class LLMAuthError(LLMError):
    """LLM authentication failed."""
    pass


class LLMRateLimitError(LLMError):
    """LLM rate limit exceeded."""
    pass


# CVE enrichment errors
class EnrichmentError(SecureScanError):
    """CVE enrichment error."""
    pass


class NVDAPIError(EnrichmentError):
    """NVD API error."""
    pass


class CISAKEVError(EnrichmentError):
    """CISA KEV data error."""
    pass


# Output errors
class OutputError(SecureScanError):
    """Output generation error."""
    pass


class SARIFError(OutputError):
    """SARIF generation error."""
    pass


class ReportError(OutputError):
    """Report generation error."""
    pass

# === LLM Validation Errors ===
class ValidationError(LLMError):
    """Validation operation failed."""
    pass
