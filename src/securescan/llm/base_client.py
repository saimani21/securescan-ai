"""Abstract base class for LLM clients."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, Optional
from enum import Enum


class LLMProvider(Enum):
    """Supported LLM providers."""
    OPENAI = "openai"
    OLLAMA = "ollama"


@dataclass
class ValidationResult:
    """Result of LLM validation."""
    
    # Core validation
    is_vulnerable: bool
    confidence: float  # 0.0 - 1.0
    reasoning: str
    
    # Additional context
    exploitability: str  # "critical", "high", "medium", "low", "none"
    attack_vector: Optional[str] = None
    mitigation_priority: Optional[str] = None
    
    # Metadata
    model_used: str = "unknown"
    tokens_used: int = 0
    cost_usd: float = 0.0


@dataclass
class FixSuggestion:
    """AI-generated fix for a vulnerability."""
    
    # The fix
    fixed_code: str
    explanation: str
    
    # Context
    changes_summary: str
    security_impact: str
    references: list = None
    
    # Metadata
    confidence: float = 0.0
    model_used: str = "unknown"
    tokens_used: int = 0
    cost_usd: float = 0.0
    
    def __post_init__(self):
        if self.references is None:
            self.references = []


class BaseLLMClient(ABC):
    """
    Abstract base class for LLM clients.
    
    All LLM providers (OpenAI, Ollama, etc.) must implement this interface.
    """
    
    def __init__(self, model: str, timeout: int = 30):
        """
        Initialize LLM client.
        
        Args:
            model: Model name/identifier
            timeout: Request timeout in seconds
        """
        self.model = model
        self.timeout = timeout
        self.total_tokens = 0
        self.total_cost = 0.0
    
    @abstractmethod
    def validate_finding(
        self,
        finding: Dict[str, Any],
        context: Optional[str] = None
    ) -> ValidationResult:
        """
        Validate if a finding is a real vulnerability or false positive.
        
        Args:
            finding: Finding dictionary with code, file, severity, etc.
            context: Additional surrounding code for context
            
        Returns:
            ValidationResult with analysis
        """
        pass
    
    @abstractmethod
    def generate_fix(
        self,
        finding: Dict[str, Any],
        validation: Optional[ValidationResult] = None
    ) -> Optional[FixSuggestion]:
        """
        Generate a secure fix for a vulnerability.
        
        Args:
            finding: Finding dictionary
            validation: Optional validation result for context
            
        Returns:
            FixSuggestion or None if no fix available
        """
        pass
    
    @abstractmethod
    def estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """
        Estimate cost for token usage.
        
        Args:
            prompt_tokens: Input tokens
            completion_tokens: Output tokens
            
        Returns:
            Estimated cost in USD
        """
        pass
    
    def get_usage_stats(self) -> Dict[str, Any]:
        """Get usage statistics."""
        return {
            "total_tokens": self.total_tokens,
            "total_cost_usd": self.total_cost,
            "model": self.model,
        }
