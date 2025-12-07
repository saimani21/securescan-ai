


"""OpenAI GPT-4 client for validation and fix generation."""

import os
import json
from typing import Dict, Any, Optional

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

from .base_client import BaseLLMClient, ValidationResult, FixSuggestion
from ..utils.logger import get_logger
from ..utils.exceptions import ValidationError

logger = get_logger(__name__)


class OpenAIClient(BaseLLMClient):
    """OpenAI GPT-4 client for security analysis."""
    
    # Token pricing (as of 2024)
    PRICING = {
        "gpt-4": {"input": 0.03 / 1000, "output": 0.06 / 1000},
        "gpt-4-turbo": {"input": 0.01 / 1000, "output": 0.03 / 1000},
        "gpt-4o": {"input": 0.005 / 1000, "output": 0.015 / 1000},
        "gpt-3.5-turbo": {"input": 0.0005 / 1000, "output": 0.0015 / 1000},
    }
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-4o-mini",
        timeout: int = 30
    ):
        """
        Initialize OpenAI client.
        
        Args:
            api_key: OpenAI API key (reads from OPENAI_API_KEY env if None)
            model: Model to use (default: gpt-4o - best cost/performance)
            timeout: Request timeout
        """
        super().__init__(model=model, timeout=timeout)
        
        if OpenAI is None:
            raise ValidationError(
                "OpenAI library not installed. Install with: pip install openai"
            )
        
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValidationError(
                "OpenAI API key not found. Set OPENAI_API_KEY environment variable."
            )
        
        self.client = OpenAI(api_key=self.api_key, timeout=timeout)
        logger.info(f"OpenAI client initialized with model: {model}")
    
    def validate_finding(
        self,
        finding: Dict[str, Any],
        context: Optional[str] = None
    ) -> ValidationResult:
        """
        Validate finding using GPT-4.
        
        Uses structured prompting for high accuracy.
        """
        prompt = self._build_validation_prompt(finding, context)
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a security expert analyzing code vulnerabilities. "
                            "Provide accurate, concise analysis in JSON format."
                        )
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                response_format={"type": "json_object"},
                temperature=0.1,  # Low temperature for consistent analysis
            )
            
            # Parse response
            result_text = response.choices[0].message.content
            result_data = json.loads(result_text)
            
            # Track usage
            tokens_used = response.usage.total_tokens
            cost = self.estimate_cost(
                response.usage.prompt_tokens,
                response.usage.completion_tokens
            )
            self.total_tokens += tokens_used
            self.total_cost += cost
            
            # Build result
            return ValidationResult(
                is_vulnerable=result_data.get("is_vulnerable", False),
                confidence=result_data.get("confidence", 0.0),
                reasoning=result_data.get("reasoning", "No reasoning provided"),
                exploitability=result_data.get("exploitability", "unknown"),
                attack_vector=result_data.get("attack_vector"),
                mitigation_priority=result_data.get("mitigation_priority"),
                model_used=self.model,
                tokens_used=tokens_used,
                cost_usd=cost,
            )
        
        except Exception as e:
            logger.error(f"OpenAI validation failed: {e}")
            # Return safe default
            return ValidationResult(
                is_vulnerable=True,  # Err on the side of caution
                confidence=0.5,
                reasoning=f"Validation failed: {str(e)}",
                exploitability="unknown",
                model_used=self.model,
            )
    
    def generate_fix(
        self,
        finding: Dict[str, Any],
        validation: Optional[ValidationResult] = None
    ) -> Optional[FixSuggestion]:
        """Generate secure fix using GPT-4."""
        
        # Only generate fix if vulnerability is confirmed
        if validation and not validation.is_vulnerable:
            logger.info("Skipping fix generation for false positive")
            return None
        
        prompt = self._build_fix_prompt(finding, validation)
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a security expert generating secure code fixes. "
                            "Provide working, secure code in JSON format."
                        )
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                response_format={"type": "json_object"},
                temperature=0.2,
            )
            
            result_text = response.choices[0].message.content
            result_data = json.loads(result_text)
            
            # Track usage
            tokens_used = response.usage.total_tokens
            cost = self.estimate_cost(
                response.usage.prompt_tokens,
                response.usage.completion_tokens
            )
            self.total_tokens += tokens_used
            self.total_cost += cost
            
            return FixSuggestion(
                fixed_code=result_data.get("fixed_code", ""),
                explanation=result_data.get("explanation", ""),
                changes_summary=result_data.get("changes_summary", ""),
                security_impact=result_data.get("security_impact", ""),
                references=result_data.get("references", []),
                confidence=result_data.get("confidence", 0.8),
                model_used=self.model,
                tokens_used=tokens_used,
                cost_usd=cost,
            )
        
        except Exception as e:
            logger.error(f"Fix generation failed: {e}")
            return None
    
    def estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """Estimate cost based on token usage."""
        pricing = self.PRICING.get(self.model, self.PRICING["gpt-4o"])
        cost = (
            prompt_tokens * pricing["input"] +
            completion_tokens * pricing["output"]
        )
        return cost
    
    def _build_validation_prompt(
        self,
        finding: Dict[str, Any],
        context: Optional[str]
    ) -> str:
        """Build validation prompt."""
        language = finding.get("language", "unknown")
        code = finding.get("code_snippet", "")
        surrounding = context or finding.get("surrounding_code", "")
        
        return f"""Analyze this potential security vulnerability for false positives.

**Code Under Review:**
**Surrounding Context (±10 lines):**
**Finding Details:**
- Rule: {finding.get('rule_id', 'unknown')}
- Type: {finding.get('cwe_id', 'unknown')} - {finding.get('category', 'unknown')}
- Severity: {finding.get('severity', 'MEDIUM')}
- File: {finding.get('file', 'unknown')}:{finding.get('line', 0)}

**Analysis Questions:**
1. Is this a TRUE vulnerability or FALSE POSITIVE?
2. Can an attacker realistically control the input?
3. Are there sanitization/validation steps not visible in the snippet?
4. What is the real-world exploitability?

**Response Format (JSON only):**
{{
  "is_vulnerable": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "2-3 sentence explanation of your analysis",
  "exploitability": "critical"/"high"/"medium"/"low"/"none",
  "attack_vector": "brief description of attack" or null,
  "mitigation_priority": "immediate"/"high"/"medium"/"low" or null
}}"""
    
    def _build_fix_prompt(
        self,
        finding: Dict[str, Any],
        validation: Optional[ValidationResult]
    ) -> str:
        """Build fix generation prompt."""
        language = finding.get("language", "python")
        vulnerable_code = finding.get("code_snippet", "")
        
        validation_context = ""
        if validation:
            validation_context = f"""
**AI Analysis:**
- Confirmed Vulnerability: {validation.is_vulnerable}
- Confidence: {validation.confidence:.2f}
- Exploitability: {validation.exploitability}
- Reasoning: {validation.reasoning}
"""
        
        return f"""Generate a secure fix for this vulnerability.

**Vulnerable Code:**

**Vulnerability Type:**
{finding.get('cwe_id', 'Unknown')} - {finding.get('title', 'Security Issue')}

{validation_context}

**Requirements:**
1. Maintain original functionality
2. Follow {language} security best practices
3. Use standard library functions
4. Add brief inline comments explaining security improvements

**Response Format (JSON only):**
{{
  "fixed_code": "complete secure code replacement",
  "explanation": "what was changed and why (2-3 sentences)",
  "changes_summary": "bullet list of specific changes",
  "security_impact": "how this prevents the vulnerability",
  "references": ["URL1", "URL2"],
  "confidence": 0.0-1.0
}}"""

