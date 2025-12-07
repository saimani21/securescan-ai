# Create all Phase 2 LLM files

# 1. Prompts template

"""Prompt templates for LLM validation and fix generation."""

from typing import Dict, Any, Optional


class PromptTemplates:
    """Centralized prompt templates for security analysis."""
    
    SYSTEM_VALIDATION = """You are a security expert analyzing code vulnerabilities.

Your task:
1. Determine if findings are real vulnerabilities or false positives
2. Provide confidence scores (0.0-1.0)
3. Explain reasoning concisely (2-3 sentences)
4. Assess real-world exploitability

Always respond in valid JSON format."""

    SYSTEM_FIX_GENERATION = """You are a security expert generating secure code fixes.

Your task:
1. Generate working, secure code that fixes the vulnerability
2. Maintain original functionality
3. Follow language-specific best practices
4. Add brief comments explaining security improvements

Always respond in valid JSON format."""

    @staticmethod
    def build_validation_prompt(
        finding: Dict[str, Any],
        context: Optional[str] = None
    ) -> str:
        """Build validation prompt for a finding."""
        language = finding.get("language", "unknown")
        code = finding.get("code_snippet", "")
        surrounding = context or finding.get("surrounding_code", "")
        
        return f"""Analyze this potential security vulnerability.

**Code Under Review:**

**Finding Details:**
- Rule: {finding.get('rule_id', 'unknown')}
- Type: {finding.get('cwe_id', 'unknown')}
- Severity: {finding.get('severity', 'MEDIUM')}
- File: {finding.get('file', 'unknown')}:{finding.get('line', 0)}

**Analysis Required:**
1. Is this a TRUE vulnerability or FALSE POSITIVE?
2. Can an attacker control the input?
3. What is the exploitability?

**Response Format (JSON only):**
{{
  "is_vulnerable": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "2-3 sentence explanation",
  "exploitability": "critical"/"high"/"medium"/"low"/"none",
  "attack_vector": "description" or null,
  "mitigation_priority": "immediate"/"high"/"medium"/"low" or null
}}"""

    @staticmethod
    def build_fix_prompt(
        finding: Dict[str, Any],
        validation: Optional[Any] = None
    ) -> str:
        """Build fix generation prompt."""
        language = finding.get("language", "python")
        vulnerable_code = finding.get("code_snippet", "")
        
        return f"""Generate a secure fix for this vulnerability.

**Vulnerable Code:**
**Vulnerability Type:**
{finding.get('cwe_id', 'Unknown')} - {finding.get('title', 'Security Issue')}

**Response Format (JSON only):**
{{
  "fixed_code": "complete secure code replacement",
  "explanation": "what was changed and why",
  "changes_summary": "bullet list of changes",
  "security_impact": "how this prevents the vulnerability",
  "references": ["URL1", "URL2"],
  "confidence": 0.0-1.0
}}"""