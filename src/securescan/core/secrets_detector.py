
"""Advanced secrets detection to supplement Semgrep."""

import re
import math
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple
from collections import Counter

from ..utils.logger import get_logger

logger = get_logger(__name__)


class SecretsDetector:
    """
    Detect secrets using comprehensive regex patterns and entropy analysis.
    
    Complements Semgrep with:
    - Extended pattern library for major cloud providers and services
    - Entropy-based detection for unknown secret types
    - Smart filtering to reduce false positives
    """
    
    # Comprehensive secret patterns (research-based + industry standards)
    PATTERNS = [
        # === Cloud Provider Keys ===
        {
            "name": "AWS Access Key ID",
            "pattern": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}",
            "severity": "CRITICAL",
            "category": "cloud-credentials",
        },
        {
            "name": "AWS Secret Access Key",
            "pattern": r"(?i)aws(.{0,20})?(?:secret|password)(.{0,20})?['\"][0-9a-zA-Z/+=]{40}['\"]",
            "severity": "CRITICAL",
            "category": "cloud-credentials",
        },
        {
            "name": "Azure Client Secret",
            "pattern": r"(?i)(azure|az)(.{0,20})?client(.{0,20})?secret(.{0,20})?['\"][0-9a-zA-Z/+=~_\-]{32,}['\"]",
            "severity": "CRITICAL",
            "category": "cloud-credentials",
        },
        {
            "name": "Google Cloud API Key",
            "pattern": r"AIza[0-9A-Za-z\-_]{35}",
            "severity": "CRITICAL",
            "category": "cloud-credentials",
        },
        {
            "name": "Google OAuth Client Secret",
            "pattern": r"(?i)google(.{0,20})?['\"][0-9a-zA-Z\-_]{24}['\"]",
            "severity": "HIGH",
            "category": "cloud-credentials",
        },
        
        # === API Keys & Tokens ===
        {
            "name": "Generic API Key (High Confidence)",
            "pattern": r"(?i)(api[_-]?key|apikey|api[_-]?token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{32,})['\"]",
            "severity": "HIGH",
            "category": "api-keys",
        },
        {
            "name": "Stripe API Key",
            "pattern": r"(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}",
            "severity": "CRITICAL",
            "category": "payment",
        },
        {
            "name": "PayPal/Braintree Access Token",
            "pattern": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
            "severity": "CRITICAL",
            "category": "payment",
        },
        {
            "name": "Square Access Token",
            "pattern": r"sq0atp-[0-9A-Za-z\-_]{22}",
            "severity": "CRITICAL",
            "category": "payment",
        },
        {
            "name": "Square OAuth Secret",
            "pattern": r"sq0csp-[0-9A-Za-z\-_]{43}",
            "severity": "CRITICAL",
            "category": "payment",
        },
        {
            "name": "GitHub Personal Access Token",
            "pattern": r"ghp_[0-9a-zA-Z]{36}",
            "severity": "HIGH",
            "category": "vcs",
        },
        {
            "name": "GitHub OAuth Token",
            "pattern": r"gho_[0-9a-zA-Z]{36}",
            "severity": "HIGH",
            "category": "vcs",
        },
        {
            "name": "GitHub App Token",
            "pattern": r"(ghu|ghs)_[0-9a-zA-Z]{36}",
            "severity": "HIGH",
            "category": "vcs",
        },
        {
            "name": "GitLab Personal Access Token",
            "pattern": r"glpat-[0-9a-zA-Z\-_]{20}",
            "severity": "HIGH",
            "category": "vcs",
        },
        {
            "name": "Heroku API Key",
            "pattern": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            "severity": "HIGH",
            "category": "paas",
        },
        {
            "name": "Slack Token",
            "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}",
            "severity": "HIGH",
            "category": "collaboration",
        },
        {
            "name": "Slack Webhook",
            "pattern": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24,}",
            "severity": "MEDIUM",
            "category": "collaboration",
        },
        {
            "name": "Twilio API Key",
            "pattern": r"SK[0-9a-fA-F]{32}",
            "severity": "HIGH",
            "category": "communication",
        },
        {
            "name": "SendGrid API Key",
            "pattern": r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
            "severity": "HIGH",
            "category": "communication",
        },
        {
            "name": "Mailgun API Key",
            "pattern": r"key-[0-9a-zA-Z]{32}",
            "severity": "HIGH",
            "category": "communication",
        },
        {
            "name": "OpenAI API Key",
            "pattern": r"sk-[a-zA-Z0-9]{48}",
            "severity": "HIGH",
            "category": "ai",
        },
        {
            "name": "Anthropic API Key",
            "pattern": r"sk-ant-[a-zA-Z0-9\-_]{95}",
            "severity": "HIGH",
            "category": "ai",
        },
        
        # === Database Credentials ===
        {
            "name": "Generic Password (Hardcoded)",
            "pattern": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
            "severity": "MEDIUM",
            "category": "credentials",
        },
        {
            "name": "Database Connection String",
            "pattern": r"(?i)(mongodb|mysql|postgresql|postgres|redis)://[^\s]+:[^\s]+@[^\s]+",
            "severity": "HIGH",
            "category": "database",
        },
        {
            "name": "JDBC Connection String",
            "pattern": r"jdbc:[a-z]+://[^\s]+password=[^\s&]+",
            "severity": "HIGH",
            "category": "database",
        },
        
        # === Private Keys ===
        {
            "name": "RSA Private Key",
            "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
            "severity": "CRITICAL",
            "category": "private-key",
        },
        {
            "name": "SSH Private Key",
            "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
            "severity": "CRITICAL",
            "category": "private-key",
        },
        {
            "name": "PGP Private Key",
            "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "severity": "CRITICAL",
            "category": "private-key",
        },
        
        # === JWT Tokens ===
        {
            "name": "JSON Web Token (JWT)",
            "pattern": r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
            "severity": "MEDIUM",
            "category": "token",
        },
    ]
    
    # Entropy configuration
    DEFAULT_ENTROPY_THRESHOLD = 4.5
    MIN_ENTROPY_LENGTH = 20
    MAX_ENTROPY_LENGTH = 100  # Ignore very long strings (likely base64 encoded files)
    
    # Known false positive patterns to skip
    FALSE_POSITIVE_PATTERNS = [
        r"^[0-9]+$",  # Pure numbers
        r"^[a-f0-9]{32}$",  # MD5 hash
        r"^[a-f0-9]{40}$",  # SHA1 hash
        r"^[a-f0-9]{64}$",  # SHA256 hash
        r"^(true|false|null|undefined)$",  # Common literals
        r"^example",  # Example values
        r"^test",  # Test values
        r"^dummy",  # Dummy values
    ]
    
    def __init__(
        self,
        entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
        enable_entropy: bool = True,
    ) -> None:
        """
        Initialize secrets detector.
        
        Args:
            entropy_threshold: Minimum entropy for detection
            enable_entropy: Whether to use entropy-based detection
        """
        self.entropy_threshold = entropy_threshold
        self.enable_entropy = enable_entropy
        self._seen_findings: Set[str] = set()  # Deduplication
    
    def scan_directory(self, target: Path) -> List[Dict[str, Any]]:
        """
        Scan directory recursively for secrets.
        
        Args:
            target: Directory path
            
        Returns:
            List of findings (deduplicated)
        """
        target = Path(target).resolve()
        findings: List[Dict[str, Any]] = []
        self._seen_findings.clear()
        
        if not target.exists() or not target.is_dir():
            logger.warning(f"SecretsDetector: target is not a directory: {target}")
            return findings
        
        file_count = 0
        for filepath in target.rglob("*"):
            if filepath.is_file() and self._should_scan(filepath):
                findings.extend(self.scan_file(filepath))
                file_count += 1
        
        logger.info(
            f"Secrets detector scanned {file_count} files, "
            f"found {len(findings)} unique findings"
        )
        return findings
    
    def scan_file(self, filepath: Path) -> List[Dict[str, Any]]:
        """
        Scan single file for secrets.
        
        Args:
            filepath: File path
            
        Returns:
            List of findings (deduplicated within file)
        """
        findings: List[Dict[str, Any]] = []
        filepath = Path(filepath)
        
        try:
            content = filepath.read_text(errors="ignore")
        except Exception as e:
            logger.debug(f"SecretsDetector: failed to read {filepath}: {e}")
            return findings
        
        lines = content.splitlines()
        
        # Pattern-based detection
        for linenum, line in enumerate(lines, 1):
            for pattern_def in self.PATTERNS:
                for match in re.finditer(pattern_def["pattern"], line):
                    matched_text = match.group(0)
                    
                    # Skip false positives
                    if self._is_false_positive(matched_text):
                        continue
                    
                    finding = self._build_finding(
                        filepath=filepath,
                        linenum=linenum,
                        column=match.start(),
                        code=line.strip(),
                        matched_text=matched_text,
                        rule_suffix=pattern_def["name"],
                        severity=pattern_def["severity"],
                        category=pattern_def["category"],
                        description=f"Detected {pattern_def['name']} in source code.",
                    )
                    
                    # Deduplicate
                    finding_key = self._finding_key(finding)
                    if finding_key not in self._seen_findings:
                        self._seen_findings.add(finding_key)
                        findings.append(finding)
        
        # Entropy-based detection
        if self.enable_entropy:
            for linenum, line in enumerate(lines, 1):
                # Look for long alphanumeric strings
                for match in re.finditer(r"[A-Za-z0-9_/+=\-]{20,100}", line):
                    token = match.group(0)
                    
                    # Skip if too long or too short
                    if not (self.MIN_ENTROPY_LENGTH <= len(token) <= self.MAX_ENTROPY_LENGTH):
                        continue
                    
                    # Skip false positives
                    if self._is_false_positive(token):
                        continue
                    
                    entropy = self._calculate_entropy(token)
                    if entropy >= self.entropy_threshold:
                        finding = self._build_finding(
                            filepath=filepath,
                            linenum=linenum,
                            column=match.start(),
                            code=line.strip(),
                            matched_text=token,
                            rule_suffix="High Entropy String",
                            severity="MEDIUM",
                            category="entropy",
                            description=(
                                f"Detected high-entropy string (entropy: {entropy:.2f}). "
                                "May indicate hardcoded secret. Review manually."
                            ),
                        )
                        
                        finding_key = self._finding_key(finding)
                        if finding_key not in self._seen_findings:
                            self._seen_findings.add(finding_key)
                            findings.append(finding)
        
        return findings
    
    def _should_scan(self, filepath: Path) -> bool:
        """Check if file should be scanned."""
        # Skip binary and generated files
        skip_extensions = {
            ".lock", ".min.js", ".min.css", ".pyc", ".pyo", ".pyd",
            ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
            ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".rar", ".7z",
            ".exe", ".dll", ".so", ".dylib", ".app",
            ".mp3", ".mp4", ".avi", ".mov", ".mkv",
            ".woff", ".woff2", ".ttf", ".eot",
        }
        
        # Skip certain directories
        skip_dirs = {
            "node_modules", ".git", "__pycache__", "venv", ".venv",
            "dist", "build", "target", ".idea", ".vscode",
            "vendor", "bower_components", ".cache", ".pytest_cache",
            "coverage", "htmlcov", ".mypy_cache", ".tox",
        }
        
        if filepath.suffix.lower() in skip_extensions:
            return False
        
        for part in filepath.parts:
            if part in skip_dirs:
                return False
        
        # Skip very large files (> 1MB)
        try:
            if filepath.stat().st_size > 1_000_000:
                logger.debug(f"Skipping large file: {filepath}")
                return False
        except OSError:
            return False
        
        return True
    
    def _is_false_positive(self, text: str) -> bool:
        """Check if text matches known false positive patterns."""
        text_lower = text.lower()
        
        for pattern in self.FALSE_POSITIVE_PATTERNS:
            if re.match(pattern, text_lower):
                return True
        
        return False
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        
        counter = Counter(data)
        length = len(data)
        entropy = 0.0
        
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _finding_key(self, finding: Dict[str, Any]) -> str:
        """Generate unique key for deduplication."""
        return f"{finding['file']}:{finding['line']}:{finding['rule_id']}"
    
    def _build_finding(
        self,
        filepath: Path,
        linenum: int,
        column: int,
        code: str,
        matched_text: str,
        rule_suffix: str,
        severity: str,
        category: str,
        description: str,
    ) -> Dict[str, Any]:
        """Build standardized finding dictionary."""
        # Redact actual secret value in output
        redacted_code = code.replace(matched_text, "[REDACTED]")
        
        return {
            "id": f"{filepath}:{linenum}:{column}:{rule_suffix.replace(' ', '_')}",
            "file": str(filepath),
            "line": linenum,
            "column": column,
            "end_line": linenum,
            "end_column": column + len(code),
            "code_snippet": redacted_code,  # Redacted for security
            "surrounding_code": redacted_code,
            "rule_id": f"secrets-{category}-{rule_suffix.lower().replace(' ', '-')}",
            "severity": severity,
            "category": f"secrets/{category}",
            "cwe_id": "CWE-798",  # Use of Hard-coded Credentials
            "title": f"Possible {rule_suffix}",
            "description": description,
            "confidence": "HIGH" if category != "entropy" else "MEDIUM",
            "references": [
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                "https://cwe.mitre.org/data/definitions/798.html",
            ],
            "semgrep_fix": None,
            "source": "secretsdetector",
            "language": self._detect_language(filepath),
        }
    
    def _detect_language(self, filepath: Path) -> str:
        """Detect programming language from file extension."""
        extension_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".java": "java",
            ".go": "go",
            ".rb": "ruby",
            ".php": "php",
            ".cs": "csharp",
            ".cpp": "cpp",
            ".c": "c",
            ".rs": "rust",
            ".kt": "kotlin",
            ".swift": "swift",
            ".yaml": "yaml",
            ".yml": "yaml",
            ".json": "json",
            ".xml": "xml",
            ".sh": "bash",
            ".env": "env",
            ".config": "config",
        }
        return extension_map.get(filepath.suffix.lower(), "unknown")

