"""Semgrep subprocess runner with improved rule detection."""

import subprocess
import json
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

from ..utils.logger import get_logger
from ..utils.exceptions import ScanError

logger = get_logger(__name__)


class SemgrepConfig(Enum):
    """Pre-defined Semgrep rule packs."""
    AUTO = "auto"
    SECURITY_AUDIT = "p/security-audit"
    PYTHON = "p/python"
    JAVASCRIPT = "p/javascript"
    COMMAND_INJECTION = "p/command-injection"
    SQL_INJECTION = "p/sql-injection"
    SECRETS = "p/secrets"
    OWASP = "p/owasp-top-ten"


@dataclass
class SemgrepFinding:
    """Standardized finding from Semgrep."""
    
    # Location
    id: str
    file: str
    line: int
    column: int
    end_line: int
    end_column: int
    code_snippet: str
    
    # Classification
    rule_id: str
    severity: str
    category: str
    cwe_id: Optional[str]
    
    # Content
    title: str
    description: str
    confidence: str
    
    # Metadata
    references: List[str]
    fix_suggestion: Optional[str]
    source: str = "semgrep"


class SemgrepRunner:
    """
    Run Semgrep security scanner via subprocess.
    
    Features:
    - Multiple rule packs
    - Configurable timeout
    - JSON output parsing
    - Enhanced detection
    """
    
    # More aggressive rule packs for better detection
    DEFAULT_CONFIGS = [
        "p/security-audit",
        "p/secrets",
        "p/owasp-top-ten",
        "p/command-injection",
        "p/sql-injection",
    ]
    
    DEFAULT_EXCLUDES = [
        "node_modules",
        ".git",
        "__pycache__",
        "*.min.js",
        "vendor",
        "dist",
        "build",
        ".venv",
        "venv",
        "test_*",  # Don't exclude our test files!
    ]
    
    def __init__(
        self,
        configs: Optional[List[str]] = None,
        timeout: int = 300,
        verify: bool = False
    ):
        """
        Initialize Semgrep runner.
        
        Args:
            configs: Rule configs to use (default: comprehensive set)
            timeout: Scan timeout in seconds (default: 300)
            verify: Verify Semgrep installation (can be slow in WSL)
        """
        self.configs = configs or self.DEFAULT_CONFIGS
        self.timeout = timeout
        
        # Optional verification
        if verify:
            self._verify_installation()
        else:
            logger.debug("Skipping Semgrep verification (verify=False)")
    
    def _verify_installation(self) -> None:
        """Verify Semgrep is installed and working."""
        if not shutil.which("semgrep"):
            raise ScanError(
                "Semgrep not found. Install with: pip install semgrep"
            )
        
        try:
            logger.info("Verifying Semgrep installation...")
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )
            
            if result.returncode == 0:
                version = result.stdout.strip()
                logger.info(f"Semgrep verified: {version}")
            else:
                logger.warning(
                    f"Semgrep verification returned code {result.returncode}, "
                    "but continuing anyway..."
                )
        
        except subprocess.TimeoutExpired:
            logger.warning(
                "Semgrep version check timed out (common in WSL). "
                "Continuing anyway - Semgrep should still work for scans."
            )
        
        except Exception as e:
            logger.warning(
                f"Semgrep verification failed: {e}. "
                "Continuing anyway - will fail later if Semgrep doesn't work."
            )
    
    def scan(
        self,
        target: Path,
        configs: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Run Semgrep scan on target.
        
        Args:
            target: Path to scan (file or directory)
            configs: Rule configs to use (overrides default)
            exclude: Additional exclude patterns
            
        Returns:
            Semgrep JSON output as dictionary
            
        Raises:
            ScanError: If scan fails
        """
        target = Path(target).resolve()
        
        if not target.exists():
            raise ScanError(f"Target does not exist: {target}")
        
        # Build command
        cmd = self._build_command(
            target=target,
            configs=configs or self.configs,
            exclude=exclude or [],
        )
        
        logger.info(f"Running Semgrep on {target}...")
        logger.debug(f"Command: {' '.join(cmd)}")
        logger.debug(f"Using configs: {', '.join(configs or self.configs)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            
            # Semgrep exit codes:
            # 0 = success (no findings)
            # 1 = success (findings found)
            # 2+ = error
            if result.returncode >= 2:
                logger.error(f"Semgrep stderr: {result.stderr[:500]}")
                raise ScanError(
                    f"Semgrep failed with exit code {result.returncode}\n"
                    f"Error: {result.stderr[:500]}"
                )
            
            # Parse JSON output
            try:
                output = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                logger.error(f"Semgrep stdout: {result.stdout[:500]}")
                raise ScanError(f"Failed to parse Semgrep JSON output: {e}")
            
            findings_count = len(output.get("results", []))
            logger.info(f"Semgrep found {findings_count} findings")
            
            # Debug: Show sample finding if any
            if findings_count > 0:
                sample = output["results"][0]
                logger.debug(f"Sample finding: {sample.get('check_id', 'unknown')}")
            
            return output
        
        except subprocess.TimeoutExpired:
            raise ScanError(f"Semgrep scan timed out after {self.timeout}s")
        
        except Exception as e:
            if isinstance(e, ScanError):
                raise
            raise ScanError(f"Semgrep scan failed: {e}")
    
    def _build_command(
        self,
        target: Path,
        configs: List[str],
        exclude: List[str],
    ) -> List[str]:
        """Build Semgrep CLI command."""
        cmd = [
            "semgrep",
            "--json",
            "--no-git-ignore",
            "--metrics=off",
            "--verbose",  # More verbose for debugging
        ]
        
        # Add rule configs
        for config in configs:
            cmd.extend(["--config", config])
        
        # Reduce excludes (don't exclude our test files!)
        minimal_excludes = [
            "node_modules",
            ".git",
            "__pycache__",
            "*.min.js",
        ]
        
        for pattern in minimal_excludes + exclude:
            cmd.extend(["--exclude", pattern])
        
        # Add target path
        cmd.append(str(target))
        
        return cmd
    
    def convert_findings(
        self,
        semgrep_output: Dict[str, Any]
    ) -> List[SemgrepFinding]:
        """Convert Semgrep JSON output to standardized findings."""
        findings = []
        
        for result in semgrep_output.get("results", []):
            try:
                finding = SemgrepFinding(
                    # Location
                    id=result.get("extra", {}).get("fingerprint", ""),
                    file=result.get("path", ""),
                    line=result.get("start", {}).get("line", 0),
                    column=result.get("start", {}).get("col", 0),
                    end_line=result.get("end", {}).get("line", 0),
                    end_column=result.get("end", {}).get("col", 0),
                    code_snippet=result.get("extra", {}).get("lines", ""),
                    
                    # Classification
                    rule_id=result.get("check_id", ""),
                    severity=self._map_severity(
                        result.get("extra", {}).get("severity", "WARNING")
                    ),
                    category=result.get("extra", {}).get("metadata", {}).get(
                        "category", "security"
                    ),
                    cwe_id=self._extract_cwe(result),
                    
                    # Content
                    title=result.get("extra", {}).get("message", ""),
                    description=self._extract_description(result),
                    confidence=result.get("extra", {}).get("metadata", {}).get(
                        "confidence", "MEDIUM"
                    ),
                    
                    # Metadata
                    references=result.get("extra", {}).get("metadata", {}).get(
                        "references", []
                    ),
                    fix_suggestion=result.get("extra", {}).get("fix"),
                )
                
                findings.append(finding)
            
            except Exception as e:
                logger.warning(f"Failed to parse Semgrep finding: {e}")
                continue
        
        return findings
    
    def _map_severity(self, semgrep_severity: str) -> str:
        """Map Semgrep severity to standard levels."""
        mapping = {
            "ERROR": "HIGH",
            "WARNING": "MEDIUM",
            "INFO": "LOW",
        }
        return mapping.get(semgrep_severity.upper(), "MEDIUM")
    
    def _extract_cwe(self, result: Dict) -> Optional[str]:
        """Extract CWE ID from Semgrep result metadata."""
        metadata = result.get("extra", {}).get("metadata", {})
        cwe = metadata.get("cwe")
        
        if cwe:
            if isinstance(cwe, list):
                return cwe[0] if cwe else None
            return str(cwe)
        
        return None
    
    def _extract_description(self, result: Dict) -> str:
        """Extract or build description from Semgrep result."""
        metadata = result.get("extra", {}).get("metadata", {})
        
        parts = []
        
        # Add message
        if "message" in result.get("extra", {}):
            parts.append(result["extra"]["message"])
        
        # Add metadata description if different
        if "description" in metadata:
            desc = metadata["description"]
            if desc and desc not in parts:
                parts.append(desc)
        
        return " ".join(parts) if parts else "No description"
    
    def to_dict_list(
        self,
        findings: List[SemgrepFinding]
    ) -> List[Dict[str, Any]]:
        """Convert SemgrepFinding objects to list of dictionaries."""
        return [
            {
                "id": f.id,
                "file": f.file,
                "line": f.line,
                "column": f.column,
                "end_line": f.end_line,
                "end_column": f.end_column,
                "code_snippet": f.code_snippet,
                "rule_id": f.rule_id,
                "severity": f.severity,
                "category": f.category,
                "cwe_id": f.cwe_id,
                "title": f.title,
                "description": f.description,
                "confidence": f.confidence,
                "references": f.references,
                "fix_suggestion": f.fix_suggestion,
                "source": f.source,
            }
            for f in findings
        ]
