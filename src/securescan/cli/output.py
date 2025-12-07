"""Enhanced output formatting for CLI."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from rich.syntax import Syntax
from rich.tree import Tree
from pathlib import Path
from typing import List, Dict, Any

console = Console()


def display_banner(version: str):
    """Display application banner."""
    banner = f"""
[bold cyan]
  ____                          ____                  
 / ___|  ___  ___ _   _ _ __ ___/ ___|  ___ __ _ _ __  
 \___ \ / _ \/ __| | | | '__/ _ \___ \ / __/ _` | '_ \ 
  ___) |  __/ (__| |_| | | |  __/___) | (_| (_| | | | |
 |____/ \___|\___|\__,_|_|  \___|____/ \___\__,_|_| |_|
[/bold cyan]
[bold white]AI-Powered Security Scanner[/bold white] [dim]v{version}[/dim]
    """
    console.print(Panel(banner, border_style="cyan", padding=(0, 2)))


def display_scan_config(config: Dict[str, Any]):
    """Display scan configuration."""
    table = Table(title="Scan Configuration", show_header=True, box=None)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="yellow")
    
    table.add_row("Target", str(config.get("target", ".")))
    table.add_row("Severity", ", ".join(config.get("severity_filter", ["ALL"])))
    
    if config.get("enable_llm"):
        table.add_row("AI Validation", f"✅ {config['llm_provider']}/{config['llm_model']}")
    else:
        table.add_row("AI Validation", "❌ Disabled")
    
    if config.get("enable_cve"):
        table.add_row("CVE Enrichment", "✅ Enabled")
    else:
        table.add_row("CVE Enrichment", "❌ Disabled")
    
    console.print(table)
    console.print()


def create_progress_bar(description: str = "Scanning..."):
    """Create rich progress bar."""
    return Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    )


def display_findings_tree(findings: List[Dict[str, Any]], max_display: int = 10):
    """Display findings as tree structure."""
    tree = Tree("🔍 Security Findings")
    
    # Group by severity
    by_severity = {}
    for finding in findings:
        severity = finding.get("severity", "UNKNOWN")
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(finding)
    
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    severity_icons = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵",
        "INFO": "⚪"
    }
    
    for severity in severity_order:
        if severity not in by_severity:
            continue
        
        findings_list = by_severity[severity]
        icon = severity_icons.get(severity, "⚪")
        
        severity_branch = tree.add(f"{icon} [bold]{severity}[/bold] ({len(findings_list)})")
        
        for finding in findings_list[:max_display]:
            title = finding.get("title", "Unknown")[:60]
            file_name = Path(finding.get("file", "")).name
            line = finding.get("line", 0)
            
            severity_branch.add(f"{title}\n[dim]{file_name}:{line}[/dim]")
    
    console.print(tree)


def display_summary_panel(result):
    """Display scan summary panel."""
    lines = []
    
    # Basic stats
    lines.append(f"[bold]Scan ID:[/bold] {result.scan_id}")
    lines.append(f"[bold]Duration:[/bold] {result.duration_seconds:.2f}s")
    lines.append(f"[bold]Files:[/bold] {result.files_scanned}")
    lines.append(f"[bold]Findings:[/bold] {result.total_findings}")
    
    # Severity breakdown
    if result.total_findings > 0:
        lines.append("")
        lines.append("[bold]By Severity:[/bold]")
        for severity, count in result.findings_by_severity.items():
            if count > 0:
                lines.append(f"  {severity}: {count}")
    
    # AI stats
    if "llm_validation" in result.config:
        llm = result.config["llm_validation"]
        lines.append("")
        lines.append("[bold]AI Validation:[/bold]")
        lines.append(f"  Confirmed: {llm['confirmed_vulnerable']}")
        lines.append(f"  False Positives: {llm['false_positives']}")
        lines.append(f"  Cost: ${llm['total_cost_usd']:.4f}")
    
    # CVE stats
    if "cve_enrichment" in result.config and "error" not in result.config["cve_enrichment"]:
        cve = result.config["cve_enrichment"]
        lines.append("")
        lines.append("[bold]CVE Intelligence:[/bold]")
        lines.append(f"  Enriched: {cve['enriched_findings']}")
        lines.append(f"  CVEs: {cve['total_cves_found']}")
        lines.append(f"  Avg CVSS: {cve.get('avg_cvss', 0):.1f}")
    
    summary = "\n".join(lines)
    
    if result.total_findings == 0:
        console.print(Panel(summary, title="✅ Scan Complete - No Issues", 
                          border_style="green"))
    elif result.findings_by_severity.get("CRITICAL", 0) > 0:
        console.print(Panel(summary, title="⚠️  Scan Complete - Critical Issues Found", 
                          border_style="red"))
    else:
        console.print(Panel(summary, title="⚠️  Scan Complete - Issues Found", 
                          border_style="yellow"))
