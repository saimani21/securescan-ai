"""Enhanced output formatters with CVE enrichment."""

from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()


def format_enriched_finding(finding: Dict[str, Any]) -> Panel:
    """Format a single enriched finding with CVE data."""
    
    # Basic info
    title = f"[{finding['severity']}] {finding['title']}"
    location = f"{finding['file']}:{finding['line']}"
    
    lines = [
        f"📁 [dim]{location}[/dim]",
        "",
    ]
    
    # Description
    if finding.get("description"):
        lines.append(finding["description"][:150])
        lines.append("")
    
    # LLM Analysis
    if finding.get("llm_validated"):
        confidence = finding.get("llm_confidence", 0)
        is_vuln = finding.get("llm_is_vulnerable")
        
        status = "✅ Confirmed" if is_vuln else "❌ False Positive"
        lines.append(f"🤖 AI Analysis: {status} (confidence: {confidence:.0%})")
        
        if finding.get("llm_reasoning"):
            lines.append(f"   {finding['llm_reasoning'][:100]}...")
        lines.append("")
    
    # CVE Enrichment
    if finding.get("cve_enriched"):
        lines.append("📋 [bold]CVE Intelligence:[/bold]")
        lines.append(f"   Related CVEs: {finding['cve_count']}")
        
        if finding.get("avg_cvss"):
            lines.append(f"   Avg CVSS: {finding['avg_cvss']:.1f}/10")
            lines.append(f"   Max CVSS: {finding['max_cvss']:.1f}/10")
        
        # Threat intelligence
        if finding.get("cisa_kev"):
            kev_count = len(finding.get("cisa_kev_cves", []))
            lines.append(f"   🚨 [bold red]CISA KEV: {kev_count} CVE(s) actively exploited![/bold red]")
        
        if finding.get("exploit_available"):
            exploit_count = finding.get("exploit_count", 0)
            lines.append(f"   💥 Public exploits: {exploit_count} available")
        
        threat_level = finding.get("threat_level", "UNKNOWN")
        threat_colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
        }
        color = threat_colors.get(threat_level, "white")
        lines.append(f"   🎯 Threat Level: [{color}]{threat_level}[/{color}]")
        
        # Top CVEs
        if finding.get("related_cves"):
            lines.append("")
            lines.append("   [dim]Top CVEs:[/dim]")
            for i, cve in enumerate(finding["related_cves"][:3], 1):
                cvss = cve.get("cvss_score", "N/A")
                lines.append(f"   {i}. {cve['cve_id']} (CVSS: {cvss})")
    
    content = "\n".join(lines)
    
    # Color by severity
    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "cyan",
    }
    
    border_color = severity_colors.get(finding["severity"], "white")
    
    return Panel(
        content,
        title=title,
        border_style=border_color,
        padding=(1, 2),
    )


def print_enrichment_summary(stats: Dict[str, Any]) -> None:
    """Print CVE enrichment summary."""
    
    console.print("\n[bold cyan]📊 CVE Enrichment Summary[/bold cyan]")
    
    table = Table(show_header=False, box=None)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Total Findings", str(stats['total_findings']))
    table.add_row("Enriched", str(stats['enriched_findings']))
    table.add_row("Enrichment Rate", f"{stats['enrichment_rate']*100:.1f}%")
    table.add_row("Total CVEs Found", str(stats['total_cves_found']))
    table.add_row("In CISA KEV", f"[bold red]{stats['findings_in_cisa_kev']}[/bold red]" if stats['findings_in_cisa_kev'] > 0 else "0")
    table.add_row("With Exploits", f"[yellow]{stats['findings_with_exploits']}[/yellow]" if stats['findings_with_exploits'] > 0 else "0")
    
    if stats.get('avg_cvss'):
        table.add_row("Avg CVSS Score", f"{stats['avg_cvss']:.1f}/10")
        table.add_row("Max CVSS Score", f"{stats['max_cvss']:.1f}/10")
    
    console.print(table)
    
    # Threat level breakdown
    threat_levels = stats.get('threat_levels', {})
    if any(threat_levels.values()):
        console.print("\n[bold]Threat Levels:[/bold]")
        for level, count in threat_levels.items():
            if count > 0:
                colors = {
                    "CRITICAL": "bold red",
                    "HIGH": "red",
                    "MEDIUM": "yellow",
                    "LOW": "green",
                }
                color = colors.get(level, "white")
                console.print(f"  [{color}]●[/{color}] {level}: {count}")
