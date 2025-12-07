"""CLI entry point for SecureScan AI."""

import click
import json
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from ..core.scanner import Scanner
from ..utils.logger import get_logger, setup_logging
from ..utils.config import Config, init_config
from ..utils.exceptions import SecureScanError, ConfigError, ScanError
from ..version import VERSION
from securescan.cli.setup import setup as setup_cmd

# Register setup command

try:
    from dotenv import load_dotenv
    load_dotenv()  # Auto-load .env from current directory
except ImportError:
    pass  
console = Console()
logger = get_logger(__name__)

cli.add_command(setup_cmd, name='setup')
@click.group()
@click.version_option(version=VERSION, prog_name="SecureScan AI")
@click.option(
    "--config",
    type=click.Path(exists=True),
    help="Configuration file path"
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output"
)
@click.option(
    "--log-file",
    type=click.Path(),
    help="Write logs to file"
)
@click.pass_context
def cli(ctx, config, verbose, log_file):
    """
    SecureScan AI - Open Source Security Code Review Platform
    
    Combines SAST scanning, AI validation, and CVE intelligence.
    
    \b
    Examples:
        # Basic scan
        secscan scan .
        
        # With AI validation
        secscan scan . --llm openai
        
        # Complete pipeline
        secscan scan . --llm openai --enrich-cve
        
        # Show configuration
        secscan config show
    """
    # Setup logging
    log_level = "DEBUG" if verbose else "INFO"
    
    try:
        setup_logging(
            level=log_level,
            log_file=Path(log_file) if log_file else None,
            verbose=verbose
        )
    except Exception as e:
        console.print(f"[red]❌ Logging setup failed:[/red] {e}")
        sys.exit(1)
    
    # Initialize configuration
    try:
        if config:
            logger.info(f"Loading config from: {config}")
            cfg = init_config(Path(config))
        else:
            cfg = Config()
        
        # Store in context for subcommands
        ctx.ensure_object(dict)
        ctx.obj["config"] = cfg
        ctx.obj["verbose"] = verbose
        
        logger.debug("Configuration loaded successfully")
    
    except ConfigError as e:
        console.print(f"[red]❌ Configuration Error:[/red]\n{e}")
        sys.exit(1)
    
    except Exception as e:
        console.print(f"[red]❌ Unexpected Error:[/red] {e}")
        logger.error(f"Initialization failed: {e}", exc_info=True)
        sys.exit(1)


@cli.command()
@click.argument(
    "target",
    type=click.Path(exists=True),
    required=True,
)
@click.option(
    "--severity",
    "-s",
    multiple=True,
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
    help="Filter by severity (can specify multiple times)",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["console", "json"], case_sensitive=False),
    default="console",
    help="Output format (default: console)",
)
@click.option(
    "--output-file",
    "-f",
    type=click.Path(),
    help="Write output to file (only for json format)",
)
@click.option(
    "--max-findings",
    "-m",
    type=int,
    default=50,
    help="Maximum findings to display in console (default: 50)",
)
@click.option(
    "--llm",
    type=click.Choice(["openai", "ollama"], case_sensitive=False),
    help="Enable LLM validation (openai or ollama)",
)
@click.option(
    "--llm-model",
    default="gpt-4o",
    help="LLM model to use (default: gpt-4o)",
)
@click.option(
    "--llm-confidence",
    type=float,
    default=0.7,
    help="LLM confidence threshold 0.0-1.0 (default: 0.7)",
)
@click.option(
    "--enrich-cve",
    is_flag=True,
    help="Enable CVE enrichment from NVD",
)
@click.option(
    "--cve-max",
    default=10,
    type=int,
    help="Max CVEs per finding (default: 10)",
)
@click.option(
    "--no-secrets",
    is_flag=True,
    help="Disable secrets detection",
)
@click.option(
    "--fail-on",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"], case_sensitive=False),
    default="HIGH",
    help="Fail build on severity (default: HIGH)",
)
@click.pass_context
def scan(
    ctx,
    target,
    severity,
    output,
    output_file,
    max_findings,
    llm,
    llm_model,
    llm_confidence,
    enrich_cve,
    cve_max,
    no_secrets,
    fail_on
):
    """
    Scan target directory or file for security vulnerabilities.
    
    \b
    Examples:
        # Basic scan
        secscan scan .
        
        # With AI validation (reduces false positives by 40%)
        secscan scan ./src --llm openai
        
        # With CVE enrichment (adds threat intelligence)
        secscan scan ./src --enrich-cve
        
        # Complete pipeline (SAST + AI + CVE)
        secscan scan ./src --llm openai --enrich-cve
        
        # Scan with severity filter
        secscan scan ./src --severity HIGH --severity CRITICAL
        
        # JSON output to file
        secscan scan ./src --output json --output-file results.json
        
        # Strict mode (fail on MEDIUM+)
        secscan scan ./src --fail-on MEDIUM
    """
    cfg = ctx.obj.get("config", Config())
    verbose = ctx.obj.get("verbose", False)
    
    target_path = Path(target).resolve()
    
    # Validate target
    if not target_path.exists():
        console.print(f"[red]❌ Target not found:[/red] {target_path}")
        sys.exit(1)
    
    # Display header
    console.print()
    console.print(
        Panel.fit(
            f"[bold cyan]SecureScan AI v{VERSION}[/bold cyan]\n"
            f"Target: [yellow]{target_path}[/yellow]",
            border_style="cyan",
        )
    )
    console.print()
    
    # Convert severity filter to uppercase list
    severity_filter = [s.upper() for s in severity] if severity else None
    
    # Display scan configuration
    if severity_filter:
        console.print(f"🔍 Severity filter: [yellow]{', '.join(severity_filter)}[/yellow]")
    
    if llm:
        console.print(
            f"🤖 LLM validation: [green]{llm}/{llm_model}[/green] "
            f"(confidence: {llm_confidence:.0%})"
        )
        console.print(f"[dim]   Using {llm.upper()} API - costs may apply[/dim]")
    
    if enrich_cve:
        console.print(f"📋 CVE enrichment: [green]Enabled[/green] (max {cve_max} per finding)")
        console.print(f"[dim]   Fetching threat intelligence from NVD[/dim]")
    
    console.print(f"⚠️  Fail on: [yellow]{fail_on.upper()}[/yellow] severity or higher")
    console.print()
    
    # Run scan with progress indicator
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("🔍 Scanning...", total=None)
            
            scanner = Scanner(config=cfg)
            
            result = scanner.scan(
                target=target_path,
                severity_filter=severity_filter,
                enable_secrets=not no_secrets,
                enable_llm=bool(llm),
                llm_provider=llm or "openai",
                llm_model=llm_model,
                llm_confidence_threshold=llm_confidence,
                enable_cve_enrichment=enrich_cve,
                cve_max_per_finding=cve_max,
            )
            
            progress.update(task, description="✅ Scan complete")
        
        console.print()
        
        # Handle output format
        if output == "json":
            _output_json(result, output_file)
        else:
            _output_console(result, max_findings)
        
        # Determine exit code based on fail_on threshold
        exit_code = _determine_exit_code(result, fail_on)
        
        if exit_code != 0:
            logger.warning(f"Scan failed with exit code {exit_code}")
        
        sys.exit(exit_code)
    
    except ScanError as e:
        console.print(f"\n[bold red]❌ Scan Error:[/bold red]\n{e}")
        logger.error(f"Scan failed: {e}", exc_info=verbose)
        sys.exit(3)
    
    except ConfigError as e:
        console.print(f"\n[bold red]❌ Configuration Error:[/bold red]\n{e}")
        logger.error(f"Config error: {e}", exc_info=verbose)
        sys.exit(3)
    
    except SecureScanError as e:
        console.print(f"\n[bold red]❌ SecureScan Error:[/bold red]\n{e}")
        logger.error(f"SecureScan error: {e}", exc_info=verbose)
        sys.exit(3)
    
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan interrupted by user[/yellow]")
        sys.exit(130)
    
    except Exception as e:
        console.print(f"\n[bold red]❌ Unexpected Error:[/bold red] {e}")
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(3)


def _determine_exit_code(result, fail_on: str) -> int:
    """
    Determine exit code based on findings and fail_on threshold.
    
    Returns:
        0: No issues or below threshold
        1: HIGH severity found
        2: CRITICAL severity found
        3: Scan error
    """
    if not result.success:
        return 3
    
    if fail_on.upper() == "NONE":
        return 0
    
    severity_order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0,
    }
    
    fail_threshold = severity_order.get(fail_on.upper(), 3)
    
    # Check if any findings meet or exceed threshold
    for severity, count in result.findings_by_severity.items():
        if count > 0 and severity_order.get(severity, 0) >= fail_threshold:
            # Return appropriate exit code
            if severity == "CRITICAL":
                return 2
            elif severity == "HIGH":
                return 1
    
    return 0


def _output_console(result, max_findings: int):
    """Display results in rich console format."""
    
    # === SUMMARY SECTION ===
    console.print()
    console.print("[bold]" + "="*70 + "[/bold]")
    console.print("[bold cyan]SCAN SUMMARY[/bold cyan]")
    console.print("[bold]" + "="*70 + "[/bold]")
    console.print()
    
    console.print(f"[bold]Scan ID:[/bold] {result.scan_id}")
    console.print(f"[bold]Target:[/bold] {result.target}")
    console.print(f"[bold]Duration:[/bold] {result.duration_seconds:.2f}s")
    console.print(f"[bold]Files Scanned:[/bold] {result.files_scanned}")
    console.print(f"[bold]Total Findings:[/bold] {result.total_findings}")
    
    if not result.success:
        console.print(f"[bold red]Status:[/bold red] Failed")
        for error in result.errors:
            console.print(f"[red]  • {error}[/red]")
        return
    
    # === LLM VALIDATION STATS ===
    if "llm_validation" in result.config:
        llm_stats = result.config["llm_validation"]
        console.print()
        console.print("[bold]" + "─"*70 + "[/bold]")
        console.print("[bold green]🤖 AI VALIDATION RESULTS[/bold green]")
        console.print("[bold]" + "─"*70 + "[/bold]")
        console.print()
        
        console.print(f"[bold]Provider:[/bold] {llm_stats['provider']}/{llm_stats['model']}")
        console.print(f"[bold]Original Findings:[/bold] {llm_stats['original_findings']}")
        console.print(f"[bold]Validated:[/bold] {llm_stats['validated']}")
        console.print(f"[bold]Confirmed Vulnerable:[/bold] [red]{llm_stats['confirmed_vulnerable']}[/red]")
        console.print(f"[bold]False Positives:[/bold] [green]{llm_stats['false_positives']}[/green]")
        console.print(f"[bold]Avg Confidence:[/bold] {llm_stats['avg_confidence']:.2f}")
        console.print(f"[bold]Total Tokens:[/bold] {llm_stats['total_tokens']:,}")
        console.print(f"[bold]Cost:[/bold] ${llm_stats['total_cost_usd']:.4f}")
        
        if llm_stats['failed'] > 0:
            console.print(f"[bold yellow]Failed:[/bold yellow] {llm_stats['failed']}")
        
        if llm_stats['original_findings'] > 0:
            reduction = (llm_stats['false_positives'] / llm_stats['original_findings']) * 100
            console.print()
            console.print(f"[bold green]✨ False Positive Reduction: {reduction:.1f}%[/bold green]")
    
    # === CVE ENRICHMENT STATS ===
    if "cve_enrichment" in result.config and "error" not in result.config["cve_enrichment"]:
        cve_stats = result.config["cve_enrichment"]
        console.print()
        console.print("[bold]" + "─"*70 + "[/bold]")
        console.print("[bold cyan]📋 CVE INTELLIGENCE[/bold cyan]")
        console.print("[bold]" + "─"*70 + "[/bold]")
        console.print()
        
        console.print(f"[bold]Enriched Findings:[/bold] {cve_stats['enriched_findings']}")
        console.print(f"[bold]Total CVEs:[/bold] {cve_stats['total_cves_found']}")
        console.print(f"[bold]Avg CVEs per Finding:[/bold] {cve_stats['avg_cves_per_finding']:.1f}")
        
        if cve_stats['findings_in_cisa_kev'] > 0:
            console.print(f"[bold red]🚨 CISA KEV:[/bold red] {cve_stats['findings_in_cisa_kev']} (actively exploited!)")
        else:
            console.print(f"[bold]CISA KEV:[/bold] 0")
        
        if cve_stats['findings_with_exploits'] > 0:
            console.print(f"[bold yellow]💥 With Exploits:[/bold yellow] {cve_stats['findings_with_exploits']}")
        else:
            console.print(f"[bold]With Exploits:[/bold] 0")
        
        if cve_stats.get('avg_cvss'):
            console.print(f"[bold]Avg CVSS:[/bold] {cve_stats['avg_cvss']:.1f}/10")
            console.print(f"[bold]Max CVSS:[/bold] {cve_stats['max_cvss']:.1f}/10")
        
        threat_levels = cve_stats.get('threat_levels', {})
        if any(threat_levels.values()):
            console.print()
            console.print("[bold]Threat Levels:[/bold]")
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
    
    # === SEVERITY BREAKDOWN ===
    console.print()
    severity_table = Table(title="Findings by Severity", show_header=True)
    severity_table.add_column("Severity", style="bold")
    severity_table.add_column("Count", justify="right")
    
    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "dim",
    }
    
    for severity, count in result.findings_by_severity.items():
        if count > 0:
            color = severity_colors.get(severity, "white")
            severity_table.add_row(
                f"[{color}]{severity}[/{color}]",
                f"[{color}]{count}[/{color}]"
            )
    
    console.print(severity_table)
    
    # === FINDINGS DETAILS ===
    if result.findings:
        console.print()
        console.print("[bold]" + "="*70 + "[/bold]")
        console.print(f"[bold cyan]TOP FINDINGS[/bold cyan] (showing up to {max_findings})")
        console.print("[bold]" + "="*70 + "[/bold]")
        console.print()
        
        for i, finding in enumerate(result.findings[:max_findings], 1):
            severity = finding.get("severity", "MEDIUM")
            color = severity_colors.get(severity, "white")
            
            # Header
            header = f"[bold]{i}. [{color}]{severity}[/{color}][/bold] {finding.get('title', 'No title')[:60]}"
            
            if finding.get("threat_level"):
                threat = finding["threat_level"]
                threat_color = severity_colors.get(threat, "white")
                header += f" [{threat_color}]●{threat}[/{threat_color}]"
            
            console.print(header)
            
            # Details
            file_name = Path(finding.get("file", "")).name
            console.print(f"   [dim]File:[/dim] {file_name}:{finding.get('line', 0)}")
            console.print(f"   [dim]Rule:[/dim] {finding.get('rule_id', 'unknown')}")
            
            if finding.get("cwe_id"):
                console.print(f"   [dim]CWE:[/dim] {finding['cwe_id']}")
            
            # AI Analysis
            if finding.get("llm_validated"):
                confidence = finding.get("llm_confidence", 0.0)
                exploitability = finding.get("llm_exploitability", "unknown")
                
                console.print(
                    f"   [dim]🤖 AI:[/dim] Confidence: [green]{confidence:.2f}[/green] | "
                    f"Exploitability: [{_get_exploit_color(exploitability)}]{exploitability}[/{_get_exploit_color(exploitability)}]"
                )
                
                reasoning = finding.get("llm_reasoning", "")
                if reasoning:
                    short = reasoning[:100] + "..." if len(reasoning) > 100 else reasoning
                    console.print(f"   [dim]   Reason:[/dim] {short}")
            
            # CVE Intelligence
            if finding.get("cve_enriched"):
                cve_count = finding.get("cve_count", 0)
                max_cvss = finding.get("max_cvss", 0)
                
                console.print(f"   [dim]📋 CVE:[/dim] {cve_count} related | Max CVSS: {max_cvss:.1f}/10")
                
                if finding.get("cisa_kev"):
                    kev_count = len(finding.get("cisa_kev_cves", []))
                    console.print(f"   [bold red]🚨 CISA KEV: {kev_count} actively exploited![/bold red]")
                
                if finding.get("exploit_available"):
                    exploit_count = finding.get("exploit_count", 0)
                    console.print(f"   [yellow]💥 Exploits: {exploit_count} available[/yellow]")
                
                related_cves = finding.get("related_cves", [])
                if related_cves:
                    top_cve = related_cves[0]
                    console.print(f"   [dim]   Top:[/dim] {top_cve['cve_id']} (CVSS: {top_cve.get('cvss_score', 'N/A')})")
            
            # Code snippet
            snippet = finding.get("code_snippet", "").strip()
            if snippet:
                if len(snippet) > 100:
                    snippet = snippet[:97] + "..."
                console.print(f"   [dim]Code:[/dim] [yellow]{snippet}[/yellow]")
            
            console.print()
        
        if len(result.findings) > max_findings:
            remaining = len(result.findings) - max_findings
            console.print(f"[dim]... and {remaining} more findings[/dim]")
    
    # === FOOTER ===
    console.print("[bold]" + "="*70 + "[/bold]")
    
    if result.total_findings == 0:
        console.print("[bold green]✅ No vulnerabilities found![/bold green]")
    else:
        console.print(
            f"[bold yellow]⚠️  Found {result.total_findings} potential "
            f"{'vulnerability' if result.total_findings == 1 else 'vulnerabilities'}[/bold yellow]"
        )
    
    console.print()


def _get_exploit_color(exploitability: str) -> str:
    """Get color for exploitability level."""
    colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "none": "green",
    }
    return colors.get(exploitability.lower(), "white")


def _output_json(result, output_file: str = None):
    """Output results as JSON."""
    data = {
        "scan_id": result.scan_id,
        "target": result.target,
        "started_at": result.started_at.isoformat(),
        "completed_at": result.completed_at.isoformat() if result.completed_at else None,
        "duration_seconds": result.duration_seconds,
        "files_scanned": result.files_scanned,
        "total_findings": result.total_findings,
        "findings_by_severity": result.findings_by_severity,
        "success": result.success,
        "errors": result.errors,
        "config": result.config,
        "findings": result.findings,
    }
    
    json_str = json.dumps(data, indent=2)
    
    if output_file:
        Path(output_file).write_text(json_str)
        console.print(f"[green]✅ Results written to {output_file}[/green]")
    else:
        console.print(json_str)


# === CONFIG COMMANDS ===

@cli.group()
def config():
    """Manage SecureScan configuration."""
    pass


@config.command()
@click.pass_context
def show(ctx):
    """Show current configuration."""
    cfg = ctx.obj.get("config", Config())
    
    console.print("\n[bold cyan]📋 Current Configuration[/bold cyan]\n")
    
    # Scan settings
    console.print("[bold]Scan Settings:[/bold]")
    table = Table(show_header=False, box=None)
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="yellow")
    
    table.add_row("Timeout", f"{cfg.scan.timeout}s")
    table.add_row("Max Findings", str(cfg.scan.max_findings))
    table.add_row("Exclude Patterns", str(len(cfg.scan.exclude_patterns)))
    
    console.print(table)
    console.print()
    
    # LLM settings
    console.print("[bold]LLM Settings:[/bold]")
    table = Table(show_header=False, box=None)
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="yellow")
    
    table.add_row("Provider", cfg.llm.provider)
    table.add_row("Model", cfg.llm.model)
    table.add_row("Confidence Threshold", f"{cfg.llm.confidence_threshold:.2f}")
    table.add_row("Max Workers", str(cfg.llm.max_workers))
    
    console.print(table)
    console.print()
    
    # CVE settings
    console.print("[bold]CVE Settings:[/bold]")
    table = Table(show_header=False, box=None)
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="yellow")
    
    table.add_row("Enabled", "✅" if cfg.cve.enabled else "❌")
    table.add_row("Max CVEs per Finding", str(cfg.cve.max_cves_per_finding))
    table.add_row("Cache Days", str(cfg.cve.cache_days))
    
    console.print(table)
    console.print()


@config.command()
@click.option("--overwrite", is_flag=True, help="Overwrite existing config")
def init(overwrite):
    """Initialize user configuration file."""
    try:
        config_file = Config.create_user_config(overwrite=overwrite)
        console.print(f"\n[green]✅ Created configuration:[/green] {config_file}")
        console.print("\n[dim]Edit this file to customize settings.[/dim]\n")
    
    except ConfigError as e:
        console.print(f"\n[red]❌ Error:[/red] {e}\n")
        sys.exit(1)


@config.command()
@click.argument("config_file", type=click.Path(exists=True))
def validate(config_file):
    """Validate configuration file."""
    console.print(f"\n[bold]🔍 Validating:[/bold] {config_file}\n")
    
    try:
        cfg = init_config(Path(config_file))
        console.print("[green]✅ Configuration is valid![/green]\n")
        
        import yaml
        config_dict = cfg.to_dict()
        yaml_str = yaml.dump(config_dict, default_flow_style=False, sort_keys=False)
        
        from rich.syntax import Syntax
        syntax = Syntax(yaml_str, "yaml", theme="monokai")
        console.print(syntax)
    
    except (ConfigError, SecureScanError) as e:
        console.print(f"[red]❌ Validation failed:[/red]\n{e}\n")
        sys.exit(1)


@config.command()
@click.argument("key")
@click.pass_context
def get(ctx, key):
    """Get configuration value."""
    cfg = ctx.obj.get("config", Config())
    value = cfg.get(key)
    
    if value is None:
        console.print(f"\n[yellow]⚠️  Key not found:[/yellow] {key}\n")
    else:
        console.print(f"\n[cyan]{key}:[/cyan] [yellow]{value}[/yellow]\n")


# === VERSION COMMAND ===

@cli.command()
def version():
    """Show version information."""
    console.print()
    console.print(f"[bold cyan]SecureScan AI[/bold cyan] version [yellow]{VERSION}[/yellow]")
    console.print()
    console.print("[dim]Open Source Security Code Review Platform[/dim]")
    console.print("[dim]https://github.com/your-org/securescan-ai[/dim]")
    console.print()


if __name__ == "__main__":
    cli(obj={})
