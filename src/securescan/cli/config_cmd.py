"""Configuration management CLI commands."""

import click
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax

from ..utils.config import Config
from ..utils.logger import get_logger

console = Console()
logger = get_logger(__name__)


@click.group()
def config():
    """Manage SecureScan configuration."""
    pass


@config.command()
def show():
    """Show current configuration."""
    console.print("\n[bold cyan]📋 Current Configuration[/bold cyan]\n")
    
    cfg = Config()
    
    # Scan config
    console.print("[bold]Scan Settings:[/bold]")
    table = Table(show_header=False, box=None)
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="yellow")
    
    table.add_row("Timeout", f"{cfg.scan.timeout}s")
    table.add_row("Max Findings", str(cfg.scan.max_findings))
    table.add_row("Exclude Patterns", str(len(cfg.scan.exclude_patterns)))
    
    console.print(table)
    console.print()
    
    # LLM config
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
    
    # CVE config
    console.print("[bold]CVE Settings:[/bold]")
    table = Table(show_header=False, box=None)
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="yellow")
    
    table.add_row("Enabled", "✅" if cfg.cve.enabled else "❌")
    table.add_row("Max CVEs", str(cfg.cve.max_cves_per_finding))
    table.add_row("Cache Days", str(cfg.cve.cache_days))
    
    console.print(table)
    console.print()


@config.command()
@click.option("--overwrite", is_flag=True, help="Overwrite existing config")
def init(overwrite):
    """Initialize user configuration file."""
    try:
        config_file = Config.create_user_config(overwrite=overwrite)
        console.print(f"\n[green]✅ Created configuration file:[/green] {config_file}")
        console.print("\n[dim]Edit this file to customize your settings.[/dim]\n")
    
    except Exception as e:
        console.print(f"\n[red]❌ Error:[/red] {e}\n")


@config.command()
@click.argument("config_file", type=click.Path(exists=True))
def validate(config_file):
    """Validate configuration file."""
    console.print(f"\n[bold]🔍 Validating:[/bold] {config_file}\n")
    
    try:
        from ..utils.config import init_config
        
        cfg = init_config(Path(config_file))
        
        console.print("[green]✅ Configuration is valid![/green]\n")
        
        # Show loaded config
        console.print("[bold]Loaded configuration:[/bold]")
        
        import yaml
        config_yaml = yaml.dump(cfg.to_dict(), default_flow_style=False, sort_keys=False)
        syntax = Syntax(config_yaml, "yaml", theme="monokai", line_numbers=True)
        console.print(syntax)
    
    except Exception as e:
        console.print(f"[red]❌ Validation failed:[/red]\n{e}\n")


@config.command()
@click.argument("key")
def get(key):
    """Get configuration value."""
    cfg = Config()
    value = cfg.get(key)
    
    if value is None:
        console.print(f"\n[yellow]⚠️  Key not found:[/yellow] {key}\n")
    else:
        console.print(f"\n[cyan]{key}:[/cyan] [yellow]{value}[/yellow]\n")
