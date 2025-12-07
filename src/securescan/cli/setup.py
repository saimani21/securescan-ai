"""Interactive setup wizard for SecureScan AI."""

import os
import sys
import subprocess
from pathlib import Path
import click
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel

console = Console()


def check_semgrep():
    """Check if semgrep is installed."""
    try:
        result = subprocess.run(['semgrep', '--version'], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def install_semgrep():
    """Install semgrep using pipx."""
    console.print("\n[yellow]Installing Semgrep...[/yellow]")
    try:
        subprocess.run(['pipx', 'install', 'semgrep'], check=True)
        console.print("[green]✅ Semgrep installed successfully![/green]")
        return True
    except subprocess.CalledProcessError:
        console.print("[red]❌ Failed to install Semgrep[/red]")
        console.print("[yellow]Please install manually: pipx install semgrep[/yellow]")
        return False
    except FileNotFoundError:
        console.print("[red]❌ pipx not found[/red]")
        console.print("[yellow]Install pipx first: sudo apt install pipx[/yellow]")
        return False


def setup_api_keys():
    """Interactive API key setup."""
    config_dir = Path.home() / '.securescan'
    config_file = config_dir / 'config.yml'
    env_file = config_dir / '.env'
    
    # Create config directory
    config_dir.mkdir(exist_ok=True)
    
    console.print("\n[bold cyan]API Key Setup[/bold cyan]")
    console.print("You can skip any key and set it later via environment variables\n")
    
    # OpenAI API Key
    openai_key = os.getenv('OPENAI_API_KEY', '')
    if openai_key:
        console.print(f"[green]✅ OPENAI_API_KEY already set: {openai_key[:20]}...[/green]")
        if not Confirm.ask("Update it?", default=False):
            openai_key = None
    
    if not openai_key:
        console.print("\n[bold]OpenAI API Key[/bold] (for AI validation)")
        console.print("Get it from: https://platform.openai.com/api-keys")
        console.print("Cost: ~$0.10-0.20 per scan")
        openai_key = Prompt.ask("Enter OpenAI API key (or press Enter to skip)", default="")
    
    # NVD API Key
    nvd_key = os.getenv('NVD_API_KEY', '')
    if nvd_key:
        console.print(f"\n[green]✅ NVD_API_KEY already set: {nvd_key[:20]}...[/green]")
        if not Confirm.ask("Update it?", default=False):
            nvd_key = None
    
    if not nvd_key:
        console.print("\n[bold]NVD API Key[/bold] (optional, for faster CVE enrichment)")
        console.print("Get it from: https://nvd.nist.gov/developers/request-an-api-key")
        console.print("Free, increases rate limit 10x")
        nvd_key = Prompt.ask("Enter NVD API key (or press Enter to skip)", default="")
    
    # Save to .env file
    env_content = ""
    if openai_key:
        env_content += f"OPENAI_API_KEY={openai_key}\n"
    if nvd_key:
        env_content += f"NVD_API_KEY={nvd_key}\n"
    
    if env_content:
        env_file.write_text(env_content)
        console.print(f"\n[green]✅ API keys saved to: {env_file}[/green]")
        
        # Add to bashrc
        bashrc = Path.home() / '.bashrc'
        source_line = f'\n# SecureScan AI - Load API keys\n[ -f "{env_file}" ] && export $(cat "{env_file}" | xargs)\n'
        
        if bashrc.exists():
            bashrc_content = bashrc.read_text()
            if str(env_file) not in bashrc_content:
                if Confirm.ask("\nAdd API keys to ~/.bashrc for permanent use?", default=True):
                    with bashrc.open('a') as f:
                        f.write(source_line)
                    console.print("[green]✅ Added to ~/.bashrc[/green]")
                    console.print("[yellow]Run: source ~/.bashrc[/yellow]")
    
    return bool(openai_key or nvd_key)


@click.command()
def setup():
    """Interactive setup wizard for SecureScan AI."""
    console.print(Panel.fit(
        "[bold cyan]SecureScan AI - Setup Wizard[/bold cyan]\n"
        "This will help you configure SecureScan AI",
        border_style="cyan"
    ))
    
    # Check semgrep
    console.print("\n[bold]1️⃣  Checking Semgrep...[/bold]")
    if check_semgrep():
        console.print("[green]✅ Semgrep is already installed[/green]")
    else:
        console.print("[yellow]⚠️  Semgrep not found[/yellow]")
        if Confirm.ask("Install Semgrep now?", default=True):
            install_semgrep()
    
    # Setup API keys
    console.print("\n[bold]2️⃣  API Key Configuration[/bold]")
    setup_api_keys()
    
    # Test installation
    console.print("\n[bold]3️⃣  Testing Installation[/bold]")
    
    # Create test file
    test_dir = Path('/tmp/securescan-test')
    test_dir.mkdir(exist_ok=True)
    test_file = test_dir / 'test.py'
    test_file.write_text('eval(input())\n')
    
    console.print("\nRunning test scan...")
    try:
        result = subprocess.run(
            ['secscan', 'scan', str(test_dir)],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode in [0, 1, 2]:  # 0=clean, 1=HIGH, 2=CRITICAL
            console.print("[green]✅ Test scan successful![/green]")
        else:
            console.print("[yellow]⚠️  Test scan completed with warnings[/yellow]")
    except Exception as e:
        console.print(f"[yellow]⚠️  Test scan failed: {e}[/yellow]")
    finally:
        # Cleanup
        test_file.unlink(missing_ok=True)
        test_dir.rmdir()
    
    # Final instructions
    console.print("\n" + "="*60)
    console.print(Panel.fit(
        "[bold green]✅ Setup Complete![/bold green]\n\n"
        "[bold]Quick Start:[/bold]\n"
        "  # Basic scan (free)\n"
        "  secscan scan /path/to/code\n\n"
        "  # With AI validation\n"
        "  secscan scan /path/to/code --llm openai --severity HIGH --severity CRITICAL\n\n"
        "  # Full pipeline\n"
        "  secscan scan /path/to/code --llm openai --enrich-cve\n\n"
        "[bold]Need help?[/bold]\n"
        "  secscan --help\n"
        "  https://github.com/saimani21/securescan-ai",
        border_style="green"
    ))


if __name__ == '__main__':
    setup()
