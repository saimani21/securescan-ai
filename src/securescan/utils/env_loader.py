"""Auto-load environment variables from .env file."""

from pathlib import Path
from dotenv import load_dotenv

def load_env():
    """Load .env file if it exists."""
    env_file = Path.cwd() / ".env"
    if env_file.exists():
        load_dotenv(env_file)
        return True
    return False
