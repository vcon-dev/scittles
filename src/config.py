from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings."""

    # Database
    db_path: str = "transparency.db"

    # Service
    service_url: str = "https://transparency.example"
    service_id: str = "https://transparency.example"

    # API
    host: str = "0.0.0.0"
    port: int = 8000

    # Security
    key_file: Optional[str] = None  # Path to signing key
    enable_auth: bool = False

    # Performance
    max_tree_cache_size: int = 10000

    model_config = {"env_prefix": "SCITT_", "env_file": ".env"}


settings = Settings()
