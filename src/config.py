from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings."""

    # Database
    db_path: str = "transparency.db"
    storage_backend: str = "sqlite"  # "sqlite" or "postgres"
    postgres_url: Optional[str] = None
    postgres_pool_min: int = 2
    postgres_pool_max: int = 10

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

    # Observability - Logging
    log_level: str = "INFO"  # DEBUG, INFO, WARNING, ERROR
    log_format: str = "text"  # json or text

    # Observability - OpenTelemetry
    otel_enabled: bool = True
    otel_service_name: str = "scittles"
    otel_exporter: str = "console"  # console, otlp, prometheus, or comma-separated list
    otel_endpoint: Optional[str] = None  # OTLP endpoint URL (e.g., http://localhost:4317)
    otel_headers: Optional[str] = None  # OTLP headers as comma-separated key=value pairs
    prometheus_port: int = 9090  # Port for Prometheus metrics endpoint

    model_config = {"env_prefix": "SCITT_", "env_file": ".env"}


settings = Settings()
