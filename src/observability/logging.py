"""Structured logging setup with structlog and OpenTelemetry integration."""

import logging
import sys
from typing import Any, Dict

import structlog
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from ..config import settings


def add_trace_context(logger: Any, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Add OpenTelemetry trace context to log records."""
    span = trace.get_current_span()
    if span and span.get_span_context().is_valid:
        span_context = span.get_span_context()
        event_dict["trace_id"] = format(span_context.trace_id, "032x")
        event_dict["span_id"] = format(span_context.span_id, "016x")
        if span_context.trace_flags:
            event_dict["trace_flags"] = format(span_context.trace_flags, "02x")
    return event_dict


def setup_logging() -> None:
    """Configure structured logging with structlog."""
    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
    )

    # Configure structlog processors
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        add_trace_context,
    ]

    # Add formatter based on configuration
    if settings.log_format.lower() == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))

    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = None) -> structlog.stdlib.BoundLogger:
    """Get a configured logger instance."""
    return structlog.get_logger(name)

