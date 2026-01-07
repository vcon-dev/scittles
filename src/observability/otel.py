"""OpenTelemetry setup and configuration."""

import os
from typing import List, Optional

from opentelemetry import trace, metrics
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader, ConsoleMetricExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.sqlite3 import SQLite3Instrumentor
from opentelemetry.propagators.composite import CompositeHTTPPropagator
from opentelemetry.propagate import set_global_textmap
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from ..config import settings


def _parse_headers(headers_str: Optional[str]) -> dict:
    """Parse OTLP headers from comma-separated key=value pairs."""
    if not headers_str:
        return {}
    headers = {}
    for pair in headers_str.split(","):
        if "=" in pair:
            key, value = pair.split("=", 1)
            headers[key.strip()] = value.strip()
    return headers


def setup_opentelemetry() -> None:
    """Initialize OpenTelemetry SDK with configured exporters."""
    if not settings.otel_enabled:
        return

    # Create resource with service information
    resource = Resource.create(
        {
            "service.name": settings.otel_service_name,
            "service.version": "0.1.0",
        }
    )

    # Setup trace provider
    trace_provider = TracerProvider(resource=resource)
    trace.set_tracer_provider(trace_provider)

    # Setup metric provider
    metric_readers = []
    metric_provider = MeterProvider(resource=resource, metric_readers=metric_readers)
    metrics.set_meter_provider(metric_provider)

    # Parse exporters from configuration
    exporters = [e.strip() for e in settings.otel_exporter.split(",")]

    # Setup span exporters
    span_processors = []
    if "console" in exporters:
        span_processors.append(BatchSpanProcessor(ConsoleSpanExporter()))
    if "otlp" in exporters:
        headers = _parse_headers(settings.otel_headers)
        endpoint = settings.otel_endpoint or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
        otlp_exporter = OTLPSpanExporter(endpoint=endpoint, headers=headers)
        span_processors.append(BatchSpanProcessor(otlp_exporter))

    for processor in span_processors:
        trace_provider.add_span_processor(processor)

    # Setup metric exporters
    if "console" in exporters:
        console_metric_exporter = ConsoleMetricExporter()
        metric_readers.append(PeriodicExportingMetricReader(console_metric_exporter))
    if "otlp" in exporters:
        headers = _parse_headers(settings.otel_headers)
        endpoint = settings.otel_endpoint or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
        otlp_metric_exporter = OTLPMetricExporter(endpoint=endpoint, headers=headers)
        metric_readers.append(PeriodicExportingMetricReader(otlp_metric_exporter))
    if "prometheus" in exporters:
        # Prometheus exporter is set up separately via setup_prometheus_exporter()
        # to allow access to the reader for the /metrics endpoint
        pass

    # Setup context propagation
    propagator = CompositeHTTPPropagator([TraceContextTextMapPropagator()])
    set_global_textmap(propagator)

    # Instrument FastAPI
    FastAPIInstrumentor().instrument()

    # Instrument SQLite
    SQLite3Instrumentor().instrument()


def get_tracer(name: str):
    """Get a tracer instance."""
    return trace.get_tracer(name)


def get_meter(name: str):
    """Get a meter instance."""
    return metrics.get_meter(name)

