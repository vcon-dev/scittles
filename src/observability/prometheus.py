"""Prometheus metrics endpoint."""

from fastapi import Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry import metrics

from ..config import settings


_prometheus_reader: PrometheusMetricReader = None


def setup_prometheus_exporter() -> PrometheusMetricReader:
    """Setup Prometheus metric reader."""
    global _prometheus_reader
    if _prometheus_reader is None:
        _prometheus_reader = PrometheusMetricReader()
        # Add to existing meter provider
        meter_provider = metrics.get_meter_provider()
        if isinstance(meter_provider, MeterProvider):
            # Recreate the provider with the new reader
            # This is necessary because metric_readers are set at provider creation
            from opentelemetry.sdk.resources import Resource
            # Get resource from provider if available, otherwise create default
            try:
                resource = meter_provider._resource
            except AttributeError:
                # Fallback to default resource if _resource is not accessible
                resource = Resource.create({"service.name": "scittles"})
            # Get existing readers - try both attribute names for compatibility
            try:
                existing_readers = list(meter_provider._all_metric_readers)
            except AttributeError:
                try:
                    existing_readers = list(meter_provider._metric_readers)
                except AttributeError:
                    existing_readers = []
            existing_readers.append(_prometheus_reader)
            new_provider = MeterProvider(resource=resource, metric_readers=existing_readers)
            metrics.set_meter_provider(new_provider)
    return _prometheus_reader


def get_metrics_endpoint():
    """Get FastAPI endpoint handler for /metrics."""

    async def metrics_endpoint() -> Response:
        """Prometheus metrics endpoint."""
        if _prometheus_reader is None:
            return Response(content="Prometheus exporter not configured", status_code=503)

        # The PrometheusMetricReader integrates with prometheus_client
        # and exposes metrics via the default REGISTRY
        try:
            from prometheus_client.core import REGISTRY
            prometheus_output = generate_latest(REGISTRY)
        except Exception as e:
            # Fallback if metrics are not available
            prometheus_output = f"# Prometheus metrics not available: {str(e)}\n".encode()

        return Response(content=prometheus_output, media_type=CONTENT_TYPE_LATEST)

    return metrics_endpoint

