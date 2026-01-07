"""Custom metrics definitions for the transparency service."""

from opentelemetry import metrics
from opentelemetry.metrics import Counter, Histogram, UpDownCounter


class Metrics:
    """Custom metrics for the transparency service."""

    def __init__(self):
        meter = metrics.get_meter(__name__)

        # HTTP metrics
        self.http_request_duration = meter.create_histogram(
            name="http_request_duration_seconds",
            description="HTTP request duration in seconds",
            unit="s",
        )
        self.http_request_count = meter.create_counter(
            name="http_request_total",
            description="Total number of HTTP requests",
        )
        self.http_error_count = meter.create_counter(
            name="http_error_total",
            description="Total number of HTTP errors",
        )

        # Database metrics
        self.db_operation_duration = meter.create_histogram(
            name="db_operation_duration_seconds",
            description="Database operation duration in seconds",
            unit="s",
        )
        self.db_operation_count = meter.create_counter(
            name="db_operation_total",
            description="Total number of database operations",
        )
        self.db_error_count = meter.create_counter(
            name="db_error_total",
            description="Total number of database errors",
        )

        # Merkle tree metrics
        self.merkle_tree_size = meter.create_up_down_counter(
            name="merkle_tree_size",
            description="Current size of the Merkle tree",
        )
        self.merkle_operation_duration = meter.create_histogram(
            name="merkle_operation_duration_seconds",
            description="Merkle tree operation duration in seconds",
            unit="s",
        )
        self.merkle_proof_generation_count = meter.create_counter(
            name="merkle_proof_generation_total",
            description="Total number of inclusion proofs generated",
        )

        # Receipt metrics
        self.receipt_generation_duration = meter.create_histogram(
            name="receipt_generation_duration_seconds",
            description="Receipt generation duration in seconds",
            unit="s",
        )
        self.receipt_generation_count = meter.create_counter(
            name="receipt_generation_total",
            description="Total number of receipts generated",
        )
        self.receipt_error_count = meter.create_counter(
            name="receipt_error_total",
            description="Total number of receipt generation errors",
        )

        # Entry registration metrics
        self.entry_registration_count = meter.create_counter(
            name="entry_registration_total",
            description="Total number of entries registered",
        )
        self.entry_registration_duration = meter.create_histogram(
            name="entry_registration_duration_seconds",
            description="Entry registration duration in seconds",
            unit="s",
        )


# Global metrics instance
_metrics: Metrics = None


def get_metrics() -> Metrics:
    """Get the global metrics instance."""
    global _metrics
    if _metrics is None:
        _metrics = Metrics()
    return _metrics

