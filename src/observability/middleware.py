"""FastAPI middleware for observability."""

import time
import uuid
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from .logging import get_logger
from .metrics import get_metrics

logger = get_logger(__name__)
metrics = get_metrics()


class ObservabilityMiddleware(BaseHTTPMiddleware):
    """Middleware for request/response logging and tracing."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with observability."""
        # Generate request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        # Start timing
        start_time = time.time()

        # Get current span (FastAPI instrumentation creates one automatically)
        # If no span exists, create one
        current_span = trace.get_current_span()
        if not current_span or not current_span.get_span_context().is_valid:
            tracer = trace.get_tracer(__name__)
            span = tracer.start_span(
                name=f"{request.method} {request.url.path}",
                kind=trace.SpanKind.SERVER,
            )
            ctx = trace.use_span(span)
        else:
            span = current_span
            ctx = None

        # Add span attributes
        if span and span.is_recording():
            span.set_attribute("http.method", request.method)
            span.set_attribute("http.url", str(request.url))
            span.set_attribute("http.route", request.url.path)
            span.set_attribute("request.id", request_id)

        # Log request
        logger.info(
            "request_started",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            query_params=str(request.query_params) if request.query_params else None,
            client_host=request.client.host if request.client else None,
        )

        # Record metrics
        metrics.http_request_count.add(1, {"method": request.method, "path": request.url.path})

        response = None
        status_code = 500
        error_occurred = False

        try:
            if ctx:
                with ctx:
                    response = await call_next(request)
            else:
                response = await call_next(request)
                
            status_code = response.status_code
            if span and span.is_recording():
                span.set_attribute("http.status_code", status_code)

                # Record error if status >= 400
                if status_code >= 400:
                    error_occurred = True
                    span.set_status(Status(StatusCode.ERROR, f"HTTP {status_code}"))
                    metrics.http_error_count.add(
                        1, {"method": request.method, "path": request.url.path, "status_code": status_code}
                    )
                else:
                    span.set_status(Status(StatusCode.OK))

            return response

        except Exception as e:
            error_occurred = True
            status_code = 500
            if span and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, str(e)))
                span.record_exception(e)
            metrics.http_error_count.add(
                1, {"method": request.method, "path": request.url.path, "status_code": 500}
            )
            logger.exception(
                "request_failed",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                error=str(e),
            )
            raise

        finally:
            # Calculate duration
            duration = time.time() - start_time

            # Record duration metric
            metrics.http_request_duration.record(
                duration,
                {
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": status_code,
                },
            )

            # Log response
            logger.info(
                "request_completed",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                status_code=status_code,
                duration_seconds=duration,
            )

            # End span if we created it (FastAPI instrumentation handles its own spans)
            # Only end if it's our custom span (when ctx was set)
            if ctx and span and span.is_recording():
                try:
                    span.end()
                except Exception:
                    pass  # Span may already be ended

            # Add request ID to response headers
            if response:
                response.headers["X-Request-ID"] = request_id

