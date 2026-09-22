"""OpenTelemetry tracing for the advisory-intel agent.

Provides a decision audit trail: which tools were called, how long each
took, what data was returned, and the full agent reasoning chain.

Console exporter by default (for demos). Set OTEL_EXPORTER_OTLP_ENDPOINT
to send traces to Grafana/Tempo/Jaeger.
"""

import os
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION

_tracer_provider: TracerProvider | None = None


def initialize_tracing() -> None:
    """Set up OTEL tracing with console or OTLP exporter."""
    global _tracer_provider

    resource = Resource.create({
        SERVICE_NAME: "advisory-intel-agent",
        SERVICE_VERSION: "2.0.0",
        "deployment.environment": os.getenv("OTEL_ENV", "development"),
    })

    _tracer_provider = TracerProvider(resource=resource)

    otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            _tracer_provider.add_span_processor(
                BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True))
            )
        except ImportError:
            _tracer_provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
    else:
        _tracer_provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))

    trace.set_tracer_provider(_tracer_provider)


def shutdown_tracing() -> None:
    """Flush and shut down the tracer provider."""
    if _tracer_provider is not None:
        _tracer_provider.shutdown()


def get_tracer(name: str = __name__) -> trace.Tracer:
    """Get a tracer instance."""
    return trace.get_tracer(name)
