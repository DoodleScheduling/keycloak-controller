package otelsetup

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"google.golang.org/grpc/credentials"
)

func Tracing(ctx context.Context, opts Options) (*trace.TracerProvider, error) {
	var grpcOptions []otlptracegrpc.Option

	if opts.Endpoint != "" {
		grpcOptions = append(grpcOptions, otlptracegrpc.WithEndpoint(opts.Endpoint))
	}

	if opts.Insecure {
		grpcOptions = append(grpcOptions, otlptracegrpc.WithInsecure())
	} else {
		tlsOpts, err := opts.getTLSConfig()
		if err != nil {
			return nil, err
		}

		grpcOptions = append(grpcOptions, otlptracegrpc.WithTLSCredentials(credentials.NewTLS(tlsOpts)))

	}

	exporter, err := otlptracegrpc.New(
		ctx,
		grpcOptions...,
	)

	if err != nil {
		return nil, err
	}

	// labels/tags/resources that are common to all traces.
	resource := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(opts.ServiceName),
	)

	provider := trace.NewTracerProvider(
		trace.WithBatcher(exporter),
		trace.WithResource(resource),
		trace.WithSampler(trace.ParentBased(trace.TraceIDRatioBased(1))),
	)

	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{}, // W3C Trace Context format; https://www.w3.org/TR/trace-context/
		),
	)

	otel.SetTracerProvider(provider)

	return provider, nil
}
