// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 LabStack and Echo contributors

package echootel

import (
	"fmt"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

const (
	// TracerKey is the key used to store the tracer in the echo context.
	TracerKey = "labstack-echo-otelecho-tracer"
	// ScopeName is the instrumentation scope name.
	ScopeName = "github.com/labstack/echo-opentelemetry"
)

// Config is used to configure the middleware.
type Config struct {
	// ServerName is set as `server.address` and `server.port` for span and metrics attributes.
	// Example: "api.example.com" or "example.com:8080"
	//
	// If known, this value must be set to the server’s canonical (primary) name.
	// For example, in Apache this corresponds to the ServerName directive
	// (https://httpd.apache.org/docs/2.4/mod/core.html#servername), and in NGINX
	// to the server_name directive
	// (http://nginx.org/en/docs/http/ngx_http_core_module.html#server_name).
	//
	// More generally, the primary server name is the host header value that maps
	// to the HTTP server’s default virtual host. It must include the hostname,
	// and if the server is accessed via a non-default port, the port must be
	// appended using the standard ":port" suffix.
	//
	// If the primary server name is unknown, this field should be set to an
	// empty string. In that case, Request.Host will be used to resolve the
	// effective server name and port.
	ServerName string

	// Skipper defines a function to skip middleware.
	Skipper middleware.Skipper

	// OnNextError is used to specify how errors returned from the next middleware / handler are handled.
	OnNextError OnErrorFunc

	// OnExtractionError is used to specify how errors returned from request extraction are handled.
	OnExtractionError OnErrorFunc

	// TracerProvider allows overriding the default tracer provider.
	TracerProvider oteltrace.TracerProvider

	// MeterProvider allows overriding the default meter provider.
	MeterProvider metric.MeterProvider

	// Propagators allow overriding the default propagators.
	Propagators propagation.TextMapPropagator

	// SpanStartOptions configures an additional set of trace.SpanStartOptions, which are applied to each new span.
	SpanStartOptions []oteltrace.SpanStartOption

	// SpanStartAttributes is used to extract additional attributes from the echo.Context
	// and return them as a slice of attribute.KeyValue.
	SpanStartAttributes AttributesFunc

	// SpanEndAttributes is used to extract additional attributes from the echo.Context
	// and return them as a slice of attribute.KeyValue.
	SpanEndAttributes AttributesFunc

	// MetricAttributes is used to compose attributes just before Metrics.Record call.
	MetricAttributes MetricAttributesFunc

	// Metrics is used to record custom metrics instead of default.
	Metrics MetricsRecorder
}

// AttributesFunc is used to extract additional attributes from the echo.Context
// and return them as a slice of attribute.KeyValue.
type AttributesFunc func(c *echo.Context, v *Values, attr []attribute.KeyValue) []attribute.KeyValue

// MetricAttributesFunc is used to compose attributes for Metrics.Record.
type MetricAttributesFunc func(c *echo.Context, v *Values) []attribute.KeyValue

// MetricsRecorder is used to record metrics.
type MetricsRecorder interface {
	Record(c *echo.Context, v RecordValues)
}

// OnErrorFunc is used to specify how errors are handled in the middleware.
type OnErrorFunc func(c *echo.Context, err error)

// NewMiddleware creates new echo opentelemetry middleware with the given server name.
func NewMiddleware(serverName string) echo.MiddlewareFunc {
	return NewMiddlewareWithConfig(Config{ServerName: serverName})
}

// NewMiddlewareWithConfig creates new echo opentelemetry middleware with the given configuration.
func NewMiddlewareWithConfig(config Config) echo.MiddlewareFunc {
	mw, err := config.ToMiddleware()
	if err != nil {
		panic(err)
	}
	return mw
}

// ToMiddleware returns echo opentelemetry middleware which will trace incoming requests.
func (config Config) ToMiddleware() (echo.MiddlewareFunc, error) {
	if config.TracerProvider == nil {
		config.TracerProvider = otel.GetTracerProvider()
	}
	if config.Propagators == nil {
		config.Propagators = otel.GetTextMapPropagator()
	}
	if config.Skipper == nil {
		config.Skipper = middleware.DefaultSkipper
	}

	var serverHost string
	var serverPort int
	if config.ServerName != "" {
		host, port, sErr := SplitAddress(config.ServerName)
		if sErr != nil {
			return nil, fmt.Errorf("otel middleware failed to parse server name: %w", sErr)
		}
		serverHost = host
		serverPort = port
	}

	tracer := config.TracerProvider.Tracer(
		ScopeName,
		oteltrace.WithInstrumentationVersion(Version),
	)

	metrics := config.Metrics
	if config.Metrics == nil {
		if config.MeterProvider == nil {
			config.MeterProvider = otel.GetMeterProvider()
		}
		meter := config.MeterProvider.Meter(
			ScopeName,
			metric.WithInstrumentationVersion(Version),
		)

		tmp, mErr := NewMetrics(meter)
		if mErr != nil {
			return nil, fmt.Errorf("otel middleware failed to create metrics: %w", mErr)
		}
		metrics = &echoMetricsRecorder{Metrics: tmp}
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if config.Skipper(c) {
				return next(c)
			}

			requestStartTime := time.Now()

			c.Set(TracerKey, tracer)
			request := c.Request()

			ev := Values{
				ServerAddress: serverHost,
				ServerPort:    serverPort,
				ClientAddress: c.RealIP(),
			}
			if err := ev.ExtractRequest(request); err != nil {
				if config.OnExtractionError != nil {
					config.OnExtractionError(c, err)
				}
			}
			spanAttributes := ev.SpanStartAttributes()
			if config.SpanStartAttributes != nil {
				spanAttributes = config.SpanStartAttributes(c, &ev, spanAttributes)
			}

			spanStartOptions := []oteltrace.SpanStartOption{
				oteltrace.WithAttributes(spanAttributes...),
				oteltrace.WithSpanKind(oteltrace.SpanKindServer),
			}
			if config.SpanStartOptions != nil {
				spanStartOptions = append(spanStartOptions, config.SpanStartOptions...)
			}

			ctx, span := tracer.Start(
				config.Propagators.Extract(request.Context(), propagation.HeaderCarrier(request.Header)),
				SpanNameFormatter(ev),
				spanStartOptions...,
			)
			defer span.End()

			// pass the span through the request context
			spanRequest := request.WithContext(ctx)
			c.SetRequest(spanRequest)
			defer func() {
				// as we have created new http.Request object we need to make sure that temporary files created to hold MultipartForm
				// files are cleaned up. This is done by http.Server at the end of request lifecycle but Server does not
				// have a reference to our new Request instance therefore it is our responsibility to fix the mess we caused.
				//
				// This means that when we are on returning path from handler middlewares up in chain from this middleware
				// can not access these temporary files anymore because we deleted them here.
				if spanRequest.MultipartForm != nil {
					_ = spanRequest.MultipartForm.RemoveAll()
				}
			}()

			// serve the request to the next middleware
			err := next(c)
			if err != nil {
				span.SetAttributes(semconv.ErrorType(err))
				span.SetStatus(codes.Error, err.Error())
				if config.OnNextError != nil {
					config.OnNextError(c, err)
				}
			}

			resp, status := echo.ResolveResponseStatus(c.Response(), err)
			ev.HTTPResponseStatusCode = status
			if resp != nil {
				ev.HTTPResponseBodySize = resp.Size
			}

			endAttributes := ev.SpanEndAttributes()
			if config.SpanEndAttributes != nil {
				endAttributes = config.SpanEndAttributes(c, &ev, endAttributes)
			}
			span.SetAttributes(endAttributes...)

			// Record the server-side attributes.
			iv := RecordValues{
				RequestDuration: time.Since(requestStartTime),
				ExtractedValues: ev,
				Attributes:      nil,
			}
			if config.MetricAttributes != nil {
				iv.Attributes = config.MetricAttributes(c, &ev)
			}
			metrics.Record(c, iv)

			return err
		}
	}, nil
}

type echoMetricsRecorder struct {
	*Metrics
}

func (e *echoMetricsRecorder) Record(c *echo.Context, v RecordValues) {
	e.Metrics.Record(c.Request().Context(), v)
}
