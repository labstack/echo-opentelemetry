// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 LabStack and Echo contributors

package echootel

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/semconv/v1.39.0/httpconv"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	b3prop "go.opentelemetry.io/contrib/propagators/b3"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/metric/metricdata/metricdatatest"
)

func TestGetSpanNotInstrumented(t *testing.T) {
	router := echo.New()
	router.GET("/ping", func(c *echo.Context) error {
		// Assert we don't have a span on the context.
		span := trace.SpanFromContext(c.Request().Context())
		ok := !span.SpanContext().IsValid()
		assert.True(t, ok)
		return c.String(http.StatusOK, "ok")
	})
	r := httptest.NewRequest(http.MethodGet, "/ping", http.NoBody)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	response := w.Result()
	assert.Equal(t, http.StatusOK, response.StatusCode)
}

func TestPropagationWithGlobalPropagators(t *testing.T) {
	provider := noop.NewTracerProvider()
	otel.SetTextMapPropagator(propagation.TraceContext{})

	r := httptest.NewRequest(http.MethodGet, "/user/123", http.NoBody)
	w := httptest.NewRecorder()

	ctx := t.Context()
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{0x01},
		SpanID:  trace.SpanID{0x01},
	})
	ctx = trace.ContextWithRemoteSpanContext(ctx, sc)
	ctx, _ = provider.Tracer(ScopeName).Start(ctx, "test")
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(r.Header))

	router := echo.New()
	router.Use(NewMiddlewareWithConfig(Config{ServerName: "foobar", TracerProvider: provider}))
	router.GET("/user/:id", func(c *echo.Context) error {
		span := trace.SpanFromContext(c.Request().Context())
		assert.Equal(t, sc.TraceID(), span.SpanContext().TraceID())
		assert.Equal(t, sc.SpanID(), span.SpanContext().SpanID())
		return c.NoContent(http.StatusOK)
	})

	router.ServeHTTP(w, r)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
	assert.Equal(t, http.StatusOK, w.Result().StatusCode, "should call the 'user' handler")
}

func TestPropagationWithCustomPropagators(t *testing.T) {
	provider := noop.NewTracerProvider()

	b3 := b3prop.New()

	r := httptest.NewRequest(http.MethodGet, "/user/123", http.NoBody)
	w := httptest.NewRecorder()

	ctx := t.Context()
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{0x01},
		SpanID:  trace.SpanID{0x01},
	})
	ctx = trace.ContextWithRemoteSpanContext(ctx, sc)
	ctx, _ = provider.Tracer(ScopeName).Start(ctx, "test")
	b3.Inject(ctx, propagation.HeaderCarrier(r.Header))

	router := echo.New()
	router.Use(NewMiddlewareWithConfig(Config{ServerName: "foobar", TracerProvider: provider, Propagators: b3}))
	router.GET("/user/:id", func(c *echo.Context) error {
		span := trace.SpanFromContext(c.Request().Context())
		assert.Equal(t, sc.TraceID(), span.SpanContext().TraceID())
		assert.Equal(t, sc.SpanID(), span.SpanContext().SpanID())
		return c.NoContent(http.StatusOK)
	})

	router.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Result().StatusCode, "should call the 'user' handler")
}

func TestSkipper(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/ping", http.NoBody)
	w := httptest.NewRecorder()

	skipper := func(c *echo.Context) bool {
		return c.Request().RequestURI == "/ping"
	}

	router := echo.New()
	router.Use(NewMiddlewareWithConfig(Config{ServerName: "foobar", Skipper: skipper}))
	router.GET("/ping", func(c *echo.Context) error {
		span := trace.SpanFromContext(c.Request().Context())
		assert.False(t, span.SpanContext().HasSpanID())
		assert.False(t, span.SpanContext().HasTraceID())
		return c.NoContent(http.StatusOK)
	})

	router.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Result().StatusCode, "should call the 'ping' handler")
}

func TestMetrics(t *testing.T) {
	tests := []struct {
		name              string
		givenConfig       Config
		whenRequestTarget string
		expectAttr        []attribute.KeyValue
	}{
		{
			name:              "default",
			whenRequestTarget: "/user/123",
			expectAttr: []attribute.KeyValue{
				attribute.String("http.request.method", "GET"),
				attribute.Int64("http.response.status_code", 200),
				attribute.String("network.protocol.name", "http"),
				attribute.String("network.protocol.version", "1.1"),
				attribute.String("server.address", "foobar"),
				attribute.String("url.scheme", "http"),
				attribute.String("http.route", "/user/:id"),
			},
		},
		{
			name:              "request target not exist",
			whenRequestTarget: "/abc/123",
			expectAttr: []attribute.KeyValue{
				attribute.String("http.request.method", "GET"),
				attribute.Int64("http.response.status_code", 404),
				attribute.String("network.protocol.name", "http"),
				attribute.String("network.protocol.version", "1.1"),
				attribute.String("server.address", "foobar"),
				attribute.String("url.scheme", "http"),
			},
		},
		{
			name: "with metric attributes callback",
			givenConfig: Config{
				SpanStartAttributes: func(c *echo.Context, v *Values, attr []attribute.KeyValue) []attribute.KeyValue {
					return append(attr, attribute.String("key3", "value3")) // these are not used
				},
				MetricAttributes: func(c *echo.Context, v *Values) []attribute.KeyValue {
					return append(v.MetricAttributes(),
						attribute.String("key1", "value1"),
						attribute.String("key2", "value"),
						attribute.String("method", strings.ToUpper(c.Request().Method)),
					)
				},
			},
			whenRequestTarget: "/user/123",
			expectAttr: []attribute.KeyValue{
				attribute.String("http.request.method", "GET"),
				attribute.Int64("http.response.status_code", 200),
				attribute.String("network.protocol.name", "http"),
				attribute.String("network.protocol.version", "1.1"),
				attribute.String("server.address", "foobar"),
				attribute.String("url.scheme", "http"),
				attribute.String("http.route", "/user/:id"),
				attribute.String("key1", "value1"),
				attribute.String("key2", "value"),
				attribute.String("method", "GET"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reader := sdkmetric.NewManualReader()
			meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

			config := tc.givenConfig
			if config.ServerName == "" {
				config.ServerName = "foobar"
			}
			if config.MeterProvider == nil {
				config.MeterProvider = meterProvider
			}

			e := echo.New()
			e.Use(NewMiddlewareWithConfig(config))
			e.GET("/user/:id", func(c *echo.Context) error {
				id := c.Param("id")
				assert.Equal(t, "123", id)
				return c.String(http.StatusOK, id)
			})

			r := httptest.NewRequest(http.MethodGet, tc.whenRequestTarget, http.NoBody)
			w := httptest.NewRecorder()
			e.ServeHTTP(w, r)

			// verify metrics
			rm := metricdata.ResourceMetrics{}
			assert.NoError(t, reader.Collect(t.Context(), &rm))

			assert.Len(t, rm.ScopeMetrics, 1)
			sm := rm.ScopeMetrics[0]
			assert.Equal(t, ScopeName, sm.Scope.Name)
			assert.Equal(t, Version, sm.Scope.Version)

			metricdatatest.AssertEqual(t, metricdata.Metrics{
				Name:        "http.server.request.duration",
				Description: "Duration of HTTP server requests.",
				Unit:        "s",
				Data: metricdata.Histogram[float64]{
					Temporality: metricdata.CumulativeTemporality,
					DataPoints: []metricdata.HistogramDataPoint[float64]{
						{
							Attributes: attribute.NewSet(tc.expectAttr...),
						},
					},
				},
			}, sm.Metrics[0], metricdatatest.IgnoreTimestamp(), metricdatatest.IgnoreValue(), metricdatatest.IgnoreExemplars())

			metricdatatest.AssertEqual(t, metricdata.Metrics{
				Name:        "http.server.request.body.size",
				Description: "Size of HTTP server request bodies.",
				Unit:        "By",
				Data: metricdata.Histogram[int64]{
					Temporality: metricdata.CumulativeTemporality,
					DataPoints: []metricdata.HistogramDataPoint[int64]{
						{
							Attributes: attribute.NewSet(tc.expectAttr...),
						},
					},
				},
			}, sm.Metrics[1], metricdatatest.IgnoreTimestamp(), metricdatatest.IgnoreValue(), metricdatatest.IgnoreExemplars())

			metricdatatest.AssertEqual(t, metricdata.Metrics{
				Name:        "http.server.response.body.size",
				Description: "Size of HTTP server response bodies.",
				Unit:        "By",
				Data: metricdata.Histogram[int64]{
					Temporality: metricdata.CumulativeTemporality,
					DataPoints: []metricdata.HistogramDataPoint[int64]{
						{
							Attributes: attribute.NewSet(tc.expectAttr...),
						},
					},
				},
			}, sm.Metrics[2], metricdatatest.IgnoreTimestamp(), metricdatatest.IgnoreValue(), metricdatatest.IgnoreExemplars())
		})
	}
}

func TestWithMetricAttributeFn(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	e := echo.New()
	e.Use(NewMiddlewareWithConfig(Config{
		ServerName:    "test-service",
		MeterProvider: meterProvider,
		MetricAttributes: func(c *echo.Context, v *Values) []attribute.KeyValue {
			return append(
				v.MetricAttributes(),
				attribute.String("custom.header", c.Request().Header.Get("X-Test-Header")),
			)
		},
	}))

	e.GET("/test", func(c *echo.Context) error {
		return c.String(http.StatusOK, "test response")
	})

	r := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	r.Header.Set("X-Test-Header", "test-value")
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Result().StatusCode)

	// verify metrics
	rm := metricdata.ResourceMetrics{}
	assert.NoError(t, reader.Collect(t.Context(), &rm))
	assert.Len(t, rm.ScopeMetrics, 1)
	sm := rm.ScopeMetrics[0]
	assert.Len(t, sm.Metrics, 3)

	// Check that custom attribute is present
	found := false
	for _, metric := range sm.Metrics {
		if metric.Name == "http.server.request.duration" {
			histogram := metric.Data.(metricdata.Histogram[float64])
			assert.Len(t, histogram.DataPoints, 1)
			attrs := histogram.DataPoints[0].Attributes.ToSlice()
			for _, attr := range attrs {
				if attr.Key == "custom.header" && attr.Value.AsString() == "test-value" {
					found = true
					break
				}
			}
		}
	}
	assert.True(t, found, "custom attribute should be found in metrics")
}

func TestWithEchoMetricAttributeFn(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	e := echo.New()
	e.Use(NewMiddlewareWithConfig(Config{
		ServerName:    "test-service",
		MeterProvider: meterProvider,
		MetricAttributes: func(c *echo.Context, v *Values) []attribute.KeyValue {
			return append(
				v.MetricAttributes(),
				// This is just for testing. Avoid high cardinality metrics such as "id" in production code
				attribute.String("echo.param.id", c.Param("id")),
				attribute.String("echo.path", c.Path()),
			)
		},
	}))

	e.GET("/user/:id", func(c *echo.Context) error {
		return c.String(http.StatusOK, "user: "+c.Param("id"))
	})

	r := httptest.NewRequest(http.MethodGet, "/user/456", http.NoBody)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Result().StatusCode)

	// verify metrics
	rm := metricdata.ResourceMetrics{}
	assert.NoError(t, reader.Collect(t.Context(), &rm))
	assert.Len(t, rm.ScopeMetrics, 1)
	sm := rm.ScopeMetrics[0]
	assert.Len(t, sm.Metrics, 3)

	// Check that custom attributes are present
	foundID := false
	foundPath := false
	for _, metric := range sm.Metrics {
		if metric.Name == "http.server.request.duration" {
			histogram := metric.Data.(metricdata.Histogram[float64])
			assert.Len(t, histogram.DataPoints, 1)
			attrs := histogram.DataPoints[0].Attributes.ToSlice()
			for _, attr := range attrs {
				if attr.Key == "echo.param.id" && attr.Value.AsString() == "456" {
					foundID = true
				}
				if attr.Key == "echo.path" && attr.Value.AsString() == "/user/:id" {
					foundPath = true
				}
			}
		}
	}
	assert.True(t, foundID, "echo param id attribute should be found")
	assert.True(t, foundPath, "echo path attribute should be found")
}

type customMetrics struct {
	requestDurationHistogram httpconv.ServerRequestDuration
}

func newCustomMetrics(meter metric.Meter) *customMetrics {
	reqDuration, _ := httpconv.NewServerRequestDuration(
		meter,
		metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10),
	)
	return &customMetrics{
		requestDurationHistogram: reqDuration,
	}
}

func (m *customMetrics) Record(c *echo.Context, v RecordValues) {
	o := metric.WithAttributeSet(attribute.NewSet(v.ExtractedValues.MetricAttributes()...))
	m.requestDurationHistogram.Inst().Record(c.Request().Context(), v.RequestDuration.Seconds(), o)
}

func TestNewMiddlewareWithConfig_Metric(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	config := Config{
		ServerName: "foobar",
		Metrics:    newCustomMetrics(meterProvider.Meter(ScopeName, metric.WithInstrumentationVersion(Version))),
	}

	e := echo.New()
	e.Use(NewMiddlewareWithConfig(config))
	e.GET("/user/:id", func(c *echo.Context) error {
		id := c.Param("id")
		assert.Equal(t, "123", id)
		return c.String(http.StatusOK, id)
	})

	r := httptest.NewRequest(http.MethodGet, "/user/123", http.NoBody)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)

	// verify metrics
	rm := metricdata.ResourceMetrics{}
	assert.NoError(t, reader.Collect(t.Context(), &rm))

	assert.Len(t, rm.ScopeMetrics, 1)
	sm := rm.ScopeMetrics[0]
	assert.Len(t, sm.Metrics, 1)
	assert.Equal(t, ScopeName, sm.Scope.Name)
	assert.Equal(t, Version, sm.Scope.Version)

	metricdatatest.AssertEqual(t, metricdata.Metrics{
		Name:        "http.server.request.duration",
		Description: "Duration of HTTP server requests.",
		Unit:        "s",
		Data: metricdata.Histogram[float64]{
			Temporality: metricdata.CumulativeTemporality,
			DataPoints: []metricdata.HistogramDataPoint[float64]{
				{
					Attributes: attribute.NewSet([]attribute.KeyValue{
						attribute.String("http.request.method", "GET"),
						attribute.Int64("http.response.status_code", 200),
						attribute.String("network.protocol.name", "http"),
						attribute.String("network.protocol.version", "1.1"),
						attribute.String("server.address", "foobar"),
						attribute.String("url.scheme", "http"),
						attribute.String("http.route", "/user/:id"),
					}...),
				},
			},
		},
	}, sm.Metrics[0], metricdatatest.IgnoreTimestamp(), metricdatatest.IgnoreValue(), metricdatatest.IgnoreExemplars())
}

func TestWithOnError(t *testing.T) {
	tests := []struct {
		name              string
		GivenOnErrorFunc  OnErrorFunc
		wantHandlerCalled int
	}{
		{
			name:              "without WithOnError option (default)",
			GivenOnErrorFunc:  nil,
			wantHandlerCalled: 1,
		},
		{
			name: "custom onError logging only",
			GivenOnErrorFunc: func(_ *echo.Context, err error) {
				t.Logf("Inside custom OnError: %v", err)
			},
			wantHandlerCalled: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/ping", http.NoBody)
			w := httptest.NewRecorder()

			router := echo.New()
			router.Use(NewMiddlewareWithConfig(Config{ServerName: "foobar", OnError: tt.GivenOnErrorFunc}))

			router.GET("/ping", func(_ *echo.Context) error {
				return assert.AnError
			})

			handlerCalled := 0
			router.HTTPErrorHandler = func(c *echo.Context, err error) {
				handlerCalled++
				assert.ErrorIs(t, err, assert.AnError, "test error is expected in error handler")
				assert.NoError(t, c.NoContent(http.StatusTeapot))
			}

			router.ServeHTTP(w, r)
			assert.Equal(t, http.StatusTeapot, w.Result().StatusCode, "should call the 'ping' handler")
			assert.Equal(t, tt.wantHandlerCalled, handlerCalled, "handler called times mismatch")
		})
	}
}
