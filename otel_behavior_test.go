// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 LabStack and Echo contributors

package echootel

import (
	"bytes"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

func newTestProviders() (*tracetest.InMemoryExporter, *sdktrace.TracerProvider, *sdkmetric.ManualReader, *sdkmetric.MeterProvider) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	return exporter, tp, reader, mp
}

// durationPoints returns the attribute sets of the http.server.request.duration data points.
func durationPoints(t *testing.T, reader *sdkmetric.ManualReader) []attribute.Set {
	t.Helper()
	rm := metricdata.ResourceMetrics{}
	assert.NoError(t, reader.Collect(t.Context(), &rm))
	var sets []attribute.Set
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "http.server.request.duration" {
				continue
			}
			for _, dp := range m.Data.(metricdata.Histogram[float64]).DataPoints {
				sets = append(sets, dp.Attributes)
			}
		}
	}
	return sets
}

func metricHas(set attribute.Set, key attribute.Key) bool {
	_, ok := set.Value(key)
	return ok
}

func TestPanicIsRecordedAndRepanicked(t *testing.T) {
	exporter, tp, reader, mp := newTestProviders()

	e := echo.New()
	e.Use(middleware.Recover()) // usual order: Recover wraps the otel middleware
	e.Use(NewMiddlewareWithConfig(Config{ServerName: "foobar", TracerProvider: tp, MeterProvider: mp}))
	e.GET("/panic", func(c *echo.Context) error {
		panic("boom")
	})

	w := httptest.NewRecorder()
	e.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/panic", http.NoBody))

	assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode, "Recover must still handle the panic")
	spans := exporter.GetSpans()
	if !assert.Len(t, spans, 1) {
		return
	}
	assert.Equal(t, codes.Error, spans[0].Status.Code)
	assert.Equal(t, "panic: boom", spans[0].Status.Description)
	assert.Contains(t, spans[0].Attributes, attribute.Int("http.response.status_code", http.StatusInternalServerError))
	assert.Contains(t, spans[0].Attributes, attribute.String("error.type", "panic"))

	points := durationPoints(t, reader)
	if assert.Len(t, points, 1) {
		v, ok := points[0].Value("error.type")
		assert.True(t, ok)
		assert.Equal(t, "panic", v.AsString())
	}
}

func TestUnknownRequestBodySizeIsNotRecorded(t *testing.T) {
	exporter, tp, reader, mp := newTestProviders()

	e := echo.New()
	e.Use(NewMiddlewareWithConfig(Config{ServerName: "foobar", TracerProvider: tp, MeterProvider: mp}))
	e.POST("/upload", func(c *echo.Context) error {
		_, _ = io.Copy(io.Discard, c.Request().Body)
		return c.NoContent(http.StatusNoContent)
	})

	r := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader([]byte("chunked body")))
	r.ContentLength = -1 // unknown size, as for a chunked request
	e.ServeHTTP(httptest.NewRecorder(), r)

	spans := exporter.GetSpans()
	assert.Len(t, spans, 1)
	for _, a := range spans[0].Attributes {
		assert.NotEqual(t, attribute.Key("http.request.body.size"), a.Key)
	}

	rm := metricdata.ResourceMetrics{}
	assert.NoError(t, reader.Collect(t.Context(), &rm))
	for _, m := range rm.ScopeMetrics[0].Metrics {
		if m.Name == "http.server.request.body.size" {
			assert.Empty(t, m.Data.(metricdata.Histogram[int64]).DataPoints, "unknown size must not be recorded")
		}
	}
}

func TestMetricsHaveNoClientChosenAttributes(t *testing.T) {
	exporter, tp, reader, mp := newTestProviders()

	e := echo.New()
	e.Use(NewMiddlewareWithConfig(Config{ServerName: "api.example.com", TracerProvider: tp, MeterProvider: mp}))
	e.Any("/x", func(c *echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	r := httptest.NewRequest("FOO", "/x", http.NoBody)
	r.Host = "evil.example.com:1234"
	e.ServeHTTP(httptest.NewRecorder(), r)

	spans := exporter.GetSpans()
	assert.Len(t, spans, 1)
	assert.Contains(t, spans[0].Attributes, attribute.String("server.address", "api.example.com"))
	assert.Contains(t, spans[0].Attributes, attribute.String("http.request.method_original", "FOO"))
	for _, a := range spans[0].Attributes {
		assert.NotEqual(t, attribute.Key("server.port"), a.Key, "port must not come from the Host header when ServerName is set")
	}

	points := durationPoints(t, reader)
	if assert.Len(t, points, 1) {
		assert.False(t, metricHas(points[0], "server.address"))
		assert.False(t, metricHas(points[0], "server.port"))
		assert.False(t, metricHas(points[0], "http.request.method_original"))
		m, _ := points[0].Value("http.request.method")
		assert.Equal(t, "_OTHER", m.AsString())
	}
}

func TestHTTPRouteIsEchoRouteBehindServeMux(t *testing.T) {
	testCases := []struct {
		name       string
		pre        bool
		whenTarget string
		expectName string
		expectPath string
	}{
		{name: "Pre middleware, matched route", pre: true, whenTarget: "/api/users/1", expectName: "GET /api/users/:id", expectPath: "/api/users/:id"},
		{name: "Use middleware, matched route", pre: false, whenTarget: "/api/users/1", expectName: "GET /api/users/:id", expectPath: "/api/users/:id"},
		{name: "Pre middleware, not found", pre: true, whenTarget: "/api/nothing", expectName: "GET"},
		{name: "Use middleware, not found", pre: false, whenTarget: "/api/nothing", expectName: "GET"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			exporter, tp, _, mp := newTestProviders()

			e := echo.New()
			mw := NewMiddlewareWithConfig(Config{ServerName: "foobar", TracerProvider: tp, MeterProvider: mp})
			if tc.pre {
				e.Pre(mw)
			} else {
				e.Use(mw)
			}
			e.GET("/api/users/:id", func(c *echo.Context) error {
				return c.NoContent(http.StatusOK)
			})

			mux := http.NewServeMux()
			mux.Handle("GET /api/", e)

			mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, tc.whenTarget, http.NoBody))

			spans := exporter.GetSpans()
			assert.Len(t, spans, 1)
			assert.Equal(t, tc.expectName, spans[0].Name)
			route := ""
			for _, a := range spans[0].Attributes {
				if a.Key == "http.route" {
					route = a.Value.AsString()
				}
			}
			assert.Equal(t, tc.expectPath, route)
		})
	}
}

func TestOnExtractionError(t *testing.T) {
	var got error
	e := echo.New()
	e.Use(NewMiddlewareWithConfig(Config{OnExtractionError: func(c *echo.Context, err error) { got = err }}))
	e.GET("/x", func(c *echo.Context) error { return c.NoContent(http.StatusOK) })

	r := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	r.Host = "bad:host:name:1"
	e.ServeHTTP(httptest.NewRecorder(), r)

	assert.Error(t, got)
}

func TestSpanStartOptionsAndTracerKey(t *testing.T) {
	exporter, tp, _, _ := newTestProviders()

	e := echo.New()
	e.Use(NewMiddlewareWithConfig(Config{
		ServerName:       "foobar",
		TracerProvider:   tp,
		SpanStartOptions: []trace.SpanStartOption{trace.WithAttributes(attribute.String("custom", "yes"))},
	}))
	e.GET("/x", func(c *echo.Context) error {
		tracer, err := echo.ContextGet[trace.Tracer](c, TracerKey)
		if assert.NoError(t, err) {
			_, child := tracer.Start(c.Request().Context(), "child")
			child.End()
		}
		return c.NoContent(http.StatusOK)
	})
	e.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", http.NoBody))

	spans := exporter.GetSpans()
	assert.Len(t, spans, 2)
	server := spans[1]
	assert.Contains(t, server.Attributes, attribute.String("custom", "yes"))
	assert.Equal(t, server.SpanContext.TraceID(), spans[0].SpanContext.TraceID(), "child span must be in the same trace")
}

func TestSpanEndAttributesCallbackMustAppend(t *testing.T) {
	testCases := []struct {
		name          string
		callback      AttributesFunc
		expectErrType bool
	}{
		{
			name: "append to attr keeps error.type",
			callback: func(c *echo.Context, v *Values, attr []attribute.KeyValue) []attribute.KeyValue {
				return append(attr, attribute.String("extra", "1"))
			},
			expectErrType: true,
		},
		{
			name: "new slice drops error.type",
			callback: func(c *echo.Context, v *Values, attr []attribute.KeyValue) []attribute.KeyValue {
				return []attribute.KeyValue{attribute.String("extra", "1")}
			},
			expectErrType: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			exporter, tp, _, _ := newTestProviders()
			e := echo.New()
			e.Use(NewMiddlewareWithConfig(Config{ServerName: "foobar", TracerProvider: tp, SpanEndAttributes: tc.callback}))
			e.GET("/x", func(c *echo.Context) error { return c.NoContent(http.StatusServiceUnavailable) })
			e.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", http.NoBody))

			spans := exporter.GetSpans()
			assert.Len(t, spans, 1)
			assert.Contains(t, spans[0].Attributes, attribute.String("extra", "1"))
			has := false
			for _, a := range spans[0].Attributes {
				if a.Key == "error.type" {
					has = true
				}
			}
			assert.Equal(t, tc.expectErrType, has)
		})
	}
}

func TestMultipartFormTempFilesAreRemoved(t *testing.T) {
	var tmpFile string
	e := echo.New()
	e.Use(NewMiddleware("foobar"))
	e.POST("/upload", func(c *echo.Context) error {
		if err := c.Request().ParseMultipartForm(1); err != nil { // tiny memory limit forces a temp file
			return err
		}
		f, err := c.Request().MultipartForm.File["file"][0].Open()
		if err != nil {
			return err
		}
		defer f.Close()
		osFile, ok := f.(*os.File)
		if assert.True(t, ok, "upload must be stored in a temp file") {
			tmpFile = osFile.Name()
		}
		return c.NoContent(http.StatusOK)
	})

	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	fw, _ := mw.CreateFormFile("file", "big.txt")
	_, _ = fw.Write(bytes.Repeat([]byte("x"), 64*1024))
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/upload", body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Result().StatusCode)
	if assert.NotEmpty(t, tmpFile) {
		_, err := os.Stat(tmpFile)
		assert.True(t, os.IsNotExist(err), "temp file must be removed after the request")
	}
}

func TestPanicPaths(t *testing.T) {
	testCases := []struct {
		name            string
		recover         bool
		config          func(cfg *Config)
		handler         echo.HandlerFunc
		expectRepanic   any
		expectStatus    int // 0 = no http.response.status_code attribute
		expectErrorType string
	}{
		{
			name:            "panic after 4xx response was sent is still an error",
			recover:         true,
			handler:         func(c *echo.Context) error { _ = c.NoContent(http.StatusNotFound); panic("late") },
			expectStatus:    http.StatusNotFound,
			expectErrorType: "panic",
		},
		{
			name:            "panic with a status error records its status",
			recover:         true,
			handler:         func(c *echo.Context) error { panic(echo.ErrUnauthorized) },
			expectStatus:    http.StatusUnauthorized,
			expectErrorType: "panic",
		},
		{
			name:            "http.ErrAbortHandler without response records no status",
			recover:         false,
			handler:         func(c *echo.Context) error { panic(http.ErrAbortHandler) },
			expectRepanic:   http.ErrAbortHandler,
			expectStatus:    0,
			expectErrorType: "panic",
		},
		{
			name:    "panic in OnNextError is recorded",
			recover: true,
			config: func(cfg *Config) {
				cfg.OnNextError = func(c *echo.Context, err error) { panic("hook") }
			},
			handler:         func(c *echo.Context) error { return errors.New("x") },
			expectStatus:    http.StatusInternalServerError,
			expectErrorType: "panic",
		},
		{
			name:    "panic in a recording callback keeps the original panic value",
			recover: false,
			config: func(cfg *Config) {
				cfg.SpanEndAttributes = func(c *echo.Context, v *Values, attr []attribute.KeyValue) []attribute.KeyValue {
					panic("callback")
				}
			},
			handler:       func(c *echo.Context) error { panic("original") },
			expectRepanic: "original",
			expectStatus:  -1, // not checked, recording was interrupted
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			exporter, tp, _, mp := newTestProviders()
			cfg := Config{ServerName: "foobar", TracerProvider: tp, MeterProvider: mp}
			if tc.config != nil {
				tc.config(&cfg)
			}
			e := echo.New()
			if tc.recover {
				e.Use(middleware.Recover())
			}
			e.Use(NewMiddlewareWithConfig(cfg))
			e.GET("/x", tc.handler)

			var repanic any
			func() {
				defer func() { repanic = recover() }()
				e.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", http.NoBody))
			}()
			if tc.expectRepanic != nil {
				assert.Equal(t, tc.expectRepanic, repanic)
			}
			if tc.expectStatus < 0 {
				return
			}
			spans := exporter.GetSpans()
			if !assert.Len(t, spans, 1) {
				return
			}
			assert.Equal(t, codes.Error, spans[0].Status.Code)
			var gotStatus int64
			var gotErrType string
			for _, a := range spans[0].Attributes {
				switch a.Key {
				case "http.response.status_code":
					gotStatus = a.Value.AsInt64()
				case "error.type":
					gotErrType = a.Value.AsString()
				}
			}
			assert.Equal(t, int64(tc.expectStatus), gotStatus)
			assert.Equal(t, tc.expectErrorType, gotErrType)
		})
	}
}

func TestRecoverAddedAfterMiddlewareReportsPanic(t *testing.T) {
	exporter, tp, _, mp := newTestProviders()
	e := echo.New()
	e.Use(NewMiddlewareWithConfig(Config{ServerName: "foobar", TracerProvider: tp, MeterProvider: mp}))
	e.Use(middleware.Recover()) // Recover inside turns the panic into *middleware.PanicStackError
	e.GET("/x", func(c *echo.Context) error { panic("boom") })
	e.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", http.NoBody))

	spans := exporter.GetSpans()
	if assert.Len(t, spans, 1) {
		assert.Equal(t, codes.Error, spans[0].Status.Code)
		assert.Equal(t, "panic: boom", spans[0].Status.Description)
		assert.Contains(t, spans[0].Attributes, attribute.String("error.type", "panic"))
	}
}

func TestServerNameWithoutHostIsRejected(t *testing.T) {
	_, err := Config{ServerName: ":8080"}.ToMiddleware()
	assert.Error(t, err)
}

func BenchmarkMiddleware(b *testing.B) {
	benchmarks := []struct {
		name string
		tp   trace.TracerProvider
		mp   *sdkmetric.MeterProvider
	}{
		{name: "noop providers"},
		{name: "sdk providers", tp: sdktrace.NewTracerProvider(), mp: sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewManualReader()))},
	}
	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			cfg := Config{ServerName: "foobar", TracerProvider: tracenoop.NewTracerProvider(), MeterProvider: metricnoop.NewMeterProvider()}
			if bm.tp != nil {
				cfg.TracerProvider = bm.tp
				cfg.MeterProvider = bm.mp
			}
			e := echo.New()
			e.Use(NewMiddlewareWithConfig(cfg))
			e.GET("/users/:id", func(c *echo.Context) error { return c.String(http.StatusOK, "ok") })
			r := httptest.NewRequest(http.MethodGet, "/users/123?x=1", http.NoBody)
			r.Header.Set("User-Agent", "bench")

			b.ReportAllocs()
			for b.Loop() {
				e.ServeHTTP(httptest.NewRecorder(), r)
			}
		})
	}
}
