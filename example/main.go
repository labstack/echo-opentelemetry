// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// This example is based on:
// https://github.com/open-telemetry/opentelemetry-go-contrib/blob/8c7ab5313db0dbbaf65bd1c79b9c28f1e8c5b40d/instrumentation/github.com/labstack/echo/otelecho/example/server.go

package main

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/labstack/echo-opentelemetry/echootel"
	"github.com/labstack/echo/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

type user struct {
	ID   string
	Name string
}

// Try with `curl -v http://localhost:8080/users/123`
func main() {
	tp, err := initTracer()
	if err != nil {
		slog.Error("Failed to initialize otel tracer", "error", err)
		return
	}
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			slog.Error("Failed to shutdown tracer provider", "error", err)
		}
	}()

	e := echo.New()
	e.Use(echootel.NewMiddlewareWithConfig(echootel.Config{
		ServerName:     "my-server",
		TracerProvider: tp,
	}))

	e.GET("/users/:id", func(c *echo.Context) error {
		u := user{
			ID:   c.Param("id"),
			Name: "",
		}
		u.Name, _ = traceGetUser(c, u.ID)
		return c.JSON(http.StatusOK, u)
	})
	if err := e.Start(":8080"); err != nil {
		e.Logger.Error("Failed to start echo server", "error", err)
	}
}

func initTracer() (*sdktrace.TracerProvider, error) {
	exporter, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exporter),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	return tp, nil
}

func traceGetUser(c *echo.Context, id string) (string, error) {
	tp, err := echo.ContextGet[trace.Tracer](c, echootel.TracerKey)
	if err != nil {
		return "", err
	}

	_, span := tp.Start(c.Request().Context(), "getUser", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()
	if id == "123" {
		return "otelecho tester", nil
	}
	return "unknown", nil
}
