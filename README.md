[![Sourcegraph](https://sourcegraph.com/github.com/labstack/echo-opentelemetry/-/badge.svg?style=flat-square)](https://sourcegraph.com/github.com/labstack/echo-opentelemetry?badge)
[![GoDoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](https://pkg.go.dev/github.com/labstack/echo-opentelemetry)
[![Go Report Card](https://goreportcard.com/badge/github.com/labstack/echo-opentelemetry?style=flat-square)](https://goreportcard.com/report/github.com/labstack/echo-opentelemetry)
[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/labstack/echo-opentelemetry/main/LICENSE)

# Echo OpenTelemetry (OTel) middleware

[OpenTelemetry](https://opentelemetry.io/) middleware for [Echo](https://github.com/labstack/echo) framework.

* [OpenTelemetry HTTP spec](https://opentelemetry.io/docs/specs/semconv/http/)
* [HTTP metrics spec](https://opentelemetry.io/docs/specs/semconv/http/http-metrics/)


## Versioning

* version `v0.x.y` tracks the latest Echo version (`v5`).
* `main` branch is compatible with the latest Echo version (`v5`).

## Usage

Add OpenTelemetry middleware dependency with go modules

```bash
go get github.com/labstack/echo-opentelemetry
```

Use as an import statement

```go
import echootel "github.com/labstack/echo-opentelemetry"
```

Add middleware in simplified form, by providing only the server name

```go
e.Use(echootel.NewMiddleware("app.example.com"))
```

Add middleware with configuration options

```go
e.Use(echootel.NewMiddlewareWithConfig(echootel.Config{
  TracerProvider: tp,
}))
```

### Public (internet-facing) endpoints

By default, the middleware trusts the incoming trace context (e.g. `traceparent` header) and continues
that trace as the parent of the server span. For endpoints exposed to untrusted clients this allows
callers to inject arbitrary trace IDs into your traces or suppress tracing entirely with a
`sampled=0` flag.

Set `PublicEndpointFn` to start a new trace instead. The incoming trace context,
if present, is recorded as a span link rather than being used as the parent. To treat every
request as public:

```go
e.Use(echootel.NewMiddlewareWithConfig(echootel.Config{
  PublicEndpointFn: func(c *echo.Context, remote trace.SpanContext) bool { return true },
}))
```

The decision is made per request, so the same server can serve both internal and public routes

```go
e.Use(echootel.NewMiddlewareWithConfig(echootel.Config{
  PublicEndpointFn: func(c *echo.Context, remote trace.SpanContext) bool {
    return !strings.HasPrefix(c.Request().URL.Path, "/internal/")
  },
}))
```

The second argument is the remote span context extracted from the incoming request, so the
decision can also be based on the incoming trace context itself.

Retrieving the tracer from the Echo context
```go
tp, err := echo.ContextGet[trace.Tracer](c, echootel.TracerKey)
```

## Full example

See [example](example/main.go)
