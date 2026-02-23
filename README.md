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

Retrieving the tracer from the Echo context
```go
tp, err := echo.ContextGet[trace.Tracer](c, echootel.TracerKey)
```

## Full example

See [example](example/main.go)
