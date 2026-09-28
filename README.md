[![Sourcegraph](https://sourcegraph.com/github.com/labstack/echo-otel/-/badge.svg?style=flat-square)](https://sourcegraph.com/github.com/labstack/echo-otel?badge)
[![GoDoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](https://pkg.go.dev/github.com/labstack/echo-otel/v4)
[![Go Report Card](https://goreportcard.com/badge/github.com/labstack/echo-otel?style=flat-square)](https://goreportcard.com/report/github.com/labstack/echo-otel)
[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/labstack/echo-otel/main/LICENSE)

# Echo OpenTelemetry (OTel) middleware

[OpenTelemetry](https://opentelemetry.io/) middleware for [Echo](https://github.com/labstack/echo) framework.

* [OpenTelemetry HTTP spec](https://opentelemetry.io/docs/specs/semconv/http/)
* [HTTP metrics spec](https://opentelemetry.io/docs/specs/semconv/http/http-metrics/)

## Versioning

This repository does not use semantic versioning. MAJOR version tracks which Echo version should be used. MINOR version
tracks API changes (possibly backwards incompatible) and PATCH version is incremented for fixes.

| Echo | Module | Branch | Minimal Echo version |
|---|---|---|---|
| v5 | `github.com/labstack/echo-otel/v5` | `main` | `v5.2.1` |
| v4 | `github.com/labstack/echo-otel/v4` | `v4` | `v4.15.4` |

This is the `v4` branch, for Echo v4. `github.com/labstack/echo-opentelemetry` (`v0.0.x`, Echo v5) is the
previous name of this project and is deprecated.

Always include the MAJOR version suffix (`/v5` or `/v4`) in `go get` and imports. Without it,
`go get github.com/labstack/echo-otel` fails.

## Usage

Add OpenTelemetry middleware dependency with go modules

```bash
go get github.com/labstack/echo-otel/v4
```

Use as an import statement

```go
import echootel "github.com/labstack/echo-otel/v4"
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
tracer, ok := c.Get(echootel.TracerKey).(trace.Tracer)
```

## Full example

See [example](example/main.go)

## Custom error handler

The middleware resolves the response status code for returned errors the same way as Echo's
`DefaultHTTPErrorHandler` does (see `echootel.ResolveResponseStatus`). If you use a custom `HTTPErrorHandler` that maps
errors to other status codes, let the middleware run the error handler, so it reports the status code that was actually
sent:

```go
e.Use(echootel.NewMiddlewareWithConfig(echootel.Config{
  ServerName:  "app.example.com",
  OnNextError: func(c echo.Context, err error) { c.Error(err) },
}))
```

This is what `otelecho` did by default. The error is still returned, so the error handler is called again; make it
return early when `c.Response().Committed` is true, as `DefaultHTTPErrorHandler` does.

## Migrating from otelecho

`go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho` is deprecated and removed from
opentelemetry-go-contrib in favor of this library.
For Echo v5 use `github.com/labstack/echo-otel/v5`. For Echo v4 use `github.com/labstack/echo-otel/v4`, there is no
need to migrate to Echo v5 first.

Replace `otelecho.Middleware("my-server", opts...)` with `echootel.NewMiddleware("my-server")`, or with
`echootel.NewMiddlewareWithConfig(echootel.Config{...})` when you use options.
The server name is used as `server.address` and `server.port`, so it must be a host name with an optional port,
for example `api.example.com` or `api.example.com:8080` (otelecho accepted any string); `NewMiddleware` panics on an
invalid value such as `:8080` (no host), `Config.ToMiddleware` returns an error, and an empty `ServerName` uses the
request `Host`:

| otelecho option | echootel.Config field |
|---|---|
| `otelecho.WithTracerProvider(tp)` | `TracerProvider: tp` |
| `otelecho.WithMeterProvider(mp)` | `MeterProvider: mp` |
| `otelecho.WithPropagators(p)` | `Propagators: p` |
| `otelecho.WithSkipper(s)` | `Skipper: s` |
| `otelecho.WithMetricAttributeFn(f)` | `MetricAttributes` (see below) |
| `otelecho.WithEchoMetricAttributeFn(f)` | `MetricAttributes` (see below) |
| `otelecho.WithOnError(f)` | `OnNextError` (and `OnExtractionError` for request extraction failures) |

Also note:

* `MetricAttributes` replaces the default metric attributes (otelecho appended to them), so return
  `append(v.MetricAttributes(), extra...)`.
* otelecho called the Echo error handler from the middleware by default (`c.Error(err)`); echootel does not. See
  [Custom error handler](#custom-error-handler) for how to get the same behavior.
* The instrumentation scope name changes from
  `go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho`
  to `github.com/labstack/echo-otel/v4`. Update dashboards and alerts that filter on it.
* The `echo.error` span attribute is not set; use `error.type` and the span status instead.

## Errors

A request that ends with an error sets `error.type` on the span and on the metrics, as the semantic conventions
require. The rules match the span status:

* a 4xx response is not an error for server spans: no `error.type`,
* a 5xx response without a returned error, with a returned `*echo.HTTPError` (not wrapped, as Echo's
  `DefaultHTTPErrorHandler` only recognizes it directly), or with a returned error that has a `StatusCode() int` method,
  reports the status code that was sent, for example `500`,
* any other returned error reports its Go type, for example `*net.OpError`. Errors created with
  `fmt.Errorf("...: %w", err)` are unwrapped first; errors joining several errors (`errors.Join`, `fmt.Errorf` with
  more than one `%w`) report their own type. An `ErrorType() string` method anywhere in the error chain takes
  precedence; keep its values low cardinality, as `error.type` is also a metric attribute.
* an invalid status code without a returned error reports `_OTHER` (below 100 or above 999) or the code itself
  (600-999),
* a panic reports `panic`, also when a 4xx response was already sent.

The middleware records a panic and then re-panics, so add a Recover middleware before this middleware
(`e.Use(middleware.Recover())` first). The recorded status is the status of the response that was already sent, the
status of a panic value of type `*echo.HTTPError`, or 500. A Recover middleware added after this middleware (with the
default configuration) calls the error handler itself, so the middleware sees a 500 response without an error and
reports `error.type` `500`.

`error.type` is part of the span end attributes. A `Config.SpanEndAttributes` callback must append to the `attr`
argument and return it, otherwise `error.type` and the other end attributes are dropped.

## Spans

Spans follow the [HTTP server span](https://opentelemetry.io/docs/specs/semconv/http/http-spans/#http-server) semantic
conventions, with these exceptions:

* `url.query` is not set. The query string can contain sensitive data, and the semantic conventions require redacting
  it. `http.request.body.size` and `http.response.body.size` are Opt-In and not set either.
* `http.response.status_code` is not set when no response was sent, for example after an `http.ErrAbortHandler` panic.

`client.address` comes from `c.RealIP()`. Without `Echo.IPExtractor`, Echo v4 takes it from the `X-Forwarded-For` and
`X-Real-IP` headers, which any client can set. Set `e.IPExtractor` to match your deployment, for example
`echo.ExtractIPDirect()` when there is no proxy in front of the server.

Add attributes with `SpanStartAttributes` and `SpanEndAttributes`. Both callbacks must append to the `attr` argument and
return it:

```go
SpanStartAttributes: func(c echo.Context, v *echootel.Values, attr []attribute.KeyValue) []attribute.KeyValue {
  if q := c.Request().URL.RawQuery; q != "" {
    attr = append(attr, semconv.URLQuery(redactQuery(q))) // redactQuery is your own function
  }
  return attr
},
SpanEndAttributes: func(c echo.Context, v *echootel.Values, attr []attribute.KeyValue) []attribute.KeyValue {
  if v.HTTPRequestBodySize >= 0 {
    attr = append(attr, semconv.HTTPRequestBodySize(int(v.HTTPRequestBodySize)))
  }
  return append(attr, semconv.HTTPResponseBodySize(int(v.HTTPResponseBodySize)))
},
```

## Metrics

The middleware records `http.server.request.duration`, `http.server.request.body.size` and
`http.server.response.body.size` with these attributes: `http.request.method`, `url.scheme`, `http.route`,
`network.protocol.name`, `network.protocol.version`, `http.response.status_code` and `error.type`.

`server.address`, `server.port` and `http.request.method_original` are Opt-In for metrics in the semantic conventions
and are not added: the `Host` header and the request method are chosen by the client and would make metric cardinality
unbounded. Add attributes with a known set of values with `MetricAttributes`, for example:

```go
MetricAttributes: func(c echo.Context, v *echootel.Values) []attribute.KeyValue {
  return append(v.MetricAttributes(), semconv.ServerAddress("api.example.com"))
},
```

## Known limitations

* Hijacked connections (for example WebSocket upgrades) are reported with the status code that Echo's response has,
  usually 200, not 101.
* A panic without a Recover middleware is recorded with status 500, but `net/http` closes the connection without
  sending a response.

## Dependency update bots

Renovate proposes a new MAJOR version (for example `github.com/labstack/echo-otel/v4` to `/v5`) as an update. A new
MAJOR version of this library needs the same MAJOR version of Echo, so update Echo first. To stay on the current Echo
version, disable major updates for this library:

```json
{
  "packageRules": [
    {
      "matchManagers": ["gomod"],
      "matchPackageNames": ["github.com/labstack/echo-otel/v4", "github.com/labstack/echo-otel/v5"],
      "matchUpdateTypes": ["major"],
      "enabled": false
    }
  ]
}
```
