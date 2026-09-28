[![Sourcegraph](https://sourcegraph.com/github.com/labstack/echo-otel/-/badge.svg?style=flat-square)](https://sourcegraph.com/github.com/labstack/echo-otel?badge)
[![GoDoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](https://pkg.go.dev/github.com/labstack/echo-otel/v5)
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

This is the `main` branch, for Echo v5. `github.com/labstack/echo-opentelemetry` (`v0.0.x`, Echo v5) is the
previous name of this project and is deprecated.

Always include the MAJOR version suffix (`/v5` or `/v4`) in `go get` and imports. Without it,
`go get github.com/labstack/echo-otel` fails.

## Usage

Add OpenTelemetry middleware dependency with go modules

```bash
go get github.com/labstack/echo-otel/v5
```

Use as an import statement

```go
import echootel "github.com/labstack/echo-otel/v5"
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
tracer, err := echo.ContextGet[trace.Tracer](c, echootel.TracerKey)
```

## Full example

See [example](example/main.go)

## Custom error handler

The middleware resolves the response status code for returned errors with `echo.ResolveResponseStatus`: the status of
an already sent response, the `StatusCode()` of the returned error (for example `echo.HTTPError`), or 500. If you
use a custom `HTTPErrorHandler` that maps errors to other status codes, let the middleware run the error handler, so it
reports the status code that was actually sent:

```go
e.Use(echootel.NewMiddlewareWithConfig(echootel.Config{
  ServerName:  "app.example.com",
  OnNextError: func(c *echo.Context, err error) { c.Echo().HTTPErrorHandler(c, err) },
}))
```

The error is still returned, so the error handler is called again; make it return early when the response is already
committed (`resp, err := echo.UnwrapResponse(c.Response()); err == nil && resp.Committed`). Echo's
`ProblemDetailsHTTPErrorHandler` (Echo v5.4.0+) does this; use the snippet above with it too, as it resolves the status
of `ProblemErrorer` errors and of `*echo.ProblemError` wrapped in another error differently.

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
  to `github.com/labstack/echo-otel/v5`. Update dashboards and alerts that filter on it.
* The `echo.error` span attribute is not set; use `error.type` and the span status instead.

## Migrating from echo-opentelemetry

`github.com/labstack/echo-opentelemetry` (`v0.0.x`) is the previous name of this project. It is deprecated and receives
no more changes. Change the import path; the API is the same, except that a `ServerName` without a host is rejected
(see below):

```go
import echootel "github.com/labstack/echo-otel/v5"
```

Telemetry changes compared to `echo-opentelemetry` `v0.0.3`:

* The instrumentation scope name changes from `github.com/labstack/echo-opentelemetry` to
  `github.com/labstack/echo-otel/v5`. Update dashboards and alerts that filter on it.
* `error.type` is no longer set for 4xx responses (it used to be `*echo.HTTPError` for a returned HTTPError, and
  `*echo.httpError` for Echo's own errors such as `echo.ErrNotFound`).
* A returned 5xx HTTPError reports the status code (`500`) instead of `*echo.HTTPError`.
* A 5xx response written without an error (for example `c.String(500, ...)`) now reports `error.type`.
* A returned error with a `StatusCode() int` method reports the status code for a 5xx response instead of its Go type.
* `error.type` is also added to metrics, see [Errors](#errors).
* `http.route` and the span name are set when the middleware is added with `Echo.Pre`.
* An error wrapped with `fmt.Errorf("...: %w", err)` reports the wrapped error's type (for example `*net.OpError`)
  instead of `*fmt.wrapError`, and an `ErrorType() string` method in the error chain is used when present.
* `error.type` is now one of the span end attributes: a `Config.SpanEndAttributes` callback must append to the `attr`
  argument, otherwise `error.type` is dropped (v0.0.3 set it separately).
* A status code of 600-999 now reports `error.type` (the code).
* Metrics no longer have `server.address`, `server.port` and `http.request.method_original`; their values come from
  the request and would make metric cardinality unbounded. They stay on spans. See [Metrics](#metrics).
* With `ServerName` set, `server.port` comes from `ServerName` only, not from the `Host` header.
* An unknown request body size (for example a chunked request) is not recorded, instead of `-1`.
* `http.route` is always the Echo route, never the pattern of an outer `http.ServeMux`.
* A panic in a handler is recorded (`error.type` `panic`) and then re-panicked, so telemetry is recorded also when a
  Recover middleware is added before this middleware. With a Recover middleware added after this middleware, the
  returned `*middleware.PanicStackError` is reported as `panic` instead of its Go type. See [Errors](#errors).
* A `ServerName` without a host (for example `:8080`) is rejected: `NewMiddleware` panics and `Config.ToMiddleware`
  returns an error. v0.0.3 accepted it.
* `network.protocol.version` is `2` for HTTP/2 and `3` for HTTP/3, instead of `2.0` and `3.0`.
* Spans no longer have `http.request.body.size` and `http.response.body.size` (Opt-In for spans in the semantic
  conventions). The body size metrics stay. See [Spans](#spans) for how to add them back.

## Errors

A request that ends with an error sets `error.type` on the span and on the metrics, as the semantic conventions
require. The rules match the span status:

* a 4xx response is not an error for server spans: no `error.type`,
* a 5xx response without a returned error, or with a returned error that carries the status code (`echo.HTTPError`
  or any error with a `StatusCode() int` method, also when wrapped), reports the status code, for example `500`,
* any other returned error reports its Go type, for example `*net.OpError`. Errors created with
  `fmt.Errorf("...: %w", err)` are unwrapped first; errors joining several errors (`errors.Join`, `fmt.Errorf` with
  more than one `%w`) report their own type. An `ErrorType() string` method anywhere in the error chain takes
  precedence; keep its values low cardinality, as `error.type` is also a metric attribute.
* an invalid status code without a returned error reports `_OTHER` (below 100 or above 999) or the code itself
  (600-999),
* a panic reports `panic`, also when a 4xx response was already sent.

The middleware records a panic and then re-panics, so add a Recover middleware before this middleware
(`e.Use(middleware.Recover())` first). The recorded status is the status of the response that was already sent, the
status of a panic value that carries one (for example `echo.ErrUnauthorized`), or 500. A Recover middleware added after
this middleware (with the default configuration) returns the panic as a `*middleware.PanicStackError`, which is also
reported as `panic`.

`error.type` is part of the span end attributes. A `Config.SpanEndAttributes` callback must append to the `attr`
argument and return it, otherwise `error.type` and the other end attributes are dropped.

## Spans

Spans follow the [HTTP server span](https://opentelemetry.io/docs/specs/semconv/http/http-spans/#http-server) semantic
conventions, with these exceptions:

* `url.query` is not set. The query string can contain sensitive data, and the semantic conventions require redacting
  it. `http.request.body.size` and `http.response.body.size` are Opt-In and not set either.
* `http.response.status_code` is not set when no response was sent, for example after an `http.ErrAbortHandler` panic.

`client.address` comes from `c.RealIP()`: the connection's remote address, or the result of `Echo.IPExtractor` when
it is set.

Add attributes with `SpanStartAttributes` and `SpanEndAttributes`. Both callbacks must append to the `attr` argument and
return it:

```go
SpanStartAttributes: func(c *echo.Context, v *echootel.Values, attr []attribute.KeyValue) []attribute.KeyValue {
  if q := c.Request().URL.RawQuery; q != "" {
    attr = append(attr, semconv.URLQuery(redactQuery(q))) // redactQuery is your own function
  }
  return attr
},
SpanEndAttributes: func(c *echo.Context, v *echootel.Values, attr []attribute.KeyValue) []attribute.KeyValue {
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
MetricAttributes: func(c *echo.Context, v *echootel.Values) []attribute.KeyValue {
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
