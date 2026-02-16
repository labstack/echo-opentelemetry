package echootel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"
	"go.opentelemetry.io/otel/semconv/v1.39.0/httpconv"
)

// Metrics holds a standard set of OpenTelemetry global request/response metrics
type Metrics struct {
	// requestDurationHistogram (`http.server.request.duration`) is the duration of HTTP server requests.
	// Unit (UCUM): S (seconds)
	// Spec: https://opentelemetry.io/docs/specs/semconv/http/http-metrics/#metric-httpserverrequestduration
	requestDurationHistogram httpconv.ServerRequestDuration //  required

	// requestBodySizeHistogram (`http.server.request.body.size`) is size of HTTP server request bodies.
	// Unit (UCUM): By (bytes)
	// Spec: https://opentelemetry.io/docs/specs/semconv/http/http-metrics/#metric-httpserverrequestbodysize
	requestBodySizeHistogram httpconv.ServerRequestBodySize // optional

	// responseBodySizeHistogram (`http.server.response.body.size`) is size of HTTP server response bodies.
	// Unit (UCUM): By (bytes)
	// Spec: https://opentelemetry.io/docs/specs/semconv/http/http-metrics/#metric-httpserverresponsebodysize
	responseBodySizeHistogram httpconv.ServerResponseBodySize // optional
}

// NewMetrics creates a new Metrics instance for Standard Required metric instances with the given Meter.
func NewMetrics(meter metric.Meter) (*Metrics, error) {
	// required, https://opentelemetry.io/docs/specs/semconv/http/http-metrics/#metric-httpserverrequestduration
	reqDuration, err := httpconv.NewServerRequestDuration(
		meter,
		metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10),
	)
	if err != nil {
		return nil, err
	}

	// optional, https://opentelemetry.io/docs/specs/semconv/http/http-metrics/#metric-httpserverrequestbodysize
	reqBodySize, err := httpconv.NewServerRequestBodySize(meter)
	if err != nil {
		return nil, err
	}

	// optional, https://opentelemetry.io/docs/specs/semconv/http/http-metrics/#metric-httpserverresponsebodysize
	respBodySize, err := httpconv.NewServerResponseBodySize(meter)
	if err != nil {
		return nil, err
	}

	return &Metrics{
		requestDurationHistogram:  reqDuration,
		requestBodySizeHistogram:  reqBodySize,
		responseBodySizeHistogram: respBodySize,
	}, nil
}

// RecordValues represents the values to Record metrics.
type RecordValues struct {
	// RequestDuration is the duration of request processing. Will be used with `http.server.request.duration` metric.
	RequestDuration time.Duration

	// ExtractedValues are values extracted from HTTP request and response before and after processing the next middleware/handler.
	ExtractedValues Values

	// Attributes are attributes to be used for recording metrics.
	// If left empty, the Metrics.Record method will use default attributes by calling Values.MetricAttributes().
	Attributes []attribute.KeyValue
}

// Record records the given RecordValues to the Metrics instance.
func (m *Metrics) Record(ctx context.Context, v RecordValues) {
	attrs := v.Attributes
	if len(attrs) == 0 {
		attrs = v.ExtractedValues.MetricAttributes()
	}
	o := metric.WithAttributeSet(attribute.NewSet(attrs...))

	m.requestDurationHistogram.Inst().Record(ctx, v.RequestDuration.Seconds(), o)
	m.requestBodySizeHistogram.Inst().Record(ctx, v.ExtractedValues.HTTPRequestBodySize, o)
	m.responseBodySizeHistogram.Inst().Record(ctx, v.ExtractedValues.HTTPResponseBodySize, o)
}

// Values represent extracted values from HTTP request and response to be used for Span and Metrics attributes.
//
// Span: Semantic Conventions for HTTP client and server spans. https://opentelemetry.io/docs/specs/semconv/http/http-spans/
// Metrics: Semantic Conventions for HTTP client and server metrics. https://opentelemetry.io/docs/specs/semconv/http/http-metrics/
type Values struct {
	// HTTPMethod (`http.request.method`) - HTTP request method.
	//
	// If the HTTP request method is not known to instrumentation, it MUST set the `http.request.method` attribute to `_OTHER`
	//
	// If the HTTP instrumentation could end up converting valid HTTP request methods to `_OTHER`, then it MUST provide a
	// way to override the list of known HTTP methods. If this override is done via environment variable, then the
	// environment variable MUST be named `OTEL_INSTRUMENTATION_HTTP_KNOWN_METHODS` and support a comma-separated list of
	// case-sensitive known HTTP methods (this list MUST be a full override of the default known method, it is not a
	// list of known methods in addition to the defaults).
	//
	// HTTP method names are case-sensitive and `http.request.method` attribute value MUST match a known HTTP method name
	// exactly. Instrumentations for specific web frameworks that consider HTTP methods to be case insensitive, SHOULD
	// populate a canonical equivalent. Tracing instrumentations that do so, MUST also set `http.request.method_original`
	// to the original value.
	//
	// Example: `GET`, `POST`, `_OTHER`
	// Spec: https://opentelemetry.io/docs/specs/semconv/registry/attributes/http/
	//
	// Requirement Level:
	//  * span - Required
	//  * metric - Required
	HTTPMethod string // metric, span

	// HTTPMethodOriginal (`http.request.method_original`) is original HTTP method sent by the client in the request line.
	// Example: `GeT`, `ACL`, `foo`
	//
	// Requirement Level:
	//  * span - conditionally required if raw value differs from `http.request.method` (different case) or `http.request.method` is `_OTHER`
	//  * metric - opt in, same rules as span
	HTTPMethodOriginal string // metric, span

	// ServerAddress (`server.address`) is the Name of the local HTTP server that received the request.
	// This value can be provided by middleware configuration or extracted from `Request.Host`.
	// Example values: `example.com` `10.1.2.80`, `/tmp/my.sock`
	// See also: https://opentelemetry.io/docs/specs/semconv/http/http-spans/#setting-serveraddress-and-serverport-attributes
	// Spec: https://opentelemetry.io/docs/specs/semconv/registry/attributes/server/
	//
	// Requirement Level:
	//  * span - Recommended
	//  * metric - Opt-In
	ServerAddress string // metric, span

	// ServerPort (`server.port`) is the Port of the local HTTP server that received the request.
	// This value can be provided by middleware configuration or extracted from `Request.Host`.
	// Example values: `80` `8080`, `443`
	// See also: https://opentelemetry.io/docs/specs/semconv/http/http-spans/#setting-serveraddress-and-serverport-attributes
	// Spec: https://opentelemetry.io/docs/specs/semconv/registry/attributes/server/
	//
	// Requirement Level:
	//  * span - conditionally Required if available and `server.address` is set
	//  * metric - Opt-In
	ServerPort int // metric, span

	// NetworkPeerAdress (`network.peer.address`) is peer address of the network connection - IP address or Unix domain socket name.
	// Spec: https://opentelemetry.io/docs/specs/semconv/registry/attributes/network/
	//
	// Go: This value is derived from `Request.RemoteAddr` field value.
	//
	// Requirement Level:
	//  * span - Recommended
	//  * metric - not used
	NetworkPeerAddress string // span (optional)

	// NetworkPeerPort (`network.peer.port`) is peer port number of the network connection.
	// Spec: https://opentelemetry.io/docs/specs/semconv/registry/attributes/network/
	//
	// Go: This value is derived from `Request.RemoteAddr` field value.
	//
	// Requirement Level:
	//  * span - Recommended if `network.peer.address` is set.
	//  * metric - not used
	NetworkPeerPort int // span (optional)

	// ClientAddress (`client.address`) is client address - domain name if available without reverse DNS lookup;
	// otherwise, IP address or Unix domain socket name.
	// Spec: https://opentelemetry.io/docs/specs/semconv/registry/attributes/client/
	//
	// Go: This value is derived by default from `Request.RemoteAddr` field value and is same as `network.peer.address`.
	//     Middleware creators or users can override with `Request.Header.Get("X-Forwarded-For")` value but be warned
	//     that it is very easy to spoof HTTP headers.
	//
	// Requirement Level:
	//  * span - Recommended if `network.peer.address` is set.
	//  * metric - not used
	ClientAddress string // span (optional)

	// URLScheme (`url.scheme`) is the [URI scheme](https://www.rfc-editor.org/rfc/rfc3986#section-3.1) component
	// identifying the used protocol.
	// The scheme of the original client request, if possible, from one of these headers:
	// - [Forwarded#proto](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Forwarded#proto)
	// - [X-Forwarded-Proto](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-Proto)
	// - Otherwise, the scheme of the immediate peer request.
	// Example values: `http`, `https`
	//
	// Requirement Level:
	//  * span - Required
	//  * metric - Required
	URLScheme string // metric, span

	// URLPath (`url.path`) is the [URI](https://www.rfc-editor.org/rfc/rfc3986#section-3.3) path component.
	// Spec: https://opentelemetry.io/docs/specs/semconv/registry/attributes/url/
	//
	// Go: This value is taken from `Request.URL.Path` method value.
	//
	// Requirement Level:
	//  * span - Required
	//  * metric - not used
	URLPath string // span

	// UserAgentOriginal (`user_agent.original`) is the value of the [HTTP User-Agent](https://www.rfc-editor.org/rfc/rfc9110.html#field.user-agent)
	// header sent by the client.
	// Spec: https://opentelemetry.io/docs/specs/semconv/registry/attributes/user-agent/
	//
	// Go: This value is taken from `Request.UserAgent()` method value.
	//
	// Requirement Level:
	//  * span - Recommended
	//  * metric - not used
	UserAgentOriginal string // span

	// NetworkProtocolName (`network.protocol.name`) is OSI application layer or non-OSI equivalent.
	// Value is required if not value is not `http` and `network.protocol.version` value is set.
	// The value SHOULD be normalized to lowercase.
	// Example: `http`, `quic`, `spdy`
	// Spec: https://opentelemetry.io/docs/specs/semconv/registry/attributes/network/
	//
	// Go: This value is derived from `Request.Proto` field value.
	//
	// Requirement Level:
	//  * span - conditionally Required if available and `network.protocol.version` is set
	//  * metric - conditionally Required if available and `network.protocol.version` is set
	NetworkProtocolName string // metric, span

	// NetworkProtocolVersion (`network.protocol.version`) is the actual version of the protocol used for network communication.
	// Example: `1.0`, `1.1`, `2`, `3`
	// Spec: https://opentelemetry.io/docs/specs/semconv/registry/attributes/network/
	//
	// Go: This value is derived from `Request.Proto` field value.
	//
	// Requirement Level:
	//  * span - Recommended
	//  * metric - Recommended
	NetworkProtocolVersion string // metric, span

	// HTTPRoute (`http.route`) is the matched route template for the request. This MUST be low-cardinality and include
	// all static path segments, with dynamic path segments represented with placeholders.
	// Spec: https://opentelemetry.io/docs/specs/semconv/registry/attributes/http/
	//
	// Go: This value is taken from `Request.Pattern` field.
	//
	// Requirement Level:
	//  * span - Recommended
	//  * metric - Conditionally Required If and only if it's available
	HTTPRoute string // metric, span

	// HTTPRequestBodySize (`http.request.body.size`) is the size of the request payload body in bytes. This is the number
	// of bytes transferred excluding headers and is often, but not always, present as the [Content-Length](https://www.rfc-editor.org/rfc/rfc9110.html#field.content-length)
	// header. For requests using transport encoding, this should be the compressed size.
	// Spec: https://opentelemetry.io/docs/specs/semconv/http/http-metrics/#metric-httpclientrequestbodysize
	//
	// Go: This value is taken from `Request.ContentLength` can be negative (-1) if the size is unknown.
	//
	// Requirement Level:
	//  * span - opt-in attribute
	//  * metric - optional, is actual Histogram metric (`http.client.request.body.size`) and NOT attribute to metric.
	HTTPRequestBodySize int64 // metric

	// HTTPResponseStatusCode (`http.response.status_code`) is HTTP response status code.
	// See also RFC: https://datatracker.ietf.org/doc/html/rfc7231#section-6
	// Spec: https://opentelemetry.io/docs/specs/semconv/registry/attributes/http/
	//
	// Requirement Level:
	//  * span - opt-in attribute
	//  * metric - conditionally Required if and only if one was received/sent
	HTTPResponseStatusCode int // metric

	// HTTPResponseBodySize (`http.response.body.size`) is the size of the response payload body in bytes. This is
	// the number of bytes transferred excluding headers and is often, but not always, present as the
	// [Content-Length](https://www.rfc-editor.org/rfc/rfc9110.html#field.content-length) header. For requests using
	// transport encoding, this should be the compressed size.
	// Spec: https://opentelemetry.io/docs/specs/semconv/http/http-metrics/#metric-httpserverresponsebodysize
	//
	// Requirement Level:
	//  * span - opt-in attribute
	//  * metric - optional, is actual Histogram metric (`http.server.response.body.size`) and NOT attribute to metric.
	HTTPResponseBodySize int64 // metric
}

// ExtractRequest extracts values from the given HTTP request and populates the Values struct.
func (v *Values) ExtractRequest(r *http.Request) error {
	var errs []error

	if v.ServerAddress == "" || v.ServerPort == 0 {
		host, port, err := SplitAddress(r.Host)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to split Request.Host: %w", err))
		}
		if v.ServerAddress == "" {
			v.ServerAddress = host
		}
		if v.ServerPort == 0 {
			v.ServerPort = port
		}
	}
	if v.HTTPRoute == "" {
		v.HTTPRoute = r.Pattern
	}

	v.HTTPMethod, v.HTTPMethodOriginal = httpMethod(r.Method)
	v.HTTPRequestBodySize = r.ContentLength // Note: this value can be -1 indicating unknown body size
	v.URLPath = r.URL.Path
	v.UserAgentOriginal = r.UserAgent()

	// Note: We are not getting URL scheme from headers as spec recommends. HTTP headers are easy to spoof, getting value
	// from headers needs to be an explicit decision from a developer.
	v.URLScheme = "http"
	if r.TLS != nil {
		v.URLScheme = "https"
	}

	v.NetworkProtocolName, v.NetworkProtocolVersion = splitProto(r.Proto)

	// The HTTP server sets Request.RemoteAddr to an "IP:port" address.
	peerAddr, peerPort, err := SplitAddress(r.RemoteAddr)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to split Request.RemoteAddr: %w", err))
	}
	v.NetworkPeerAddress = peerAddr
	v.NetworkPeerPort = peerPort
	// Note: this could be taken from `Request.Header.Get("X-Forwarded-For")` header but these are easy to spoof so we
	// default to `Request.RemoteAddr`.
	// Middleware creators or users should decide how to fill this field before/after this method call.
	if v.ClientAddress == "" {
		v.ClientAddress = peerAddr
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// SpanStartAttributes returns a list of attributes to be used when starting a span.
func (v *Values) SpanStartAttributes() []attribute.KeyValue {
	result := v.commonAttributes(5)
	if v.NetworkPeerAddress != "" {
		result = append(result, semconv.NetworkPeerAddress(v.NetworkPeerAddress))
	}
	if v.NetworkPeerPort != 0 {
		result = append(result, semconv.NetworkPeerPort(v.NetworkPeerPort))
	}
	if v.ClientAddress != "" {
		result = append(result, semconv.ClientAddress(v.ClientAddress))
	}
	if v.UserAgentOriginal != "" {
		result = append(result, semconv.UserAgentOriginal(v.UserAgentOriginal))
	}
	if v.URLPath != "" {
		result = append(result, semconv.URLPath(v.URLPath))
	}
	return result
}

// SpanEndAttributes returns a list of attributes to be used when ending a span, after the next handler has been executed.
func (v *Values) SpanEndAttributes() []attribute.KeyValue {
	return []attribute.KeyValue{
		semconv.HTTPResponseStatusCode(v.HTTPResponseStatusCode),
		semconv.HTTPRequestBodySize(int(v.HTTPRequestBodySize)),
		semconv.HTTPResponseBodySize(int(v.HTTPResponseBodySize)),
	}
}

// MetricAttributes creates attributes for metric instruments from extracted values.
// See also: https://opentelemetry.io/docs/specs/semconv/http/http-metrics/
func (v *Values) MetricAttributes() []attribute.KeyValue {
	result := v.commonAttributes(1)
	if v.HTTPResponseStatusCode != 0 {
		result = append(result, semconv.HTTPResponseStatusCode(v.HTTPResponseStatusCode))
	}
	return result
}

func (v *Values) commonAttributes(additionalSize int) []attribute.KeyValue {
	result := make([]attribute.KeyValue, 0, 8+additionalSize)

	method := otherMethodAttr
	if m, ok := knownMethods[v.HTTPMethod]; ok {
		method = m
	}
	result = append(result,
		method,
		semconv.ServerAddress(v.ServerAddress),
		semconv.URLScheme(v.URLScheme),
	)
	if v.HTTPRoute != "" {
		result = append(result, semconv.HTTPRoute(v.HTTPRoute))
	}
	if v.ServerPort != 0 {
		result = append(result, semconv.ServerPort(v.ServerPort))
	}
	if v.HTTPMethodOriginal != "" {
		result = append(result, semconv.HTTPRequestMethodOriginal(v.HTTPMethodOriginal))
	}
	if v.NetworkProtocolName != "" {
		result = append(result, semconv.NetworkProtocolName(v.NetworkProtocolName))
	}
	if v.NetworkProtocolVersion != "" {
		result = append(result, semconv.NetworkProtocolVersion(v.NetworkProtocolVersion))
	}
	return result
}

// http.request.method: HTTP request method value SHOULD be “known” to the instrumentation.
// By default, this convention defines “known” methods as the ones listed in [RFC9110](https://www.rfc-editor.org/rfc/rfc9110.html#name-methods),
// the PATCH method defined in [RFC5789](https://www.rfc-editor.org/rfc/rfc5789.html) and the
// QUERY method defined in [httpbis-safe-method-w-body](https://datatracker.ietf.org/doc/draft-ietf-httpbis-safe-method-w-body/?include_text=1).
//
// Source: OpenTelemetry semantic conventions 1.39.0
var knownMethods = map[string]attribute.KeyValue{
	http.MethodConnect: semconv.HTTPRequestMethodConnect,
	http.MethodDelete:  semconv.HTTPRequestMethodDelete,
	http.MethodGet:     semconv.HTTPRequestMethodGet,
	http.MethodHead:    semconv.HTTPRequestMethodHead,
	http.MethodOptions: semconv.HTTPRequestMethodOptions,
	http.MethodPatch:   semconv.HTTPRequestMethodPatch,
	http.MethodPost:    semconv.HTTPRequestMethodPost,
	http.MethodPut:     semconv.HTTPRequestMethodPut,
	http.MethodTrace:   semconv.HTTPRequestMethodTrace,
	"QUERY":            semconv.HTTPRequestMethodQuery,
}

// otherMethodAttr - if the HTTP request method is not known to instrumentation, it MUST set the `http.request.method` attribute to `_OTHER`
var otherMethodAttr = semconv.HTTPRequestMethodOther

const (
	otherMethod = "_OTHER"
)

// httpMethod derives values for `http.request.method` and `http.request.method_original` attributes from a given value.
func httpMethod(method string) (string, string) {
	if _, ok := knownMethods[method]; ok {
		return method, ""
	}
	originalMethod := method
	method = otherMethod
	upperMethod := strings.ToUpper(originalMethod)
	if _, ok := knownMethods[upperMethod]; ok {
		method = upperMethod
	}
	return method, originalMethod
}

// returns network protocol (`network.protocol.name`) name and version (`network.protocol.version`).
func splitProto(proto string) (name string, version string) {
	name, version, _ = strings.Cut(proto, "/")
	switch name {
	case "HTTP":
		name = "http"
	case "QUIC":
		name = "quic"
	case "SPDY":
		name = "spdy"
	default:
		name = strings.ToLower(name)
	}
	return name, version
}

// splitHostPort splits server host:port string into host (`server.address`) and port (`server.port`).
// Address can be in the form of "host", "host%zone", "[host]", "[host%zone], "host:port", "host%zone:port",
// "[host]:port", "[host%zone]:port".
func splitHostPort(address string) (host string, port int, err error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		err = fmt.Errorf("failed to parse port: %w", err)
	}
	return host, port, err
}

// SplitAddress splits server address or host into host (`server.address`) and port (`server.port`).
// Empty address is accepted and returns empty host and port.
// Port is part is not mandatory in address and can be omitted.
func SplitAddress(address string) (host string, port int, err error) {
	if address == "" {
		return "", 0, nil
	}
	lastColon := strings.LastIndexByte(address, ':')
	if lastColon < 0 {
		return address, 0, nil
	}
	lastEndBracket := strings.LastIndexByte(address, ']')
	if lastEndBracket > 0 && lastColon < lastEndBracket { // `[fe80::1]` but not `[fe80::1]:80`
		address += ":0" // for IPv6, add port so `net.SplitHostPort` could validate host port
	}

	// address is probably in the form of "host:port", "host%zone:port", "[host]:port" or "[host%zone]:port"
	return splitHostPort(address)
}

// SpanNameFormatter returns the default format for the span name based on the HTTP method and path.
//
// HTTP span names SHOULD be `{method} {target}` if there is a (low-cardinality) `target` available. If there is no
// (low-cardinality) `{target}` available, HTTP span names SHOULD be `{method}`.
//
// The `{method}` MUST be `{http.request.method}` if the method represents the original method known to the instrumentation.
// In other cases (when `{http.request.method}` is set to `_OTHER`), `{method}` MUST be `HTTP`
//
// Spec: https://opentelemetry.io/docs/specs/semconv/http/http-spans/#name
func SpanNameFormatter(v Values) string {
	method := v.HTTPMethod
	if method == otherMethod || method == "" {
		method = "HTTP"
	}
	if v.HTTPRoute != "" {
		return method + " " + v.HTTPRoute
	}
	return method
}
