package echootel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

func TestValues_ExtractRequest(t *testing.T) {
	defaultRequest, rErr := http.NewRequest("GET", "http://example.com/path?query=test", http.NoBody)
	if rErr != nil {
		t.Fatal(rErr)
	}

	var testCases = []struct {
		name        string
		given       *Values
		whenRequest *http.Request
		expect      Values
		expectErr   string
	}{
		{
			name:        "GET request, without body",
			whenRequest: defaultRequest,
			expect: Values{
				HTTPMethod:             "GET",
				HTTPMethodOriginal:     "",
				ServerAddress:          "example.com",
				ServerPort:             0,
				NetworkPeerAddress:     "",
				NetworkPeerPort:        0,
				ClientAddress:          "",
				URLScheme:              "http",
				URLPath:                "/path",
				UserAgentOriginal:      "",
				NetworkProtocolName:    "http",
				NetworkProtocolVersion: "1.1",
				HTTPRoute:              "",
				HTTPRequestBodySize:    0,
				HTTPResponseStatusCode: 0,
				HTTPResponseBodySize:   0,
			},
		},
		{
			name: "GET request, user agent, pattern",
			whenRequest: func() *http.Request {
				r := defaultRequest.Clone(context.Background())
				r.Method = "gEt"
				r.Host = "example.com:8433"
				r.ContentLength = -1

				r.RemoteAddr = "127.0.0.1:8080"
				r.Pattern = "/path"
				r.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
				return r
			}(),
			expect: Values{
				HTTPMethod:             "GET",
				HTTPMethodOriginal:     "gEt",
				ServerAddress:          "example.com",
				ServerPort:             8433,
				NetworkPeerAddress:     "127.0.0.1",
				NetworkPeerPort:        8080,
				ClientAddress:          "127.0.0.1",
				URLScheme:              "http",
				URLPath:                "/path",
				UserAgentOriginal:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
				NetworkProtocolName:    "http",
				NetworkProtocolVersion: "1.1",
				HTTPRoute:              "/path",
				HTTPRequestBodySize:    -1,
				// these are filled later
				HTTPResponseStatusCode: 0,
				HTTPResponseBodySize:   0,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v := Values{}
			if tc.given != nil {
				v = *tc.given
			}
			err := v.ExtractRequest(tc.whenRequest)

			assert.Equal(t, tc.expect, v)
			if tc.expectErr != "" {
				assert.EqualError(t, err, tc.expectErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValues_SpanStartAttributes(t *testing.T) {
	var testCases = []struct {
		name             string
		given            Values
		expectAttributes []attribute.KeyValue
	}{
		{
			name: "common + NetworkPeerAddress",
			given: Values{
				ServerAddress:      "test.com",
				URLScheme:          "http",
				NetworkPeerAddress: "127.0.0.1",
			},
			expectAttributes: []attribute.KeyValue{
				attribute.String("http.request.method", "_OTHER"),
				attribute.String("server.address", "test.com"),
				attribute.String("url.scheme", "http"),
				attribute.String("network.peer.address", "127.0.0.1"),
			},
		},
		{
			name: "common + NetworkPeerPort",
			given: Values{
				ServerAddress:   "test.com",
				URLScheme:       "http",
				NetworkPeerPort: 8080,
			},
			expectAttributes: []attribute.KeyValue{
				attribute.String("http.request.method", "_OTHER"),
				attribute.String("server.address", "test.com"),
				attribute.String("url.scheme", "http"),
				attribute.Int("network.peer.port", 8080),
			},
		},
		{
			name: "common + ClientAddress",
			given: Values{
				ServerAddress: "test.com",
				URLScheme:     "http",
				ClientAddress: "127.0.0.1",
			},
			expectAttributes: []attribute.KeyValue{
				attribute.String("http.request.method", "_OTHER"),
				attribute.String("server.address", "test.com"),
				attribute.String("url.scheme", "http"),
				attribute.String("client.address", "127.0.0.1"),
			},
		},
		{
			name: "common + UserAgentOriginal",
			given: Values{
				ServerAddress:     "test.com",
				URLScheme:         "http",
				UserAgentOriginal: "Firefox/91.0.2",
			},
			expectAttributes: []attribute.KeyValue{
				attribute.String("http.request.method", "_OTHER"),
				attribute.String("server.address", "test.com"),
				attribute.String("url.scheme", "http"),
				attribute.String("user_agent.original", "Firefox/91.0.2"),
			},
		},
		{
			name: "common + URLPath",
			given: Values{
				ServerAddress: "test.com",
				URLScheme:     "http",
				URLPath:       "/test/path",
			},
			expectAttributes: []attribute.KeyValue{
				attribute.String("http.request.method", "_OTHER"),
				attribute.String("server.address", "test.com"),
				attribute.String("url.scheme", "http"),
				attribute.String("url.path", "/test/path"),
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attr := tc.given.SpanStartAttributes()

			assert.Len(t, attr, len(tc.expectAttributes))
			assert.ElementsMatch(t, tc.expectAttributes, attr)
		})
	}
}

func TestValues_SpanEndAttributes(t *testing.T) {
	var testCases = []struct {
		name             string
		given            Values
		expectAttributes []attribute.KeyValue
	}{
		{
			name: "GET request, without body",
			given: Values{
				HTTPRequestBodySize:    999,
				HTTPResponseBodySize:   1000,
				HTTPResponseStatusCode: 200,
			},
			expectAttributes: []attribute.KeyValue{
				attribute.Int("http.response.status_code", 200),
			},
		},
		{
			name: "no status sent",
			given: Values{
				HTTPResponseStatusCode: 0,
				ErrorType:              "panic",
			},
			expectAttributes: []attribute.KeyValue{
				attribute.String("error.type", "panic"),
			},
		},
		{
			name: "request ended with an error",
			given: Values{
				HTTPRequestBodySize:    0,
				HTTPResponseBodySize:   21,
				HTTPResponseStatusCode: 500,
				ErrorType:              "500",
			},
			expectAttributes: []attribute.KeyValue{
				attribute.Int("http.response.status_code", 500),
				attribute.String("error.type", "500"),
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attr := tc.given.SpanEndAttributes()

			assert.Len(t, attr, len(tc.expectAttributes))
			assert.ElementsMatch(t, tc.expectAttributes, attr)
		})
	}
}

func TestValues_MetricAttributes(t *testing.T) {
	var testCases = []struct {
		name             string
		given            Values
		expectAttributes []attribute.KeyValue
	}{
		{
			name: "GET request, without body",
			given: Values{
				HTTPMethod:             "GET",
				HTTPMethodOriginal:     "gEt",
				ServerAddress:          "example.com",
				URLScheme:              "http",
				NetworkProtocolName:    "http",
				NetworkProtocolVersion: "1.1",
				HTTPResponseStatusCode: 200,
			},
			expectAttributes: []attribute.KeyValue{
				attribute.String("http.request.method", "GET"),
				attribute.String("url.scheme", "http"),
				attribute.String("network.protocol.name", "http"),
				attribute.String("network.protocol.version", "1.1"),
				attribute.Int64("http.response.status_code", 200),
			},
		},
		{
			name: "server address",
			given: Values{
				HTTPMethod:             "GET",
				ServerAddress:          "example.com",
				ServerPort:             9999,
				URLScheme:              "http",
				NetworkProtocolName:    "http",
				NetworkProtocolVersion: "1.1",
				HTTPRoute:              "/path/${id}",
				HTTPResponseStatusCode: 200,
			},
			expectAttributes: []attribute.KeyValue{
				attribute.String("http.request.method", "GET"),
				attribute.String("url.scheme", "http"),
				attribute.String("network.protocol.name", "http"),
				attribute.String("network.protocol.version", "1.1"),
				attribute.Int64("http.response.status_code", 200),
				attribute.String("http.route", "/path/${id}"),
			},
		},
		{
			name: "request ended with an error",
			given: Values{
				HTTPMethod:             "GET",
				ServerAddress:          "example.com",
				URLScheme:              "http",
				HTTPResponseStatusCode: 503,
				ErrorType:              "503",
			},
			expectAttributes: []attribute.KeyValue{
				attribute.String("http.request.method", "GET"),
				attribute.String("url.scheme", "http"),
				attribute.Int64("http.response.status_code", 503),
				attribute.String("error.type", "503"),
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attr := tc.given.MetricAttributes()

			assert.Len(t, attr, len(tc.expectAttributes))
			assert.ElementsMatch(t, tc.expectAttributes, attr)
		})
	}
}

func TestSplitAddress(t *testing.T) {
	var testCases = []struct {
		name          string
		whenHostPort  string
		expectHost    string
		expectPort    int
		expectedError string
	}{
		{
			name:          "empty address is accepted and returns empty host and port",
			whenHostPort:  "",
			expectHost:    "",
			expectPort:    0,
			expectedError: "",
		},
		{
			name:          "address without host, with port",
			whenHostPort:  ":8080",
			expectHost:    "",
			expectPort:    8080,
			expectedError: "",
		},
		{
			name:          "address with host, without port",
			whenHostPort:  "127.0.0.1",
			expectHost:    "127.0.0.1",
			expectPort:    0,
			expectedError: "",
		},
		{
			name:          "address with host, with port",
			whenHostPort:  "127.0.0.1:8080",
			expectHost:    "127.0.0.1",
			expectPort:    8080,
			expectedError: "",
		},
		{
			name:          "address (domain) with host, without port",
			whenHostPort:  "www.example.com",
			expectHost:    "www.example.com",
			expectPort:    0,
			expectedError: "",
		},
		{
			name:          "address (domain) with host, with port",
			whenHostPort:  "www.example.com:8080",
			expectHost:    "www.example.com",
			expectPort:    8080,
			expectedError: "",
		},
		{
			name:          "address (with zone) with host, without port",
			whenHostPort:  "127.0.0.1%25en0",
			expectHost:    "127.0.0.1%25en0",
			expectPort:    0,
			expectedError: "",
		},
		{
			name:          "address (with zone) with host, with port",
			whenHostPort:  "127.0.0.1%25en0:8080",
			expectHost:    "127.0.0.1%25en0",
			expectPort:    8080,
			expectedError: "",
		},
		{
			name:          "address brackets",
			whenHostPort:  "[]", // Ensure this doesn't panic.
			expectHost:    "[]",
			expectPort:    0,
			expectedError: "",
		},
		{
			name:          "address (invalid ipv6)",
			whenHostPort:  "[fe80::1",
			expectHost:    "",
			expectPort:    0,
			expectedError: `address [fe80::1: missing ']' in address`,
		},
		{
			name:          "address (ipv6) with host, without port",
			whenHostPort:  "[fe80::1]",
			expectHost:    "fe80::1",
			expectPort:    0,
			expectedError: ``,
		},
		{
			name:          "address (ipv6 + zone) with host, without port",
			whenHostPort:  "[fe80::1%25en0]",
			expectHost:    "fe80::1%25en0",
			expectPort:    0,
			expectedError: ``,
		},
		{
			name:          "address (ipv6 + zone) with host, with port",
			whenHostPort:  "[fe80::1]:8080",
			expectHost:    "fe80::1",
			expectPort:    8080,
			expectedError: ``,
		},
		{
			name:          "address (invalid ipv6), too many colons",
			whenHostPort:  "[fe80::1]::",
			expectHost:    "",
			expectPort:    0,
			expectedError: `address [fe80::1]::: too many colons in address`,
		},
		{
			name:          "address, empty port",
			whenHostPort:  "127.0.0.1:",
			expectHost:    "127.0.0.1",
			expectPort:    0,
			expectedError: `failed to parse port: strconv.Atoi: parsing "": invalid syntax`,
		},
		{
			name:          "address, invalid port",
			whenHostPort:  "127.0.0.1:port",
			expectHost:    "127.0.0.1",
			expectPort:    0,
			expectedError: `failed to parse port: strconv.Atoi: parsing "port": invalid syntax`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			host, port, err := SplitAddress(tc.whenHostPort)

			assert.Equal(t, tc.expectHost, host)
			assert.Equal(t, tc.expectPort, port)
			if tc.expectedError != "" {
				assert.EqualError(t, err, tc.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHTTPMethod(t *testing.T) {
	var testCases = []struct {
		name                 string
		whenMethod           string
		expectMethod         string
		expectOriginalMethod string
	}{
		{
			name:                 "GET, original is empty because method is known",
			whenMethod:           "GET",
			expectMethod:         "GET",
			expectOriginalMethod: "",
		},
		{
			name:                 "gEt, original is filled because method is in different case",
			whenMethod:           "gEt",
			expectMethod:         "GET",
			expectOriginalMethod: "gEt",
		},
		{
			name:                 "POST, original is empty because method is known",
			whenMethod:           "POST",
			expectMethod:         "POST",
			expectOriginalMethod: "",
		},
		{
			name:                 "post original is filled because method is in different case",
			whenMethod:           "post",
			expectMethod:         "POST",
			expectOriginalMethod: "post",
		},
		{
			name:                 "unknown method to _OTHER",
			whenMethod:           "unknown",
			expectMethod:         "_OTHER",
			expectOriginalMethod: "unknown",
		},
		{
			name:                 "empty to _OTHER",
			whenMethod:           "",
			expectMethod:         "_OTHER",
			expectOriginalMethod: "",
		},
		{
			name:                 "PUT, original is empty because method is known",
			whenMethod:           "PUT",
			expectMethod:         "PUT",
			expectOriginalMethod: "",
		},
		{
			name:                 "pUT, original is filled because method is in different case",
			whenMethod:           "pUT",
			expectMethod:         "PUT",
			expectOriginalMethod: "pUT",
		},
		{
			name:                 "DELETE, original is empty because method is known",
			whenMethod:           "DELETE",
			expectMethod:         "DELETE",
			expectOriginalMethod: "",
		},
		{
			name:                 "delete, original is filled because method is in different case",
			whenMethod:           "delete",
			expectMethod:         "DELETE",
			expectOriginalMethod: "delete",
		},
		{
			name:                 "HEAD, original is empty because method is known",
			whenMethod:           "HEAD",
			expectMethod:         "HEAD",
			expectOriginalMethod: "",
		},
		{
			name:                 "Head, original is filled because method is in different case",
			whenMethod:           "Head",
			expectMethod:         "HEAD",
			expectOriginalMethod: "Head",
		},
		{
			name:                 "OPTIONS, original is empty because method is known",
			whenMethod:           "OPTIONS",
			expectMethod:         "OPTIONS",
			expectOriginalMethod: "",
		},
		{
			name:                 "opTions, original is filled because method is in different case",
			whenMethod:           "opTions",
			expectMethod:         "OPTIONS",
			expectOriginalMethod: "opTions",
		},
		{
			name:                 "CONNECT, original is empty because method is known",
			whenMethod:           "CONNECT",
			expectMethod:         "CONNECT",
			expectOriginalMethod: "",
		},
		{
			name:                 "connect, original is filled because method is in different case",
			whenMethod:           "connect",
			expectMethod:         "CONNECT",
			expectOriginalMethod: "connect",
		},
		{
			name:                 "TRACE, original is empty because method is known",
			whenMethod:           "TRACE",
			expectMethod:         "TRACE",
			expectOriginalMethod: "",
		},
		{
			name:                 "trace, original is filled because method is in different case",
			whenMethod:           "trace",
			expectMethod:         "TRACE",
			expectOriginalMethod: "trace",
		},
		{
			name:                 "PATCH, original is empty because method is known",
			whenMethod:           "PATCH",
			expectMethod:         "PATCH",
			expectOriginalMethod: "",
		},
		{
			name:                 "patCH, original is filled because method is in different case",
			whenMethod:           "patCH",
			expectMethod:         "PATCH",
			expectOriginalMethod: "patCH",
		},
		{
			name:                 "QUERY, original is empty because method is known",
			whenMethod:           "QUERY",
			expectMethod:         "QUERY",
			expectOriginalMethod: "",
		},
		{
			name:                 "query, original is filled because method is in different case",
			whenMethod:           "query",
			expectMethod:         "QUERY",
			expectOriginalMethod: "query",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			method, originalMethod := httpMethod(tc.whenMethod)

			assert.Equal(t, tc.expectMethod, method)
			assert.Equal(t, tc.expectOriginalMethod, originalMethod)
		})
	}
}

func TestSpanNameFormatter(t *testing.T) {
	var testCases = []struct {
		name   string
		when   Values
		expect string
	}{
		{
			name:   "empty",
			when:   Values{},
			expect: "HTTP",
		},
		{
			name:   "known method, missing route",
			when:   Values{HTTPMethod: "GET"},
			expect: "GET",
		},
		{
			name:   "_OTHER method, missing route",
			when:   Values{HTTPMethod: "_OTHER"},
			expect: "HTTP",
		},
		{
			name:   "known method + route",
			when:   Values{HTTPMethod: "GET", HTTPRoute: "/path/${id}"},
			expect: "GET /path/${id}",
		},
		{
			name:   "_OTHER method + route",
			when:   Values{HTTPMethod: "_OTHER", HTTPRoute: "/path/${id}"},
			expect: "HTTP /path/${id}",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			spanName := SpanNameFormatter(tc.when)
			assert.Equal(t, tc.expect, spanName)
		})
	}
}

func TestSplitProto(t *testing.T) {
	var testCases = []struct {
		name          string
		whenProto     string
		expectName    string
		expectVersion string
	}{
		{
			name:          "empty",
			whenProto:     "",
			expectName:    "",
			expectVersion: "",
		},
		{
			name:          "http uppercase",
			whenProto:     "HTTP/1.1",
			expectName:    "http",
			expectVersion: "1.1",
		},
		{
			name:          "HTTP/2.0 is reported as 2",
			whenProto:     "HTTP/2.0",
			expectName:    "http",
			expectVersion: "2",
		},
		{
			name:          "HTTP/3.0 is reported as 3",
			whenProto:     "HTTP/3.0",
			expectName:    "http",
			expectVersion: "3",
		},
		{
			name:          "quic uppercase",
			whenProto:     "QUIC/2",
			expectName:    "quic",
			expectVersion: "2",
		},
		{
			name:          "spdy uppercase",
			whenProto:     "SPDY/3.1",
			expectName:    "spdy",
			expectVersion: "3.1",
		},
		{
			name:          "already lowercase",
			whenProto:     "http/2",
			expectName:    "http",
			expectVersion: "2",
		},
		{
			name:          "mixed case default branch",
			whenProto:     "HtTp/1.0",
			expectName:    "http",
			expectVersion: "1.0",
		},
		{
			name:          "unknown protocol",
			whenProto:     "FTP/1.0",
			expectName:    "ftp",
			expectVersion: "1.0",
		},
		{
			name:          "no version segment",
			whenProto:     "HTTP",
			expectName:    "http",
			expectVersion: "",
		},
		{
			name:          "no slash unknown protocol",
			whenProto:     "CustomProto",
			expectName:    "customproto",
			expectVersion: "",
		},
		{
			name:          "extra slash only splits first",
			whenProto:     "HTTP/1.1/extra",
			expectName:    "http",
			expectVersion: "1.1/extra",
		},
		{
			name:          "leading slash",
			whenProto:     "/1.0",
			expectName:    "",
			expectVersion: "1.0",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			name, version := splitProto(tc.whenProto)

			assert.Equal(t, tc.expectName, name)
			assert.Equal(t, tc.expectVersion, version)
		})
	}
}

func TestSpanStatus(t *testing.T) {
	var testCases = []struct {
		name       string
		whenStatus int
		whenError  error
		expectCode codes.Code
		expectDesc string
	}{
		{
			name:       "error overrides status code",
			whenStatus: 200,
			whenError:  errors.New("network error"),
			expectCode: codes.Error,
			expectDesc: "network error",
		},
		{
			name:       "error with invalid status code",
			whenStatus: 0,
			whenError:  errors.New("network error"),
			expectCode: codes.Error,
			expectDesc: "Invalid HTTP status code 0",
		},
		{
			name:       "invalid status code below range",
			whenStatus: 99,
			whenError:  nil,
			expectCode: codes.Error,
			expectDesc: "Invalid HTTP status code 99",
		},
		{
			name:       "invalid status code above range",
			whenStatus: 600,
			whenError:  nil,
			expectCode: codes.Error,
			expectDesc: "Invalid HTTP status code 600",
		},
		{
			name:       "server error 500",
			whenStatus: 500,
			whenError:  nil,
			expectCode: codes.Error,
			expectDesc: "",
		},
		{
			name:       "server error 503",
			whenStatus: 503,
			whenError:  nil,
			expectCode: codes.Error,
			expectDesc: "",
		},
		{
			name:       "server error 500 with error keeps error description",
			whenStatus: 500,
			whenError:  errors.New("something failed"),
			expectCode: codes.Error,
			expectDesc: "something failed",
		},
		{
			name:       "client error 404 is left unset for server span",
			whenStatus: 404,
			whenError:  nil,
			expectCode: codes.Unset,
			expectDesc: "",
		},
		{
			name:       "client error 400 with error is left unset for server span",
			whenStatus: 400,
			whenError:  errors.New("invalid request"),
			expectCode: codes.Unset,
			expectDesc: "",
		},
		{
			name:       "informational status 100",
			whenStatus: 100,
			whenError:  nil,
			expectCode: codes.Unset,
			expectDesc: "",
		},
		{
			name:       "success status 200",
			whenStatus: 200,
			whenError:  nil,
			expectCode: codes.Unset,
			expectDesc: "",
		},
		{
			name:       "redirect status 302",
			whenStatus: 302,
			whenError:  nil,
			expectCode: codes.Unset,
			expectDesc: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			code, desc := SpanStatus(tc.whenStatus, tc.whenError)

			assert.Equal(t, tc.expectCode, code)
			assert.Equal(t, tc.expectDesc, desc)
		})
	}
}

// testStatusError carries an HTTP status code, like Echo's HTTPError.
type testStatusError struct {
	code int
}

func (e *testStatusError) Error() string   { return fmt.Sprintf("status %d", e.code) }
func (e *testStatusError) StatusCode() int { return e.code }

func TestErrorType(t *testing.T) {
	var testCases = []struct {
		name       string
		whenStatus int
		whenError  error
		expect     string
	}{
		{
			name:       "success status 200",
			whenStatus: 200,
		},
		{
			name:       "redirect status 302",
			whenStatus: 302,
		},
		{
			name:       "client error 404 is not an error for server span",
			whenStatus: 404,
		},
		{
			name:       "client error 400 with error is not an error for server span",
			whenStatus: 400,
			whenError:  &testStatusError{code: 400},
		},
		{
			name:       "server error 500 without error value",
			whenStatus: 500,
			expect:     "500",
		},
		{
			name:       "server error 503 with error carrying status code",
			whenStatus: 503,
			whenError:  &testStatusError{code: 503},
			expect:     "503",
		},
		{
			name:       "server error 500 with wrapped error carrying status code",
			whenStatus: 500,
			whenError:  fmt.Errorf("handler: %w", &testStatusError{code: 500}),
			expect:     "500",
		},
		{
			name:       "server error 500 with plain error uses error type",
			whenStatus: 500,
			whenError:  errors.New("something failed"),
			expect:     "*errors.errorString",
		},
		{
			name:       "server error 500 with fmt.Errorf wrapped error reports the wrapped error type",
			whenStatus: 500,
			whenError:  fmt.Errorf("db: %w", fmt.Errorf("query: %w", &net.OpError{Op: "read", Err: errors.New("reset")})),
			expect:     "*net.OpError",
		},
		{
			name:       "server error 500 with errors.Join reports the join type",
			whenStatus: 500,
			whenError:  errors.Join(errors.New("a"), errors.New("b")),
			expect:     "*errors.joinError",
		},
		{
			name:       "server error 500 with fmt.Errorf wrapping two errors reports the wrapper type",
			whenStatus: 500,
			whenError:  fmt.Errorf("%w and %w", errors.New("a"), errors.New("b")),
			expect:     "*fmt.wrapErrors",
		},
		{
			name:       "server error 500 with ErrorType method in the error chain",
			whenStatus: 500,
			whenError:  fmt.Errorf("handler: %w", testTypedError{}),
			expect:     "test.custom",
		},
		{
			name:       "error alongside success status uses error type",
			whenStatus: 200,
			whenError:  errors.New("network error"),
			expect:     "*errors.errorString",
		},
		{
			name:       "invalid status code with error uses error type",
			whenStatus: 0,
			whenError:  errors.New("network error"),
			expect:     "*errors.errorString",
		},
		{
			name:       "status code above 599 without error reports the code",
			whenStatus: 799,
			expect:     "799",
		},
		{
			name:       "status code below 100 without error",
			whenStatus: 99,
			expect:     "_OTHER",
		},
		{
			name:       "status code above 999 without error",
			whenStatus: 1000,
			expect:     "_OTHER",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expect, ErrorType(tc.whenStatus, tc.whenError))
		})
	}
}

// testTypedError implements ErrorType() string, which semconv.ErrorType prefers over the Go type.
type testTypedError struct{}

func (testTypedError) Error() string     { return "typed" }
func (testTypedError) ErrorType() string { return "test.custom" }
