module github.com/labstack/echo-opentelemetry/echootel/example

go 1.25.6

replace github.com/labstack/echo-opentelemetry/echootel => ../

require (
	github.com/labstack/echo-opentelemetry/echootel v0.0.0-00010101000000-000000000000
	github.com/labstack/echo/v5 v5.0.4
	go.opentelemetry.io/otel v1.40.0
	go.opentelemetry.io/otel/exporters/stdout/stdouttrace v1.40.0
	go.opentelemetry.io/otel/sdk v1.40.0
	go.opentelemetry.io/otel/trace v1.40.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/metric v1.40.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/time v0.14.0 // indirect
)
