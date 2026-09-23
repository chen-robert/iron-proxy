package ratelimit

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestRateLimitReservationsArePerClient(t *testing.T) {
	rule, err := compileRule(ruleConfig{
		Host: "rpc.example.com", Port: "443", Path: "/rpc",
		RequestsPerSecond: 50, Burst: 1,
	})
	require.NoError(t, err)
	now := time.Unix(100, 0)

	require.Zero(t, rule.reserve("10.0.0.1", now))
	require.Equal(t, 20*time.Millisecond, rule.reserve("10.0.0.1", now))
	require.Zero(t, rule.reserve("10.0.0.2", now))
	require.Equal(t, 10*time.Millisecond, rule.reserve("10.0.0.1", now.Add(30*time.Millisecond)))
}

func TestRateLimitScopesExactEndpoint(t *testing.T) {
	limiter := loadLimiter(t, `
rules:
  - host: rpc.example.com
    port: "443"
    path: /rpc
    requests_per_second: 50
`)

	cases := []struct {
		name    string
		host    string
		path    string
		matched bool
	}{
		{name: "exact", host: "rpc.example.com", path: "/rpc", matched: true},
		{name: "other host", host: "api.example.com", path: "/rpc"},
		{name: "other path", host: "rpc.example.com", path: "/health"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{
				Method: http.MethodPost,
				Host:   tc.host,
				URL:    &url.URL{Scheme: "https", Path: tc.path},
				TLS:    nil,
			}
			require.Equal(t, tc.matched, limiter.match(req) != nil)
		})
	}
}

func TestRateLimitCanScopeWholeHost(t *testing.T) {
	limiter := loadLimiter(t, `
rules:
  - host: rpc.example.com
    port: "443"
    requests_per_second: 50
`)
	for _, path := range []string{"/", "/rpc", "/another-endpoint"} {
		req := &http.Request{
			Method: http.MethodPost,
			Host:   "rpc.example.com",
			URL:    &url.URL{Scheme: "https", Path: path},
		}
		require.NotNil(t, limiter.match(req))
	}
}

func TestRateLimitRejectsUnknownFields(t *testing.T) {
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(`
rules:
  - host: rpc.example.com
    port: "443"
    path: /rpc
    requests_per_second: 50
    unknown: true
`), &node))
	_, err := factory(node, nil)
	require.ErrorContains(t, err, "field unknown not found")
}

func TestRateLimitSkipsConnect(t *testing.T) {
	limiter := loadLimiter(t, `
rules:
  - host: rpc.example.com
    port: "443"
    path: /rpc
    requests_per_second: 50
`)
	req := &http.Request{Method: http.MethodConnect, RemoteAddr: "10.0.0.1:1234"}
	result, err := limiter.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, result.Action)
}

func loadLimiter(t *testing.T, source string) *limiter {
	t.Helper()
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(source), &node))
	result, err := factory(node, nil)
	require.NoError(t, err)
	return result.(*limiter)
}
