// Package ratelimit throttles matching requests independently by client IP.
package ratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"gopkg.in/yaml.v3"
)

const (
	bucketIdleTTL = 10 * time.Minute
	cleanupPeriod = time.Minute
)

type ruleConfig struct {
	Host              string `yaml:"host"`
	Port              string `yaml:"port"`
	Path              string `yaml:"path"`
	RequestsPerSecond int    `yaml:"requests_per_second"`
	Burst             int    `yaml:"burst,omitempty"`
}

type config struct {
	Rules []ruleConfig `yaml:"rules"`
}

type bucket struct {
	tokens   float64
	updated  time.Time
	lastSeen time.Time
}

type rule struct {
	host        string
	port        string
	path        string
	rate        float64
	burst       float64
	mu          sync.Mutex
	buckets     map[string]*bucket
	nextCleanup time.Time
}

type limiter struct{ rules []*rule }

func init() { transform.Register("rate_limit", factory) }

func factory(node yaml.Node, _ *slog.Logger) (transform.Transformer, error) {
	var cfg config
	if err := transform.DecodeKnownFields(node, &cfg); err != nil {
		return nil, fmt.Errorf("parsing rate_limit config: %w", err)
	}
	if len(cfg.Rules) == 0 {
		return nil, fmt.Errorf("rate_limit: at least one rule is required")
	}

	result := &limiter{}
	seen := make(map[string]struct{}, len(cfg.Rules))
	for i, source := range cfg.Rules {
		compiled, err := compileRule(source)
		if err != nil {
			return nil, fmt.Errorf("rate_limit: rules[%d]: %w", i, err)
		}
		selector := compiled.host + "\x00" + compiled.port + "\x00" + compiled.path
		if _, exists := seen[selector]; exists {
			return nil, fmt.Errorf("rate_limit: rules[%d]: duplicate host, port, and path", i)
		}
		seen[selector] = struct{}{}
		result.rules = append(result.rules, compiled)
	}
	return result, nil
}

func compileRule(source ruleConfig) (*rule, error) {
	host := strings.ToLower(strings.TrimSuffix(source.Host, "."))
	if host == "" || strings.ContainsAny(host, "*?/\\@") {
		return nil, fmt.Errorf("host must be an exact hostname")
	}
	portNumber, err := strconv.ParseUint(source.Port, 10, 16)
	if err != nil || portNumber == 0 {
		return nil, fmt.Errorf("port must be an integer from 1 through 65535")
	}
	if source.Path != "" {
		if !strings.HasPrefix(source.Path, "/") {
			return nil, fmt.Errorf("path must be an absolute exact path")
		}
		if strings.ContainsAny(source.Path, "*?[]\\") {
			return nil, fmt.Errorf("path must not contain glob or query syntax")
		}
		if decoded, err := url.PathUnescape(source.Path); err != nil || decoded != source.Path {
			return nil, fmt.Errorf("path must use its canonical unescaped spelling")
		}
	}
	if source.RequestsPerSecond <= 0 {
		return nil, fmt.Errorf("requests_per_second must be positive")
	}
	if source.Burst < 0 {
		return nil, fmt.Errorf("burst must not be negative")
	}
	burst := source.Burst
	if burst == 0 {
		burst = 1
	}
	return &rule{
		host:    host,
		port:    source.Port,
		path:    source.Path,
		rate:    float64(source.RequestsPerSecond),
		burst:   float64(burst),
		buckets: make(map[string]*bucket),
	}, nil
}

func (l *limiter) Name() string { return "rate_limit" }

func (l *limiter) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	rule := l.match(req)
	if rule == nil || req.Method == http.MethodConnect {
		return continueResult(), nil
	}

	delay := rule.reserve(clientIP(req.RemoteAddr), time.Now())
	if delay <= 0 {
		return continueResult(), nil
	}
	tctx.Annotate("wait_ms", delay.Milliseconds())
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return continueResult(), nil
	}
}

func (l *limiter) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return continueResult(), nil
}

func (l *limiter) match(req *http.Request) *rule {
	host, port := hostmatch.HostPort(req)
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	path := ""
	if req.URL != nil {
		path = req.URL.Path
	}
	for _, rule := range l.rules {
		if rule.host == host && rule.port == port && (rule.path == "" || rule.path == path) {
			return rule
		}
	}
	return nil
}

func (r *rule) reserve(key string, now time.Time) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.nextCleanup.IsZero() || !now.Before(r.nextCleanup) {
		cutoff := now.Add(-bucketIdleTTL)
		for key, existing := range r.buckets {
			if existing.lastSeen.Before(cutoff) {
				delete(r.buckets, key)
			}
		}
		r.nextCleanup = now.Add(cleanupPeriod)
	}

	state := r.buckets[key]
	if state == nil {
		state = &bucket{tokens: r.burst, updated: now}
		r.buckets[key] = state
	}
	if now.After(state.updated) {
		state.tokens += now.Sub(state.updated).Seconds() * r.rate
		if state.tokens > r.burst {
			state.tokens = r.burst
		}
		state.updated = now
	}
	state.tokens--
	state.lastSeen = now
	if state.tokens >= 0 {
		return 0
	}
	return time.Duration((-state.tokens / r.rate) * float64(time.Second))
}

func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

func continueResult() *transform.TransformResult {
	return &transform.TransformResult{Action: transform.ActionContinue}
}
