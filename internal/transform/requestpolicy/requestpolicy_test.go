// Added by crypto-scan to vendored IronProxy v0.49.0.
package requestpolicy

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	evmAddressPattern = `0[xX][0-9a-fA-F]{40}`
	topLevelAddress   = "0x0000000000000000000000000000000000000001"
	discoveredAddress = "0XAbCdEf0123456789aBCdef0123456789AbCDef01"
)

func exactValues(t *testing.T, values ...string) yaml.Node {
	t.Helper()
	var node yaml.Node
	require.NoError(t, node.Encode(values))
	return node
}

func valuePattern(t *testing.T, pattern string) yaml.Node {
	t.Helper()
	var node yaml.Node
	require.NoError(t, node.Encode(pattern))
	return node
}

func booleanNode(t *testing.T, value bool) yaml.Node {
	t.Helper()
	var node yaml.Node
	require.NoError(t, node.Encode(value))
	return node
}

func testPolicy(t *testing.T) transform.Transformer {
	t.Helper()
	var node yaml.Node
	require.NoError(t, node.Encode(config{Rules: []ruleConfig{
		{
			Host: "api.etherscan.io", Port: "443", Path: "/v2/api",
			HTTPMethods: []string{"GET", "HEAD"}, RequireEmptyBody: true,
			Query: queryConfig{Mode: "exact", Parameters: []queryParameterConfig{
				{Name: "chainid", Required: true, ExactValues: exactValues(t, "1")},
				{Name: "module", Required: true, ExactValues: exactValues(t, "contract")},
				{Name: "action", Required: true, ExactValues: exactValues(t, "getsourcecode")},
				{Name: "address", Required: true, ValuePattern: valuePattern(t, evmAddressPattern)},
				{Name: "apikey", Required: true, ExactValues: exactValues(t, "broker-token")},
			}},
		},
		{
			Host: "binaries.soliditylang.org", Port: "443", Path: "/linux-amd64/list.json",
			HTTPMethods: []string{"GET", "HEAD"}, RequireEmptyBody: true,
			Query: queryConfig{Mode: "empty"},
		},
	}}))
	result, err := factory(node, slog.Default())
	require.NoError(t, err)
	return result
}

func run(t *testing.T, p transform.Transformer, req *http.Request) (transform.TransformAction, map[string]any) {
	t.Helper()
	if req.Body != nil {
		req.Body = transform.NewBufferedBody(req.Body, 1024*1024)
	}
	tctx := &transform.TransformContext{}
	result, err := p.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	return result.Action, tctx.DrainAnnotations()
}

func TestAllowsExactShapePatternValueEmptyBodyAndCONNECT(t *testing.T) {
	p := testPolicy(t)
	for _, target := range []string{
		"https://api.etherscan.io/v2/api?module=contract&address=" + topLevelAddress + "&apikey=broker-token&action=getsourcecode&chainid=1",
		"https://api.etherscan.io/v2/api?action=getsourcecode&apikey=broker-token&address=" + discoveredAddress + "&module=contract&chainid=1",
		"https://binaries.soliditylang.org/linux-amd64/list.json",
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		action, annotations := run(t, p, req)
		require.Equal(t, transform.ActionContinue, action)
		require.Equal(t, "allow", annotations["decision"])
	}
	req := httptest.NewRequest(http.MethodConnect, "https://api.etherscan.io:443", nil)
	req.Host = "api.etherscan.io:443"
	action, annotations := run(t, p, req)
	require.Equal(t, transform.ActionContinue, action)
	require.Equal(t, "tunnel", annotations["decision"])
}

func TestRejectsQueryAndBodyExfiltration(t *testing.T) {
	p := testPolicy(t)
	valid := "module=contract&action=getsourcecode&address=" + topLevelAddress + "&chainid=1&apikey=broker-token"
	cases := []struct {
		name, target, body, reason string
		mutate                     func(*http.Request)
	}{
		{"unknown parameter", "https://api.etherscan.io/v2/api?" + valid + "&leak=x", "", "query", nil},
		{"duplicate parameter", "https://api.etherscan.io/v2/api?" + valid + "&address=" + discoveredAddress, "", "query", nil},
		{"wrong address", "https://api.etherscan.io/v2/api?module=contract&action=getsourcecode&address=0xdeadbeef&chainid=1&apikey=broker-token", "", "query", nil},
		{"address prefix", "https://api.etherscan.io/v2/api?module=contract&action=getsourcecode&address=prefix" + topLevelAddress + "&chainid=1&apikey=broker-token", "", "query", nil},
		{"address suffix", "https://api.etherscan.io/v2/api?module=contract&action=getsourcecode&address=" + topLevelAddress + "suffix&chainid=1&apikey=broker-token", "", "query", nil},
		{"address too long", "https://api.etherscan.io/v2/api?module=contract&action=getsourcecode&address=" + topLevelAddress + "0&chainid=1&apikey=broker-token", "", "query", nil},
		{"address non hex", "https://api.etherscan.io/v2/api?module=contract&action=getsourcecode&address=0x000000000000000000000000000000000000000g&chainid=1&apikey=broker-token", "", "query", nil},
		{"address decoded newline", "https://api.etherscan.io/v2/api?module=contract&action=getsourcecode&address=" + topLevelAddress + "%0A&chainid=1&apikey=broker-token", "", "query", nil},
		{"missing parameter", "https://api.etherscan.io/v2/api?module=contract&action=getsourcecode&address=" + topLevelAddress + "&chainid=1", "", "query", nil},
		{"wrong chain", "https://api.etherscan.io/v2/api?module=contract&action=getsourcecode&address=" + topLevelAddress + "&chainid=10&apikey=broker-token", "", "query", nil},
		{"wrong module", "https://api.etherscan.io/v2/api?module=account&action=getsourcecode&address=" + topLevelAddress + "&chainid=1&apikey=broker-token", "", "query", nil},
		{"wrong action", "https://api.etherscan.io/v2/api?module=contract&action=getabi&address=" + topLevelAddress + "&chainid=1&apikey=broker-token", "", "query", nil},
		{"wrong key", "https://api.etherscan.io/v2/api?module=contract&action=getsourcecode&address=" + topLevelAddress + "&chainid=1&apikey=other", "", "query", nil},
		{"v1 endpoint", "https://api.etherscan.io/api?" + valid, "", "path", nil},
		{"post method", "https://api.etherscan.io/v2/api?" + valid, "", "http_method", func(r *http.Request) { r.Method = http.MethodPost }},
		{"artifact query", "https://binaries.soliditylang.org/linux-amd64/list.json?leak=x", "", "query", nil},
		{"get body", "https://api.etherscan.io/v2/api?" + valid, "secret", "content_length", nil},
		{"head body", "https://binaries.soliditylang.org/linux-amd64/list.json", "secret", "content_length", func(r *http.Request) { r.Method = http.MethodHead }},
		{"chunked body", "https://binaries.soliditylang.org/linux-amd64/list.json", "secret", "transfer_encoding", func(r *http.Request) { r.ContentLength = -1; r.TransferEncoding = []string{"chunked"} }},
		{"hidden zero-length body", "https://binaries.soliditylang.org/linux-amd64/list.json", "secret", "body", func(r *http.Request) { r.ContentLength = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, strings.NewReader(tc.body))
			if tc.mutate != nil {
				tc.mutate(req)
			}
			action, annotations := run(t, p, req)
			require.Equal(t, transform.ActionReject, action)
			require.Equal(t, tc.reason, annotations["reason"])
		})
	}
}

func TestRejectsInvalidPatternConfiguration(t *testing.T) {
	cases := []struct {
		name      string
		parameter queryParameterConfig
	}{
		{name: "neither matcher", parameter: queryParameterConfig{Name: "key", Required: true}},
		{name: "empty exact values", parameter: queryParameterConfig{Name: "key", Required: true, ExactValues: exactValues(t)}},
		{name: "empty pattern", parameter: queryParameterConfig{Name: "key", Required: true, ValuePattern: valuePattern(t, "")}},
		{name: "both matchers", parameter: queryParameterConfig{Name: "key", Required: true, ExactValues: exactValues(t, "value"), ValuePattern: valuePattern(t, "value")}},
		{name: "pattern with empty exact values", parameter: queryParameterConfig{Name: "key", Required: true, ExactValues: exactValues(t), ValuePattern: valuePattern(t, "value")}},
		{name: "invalid pattern", parameter: queryParameterConfig{Name: "key", Required: true, ValuePattern: valuePattern(t, "[")}},
		{name: "pattern case insensitive", parameter: queryParameterConfig{Name: "key", Required: true, ValuePattern: valuePattern(t, "value"), CaseInsensitive: booleanNode(t, true)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var node yaml.Node
			require.NoError(t, node.Encode(config{Rules: []ruleConfig{
				{
					Host: "example", Port: "443", Path: "/", HTTPMethods: []string{"GET"},
					Query: queryConfig{Mode: "exact", Parameters: []queryParameterConfig{tc.parameter}},
				},
			}}))
			_, err := factory(node, slog.Default())
			require.Error(t, err)
		})
	}
}

func TestRejectsNullMatcherFieldsByYAMLKeyPresence(t *testing.T) {
	cases := map[string]string{
		"null exact plus pattern": "exact_values: null\n          value_pattern: value",
		"exact plus null pattern": "exact_values: [value]\n          value_pattern: null",
		"lone null exact":         `exact_values: null`,
		"lone null pattern":       `value_pattern: null`,
	}
	for name, matcherConfig := range cases {
		t.Run(name, func(t *testing.T) {
			source := `rules:
  - host: example
    port: "443"
    path: /
    http_methods: [GET]
    query:
      mode: exact
      parameters:
        - name: key
          required: true
          ` + matcherConfig
			var document yaml.Node
			require.NoError(t, yaml.Unmarshal([]byte(source), &document))
			_, err := factory(*document.Content[0], slog.Default())
			require.Error(t, err)
		})
	}
}

func TestRejectsNonStringPatternYAML(t *testing.T) {
	cases := map[string]struct {
		nameValue    string
		patternValue string
	}{
		"boolean":       {nameValue: "key", patternValue: "true"},
		"integer":       {nameValue: "key", patternValue: "42"},
		"float":         {nameValue: "key", patternValue: "1.5"},
		"binary":        {nameValue: "key", patternValue: "!!binary SGVsbG8="},
		"sequence":      {nameValue: "key", patternValue: "[value]"},
		"mapping":       {nameValue: "key", patternValue: "{pattern: value}"},
		"alias":         {nameValue: "&pattern key", patternValue: "*pattern"},
		"custom tag":    {nameValue: "key", patternValue: "!custom value"},
		"explicit bool": {nameValue: "key", patternValue: "!!bool true"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			source := `rules:
  - host: example
    port: "443"
    path: /
    http_methods: [GET]
    query:
      mode: exact
      parameters:
        - name: ` + tc.nameValue + `
          required: true
          value_pattern: ` + tc.patternValue
			var document yaml.Node
			require.NoError(t, yaml.Unmarshal([]byte(source), &document))
			_, err := factory(*document.Content[0], slog.Default())
			require.Error(t, err)
		})
	}
}

func TestCaseInsensitiveYAMLFieldSemantics(t *testing.T) {
	for name, value := range map[string]string{
		"pattern true":  "true",
		"pattern false": "false",
		"pattern null":  "null",
	} {
		t.Run(name, func(t *testing.T) {
			source := queryParameterYAML("value_pattern: value\n          case_insensitive: " + value)
			_, err := policyFromYAML(source)
			require.Error(t, err)
		})
	}

	for name, value := range map[string]string{
		"null":       "null",
		"string":     `"true"`,
		"integer":    "1",
		"float":      "1.5",
		"sequence":   "[true]",
		"mapping":    "{value: true}",
		"custom tag": "!custom true",
	} {
		t.Run("exact malformed "+name, func(t *testing.T) {
			source := queryParameterYAML("exact_values: [Value]\n          case_insensitive: " + value)
			_, err := policyFromYAML(source)
			require.Error(t, err)
		})
	}

	for _, tc := range []struct {
		name, setting string
		wantLower     bool
	}{
		{name: "omitted"},
		{name: "false", setting: "\n          case_insensitive: false"},
		{name: "true", setting: "\n          case_insensitive: true", wantLower: true},
	} {
		t.Run("exact valid "+tc.name, func(t *testing.T) {
			p, err := policyFromYAML(queryParameterYAML("exact_values: [Value]" + tc.setting))
			require.NoError(t, err)

			action, _ := run(t, p, httptest.NewRequest(http.MethodGet, "https://example/?key=Value", nil))
			require.Equal(t, transform.ActionContinue, action)
			action, _ = run(t, p, httptest.NewRequest(http.MethodGet, "https://example/?key=value", nil))
			if tc.wantLower {
				require.Equal(t, transform.ActionContinue, action)
			} else {
				require.Equal(t, transform.ActionReject, action)
			}
		})
	}
}

func queryParameterYAML(parameterFields string) string {
	return `rules:
  - host: example
    port: "443"
    path: /
    http_methods: [GET]
    query:
      mode: exact
      parameters:
        - name: key
          required: true
          ` + parameterFields
}

func policyFromYAML(source string) (transform.Transformer, error) {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(source), &document); err != nil {
		return nil, err
	}
	return factory(*document.Content[0], slog.Default())
}

func TestRejectsInvalidConfiguration(t *testing.T) {
	for _, source := range []ruleConfig{
		{Host: "*.example", Port: "443", Path: "/", HTTPMethods: []string{"GET"}, Query: queryConfig{Mode: "empty"}},
		{Host: "example", Port: "0", Path: "/", HTTPMethods: []string{"GET"}, Query: queryConfig{Mode: "empty"}},
		{Host: "example", Port: "443", Path: "/%61", HTTPMethods: []string{"GET"}, Query: queryConfig{Mode: "empty"}},
		{Host: "example", Port: "443", Path: "/", HTTPMethods: []string{"CONNECT"}, Query: queryConfig{Mode: "empty"}},
		{Host: "example", Port: "443", Path: "/", HTTPMethods: []string{"GET"}, Query: queryConfig{Mode: "exact"}},
	} {
		var node yaml.Node
		require.NoError(t, node.Encode(config{Rules: []ruleConfig{source}}))
		_, err := factory(node, slog.Default())
		require.Error(t, err)
	}
}

func TestExactQueryPreservesDuplicateMultiplicityAndDecodedValues(t *testing.T) {
	var node yaml.Node
	require.NoError(t, node.Encode(config{
		Rules: []ruleConfig{
			{
				Host: "rpc.example", Port: "443", Path: "/rpc", HTTPMethods: []string{"POST"},
				Query: queryConfig{Mode: "exact", Parameters: []queryParameterConfig{
					{Name: "project", Required: true, ExactValues: exactValues(t, "first", "second", "second")},
					{Name: "label", Required: true, ExactValues: exactValues(t, "Hello World"), CaseInsensitive: booleanNode(t, true)},
				}},
			},
		},
	}))
	p, err := factory(node, slog.Default())
	require.NoError(t, err)

	allowed := []string{
		"project=first&project=second&project=second&label=hello+world",
		"label=HELLO%20WORLD&project=second&project=first&project=second",
	}
	for _, rawQuery := range allowed {
		req := httptest.NewRequest(http.MethodPost, "https://rpc.example/rpc?"+rawQuery, nil)
		action, annotations := run(t, p, req)
		require.Equal(t, transform.ActionContinue, action)
		require.Equal(t, "allow", annotations["decision"])
	}

	denied := []string{
		"project=first&project=second&label=hello+world",                               // removal
		"project=first&project=second&project=second&project=second&label=hello+world", // duplication
		"project=first&project=second&project=second&label=hello+world&leak=x",         // addition
		"project=first&project=second&project=changed&label=hello+world",               // alteration
		"project=first&project=second&project=second&label=hello%2520world",            // different decoded value
	}
	for _, rawQuery := range denied {
		req := httptest.NewRequest(http.MethodPost, "https://rpc.example/rpc?"+rawQuery, nil)
		action, annotations := run(t, p, req)
		require.Equal(t, transform.ActionReject, action)
		require.Equal(t, "query", annotations["reason"])
	}
}

func TestPatternQueryRequiresExactlyOneWholeDecodedValue(t *testing.T) {
	var node yaml.Node
	require.NoError(t, node.Encode(config{
		Rules: []ruleConfig{
			{
				Host: "example", Port: "443", Path: "/source", HTTPMethods: []string{"GET"},
				Query: queryConfig{Mode: "exact", Parameters: []queryParameterConfig{
					{Name: "address", Required: true, ValuePattern: valuePattern(t, `alpha|alphabet`)},
				}},
			},
		},
	}))
	p, err := factory(node, slog.Default())
	require.NoError(t, err)

	for _, rawQuery := range []string{
		"address=alpha",
		"address=alphabet",
		"address=alpha%62et",
	} {
		req := httptest.NewRequest(http.MethodGet, "https://example/source?"+rawQuery, nil)
		action, annotations := run(t, p, req)
		require.Equal(t, transform.ActionContinue, action)
		require.Equal(t, "allow", annotations["decision"])
	}

	for _, rawQuery := range []string{
		"",
		"address=prefixalphabet",
		"address=alphabetsuffix",
		"address=alpha&address=alphabet",
		"address=other",
	} {
		req := httptest.NewRequest(http.MethodGet, "https://example/source?"+rawQuery, nil)
		action, annotations := run(t, p, req)
		require.Equal(t, transform.ActionReject, action)
		require.Equal(t, "query", annotations["reason"])
	}
}

func TestRejectsUnknownYAMLFieldsAtEveryNestingLevel(t *testing.T) {
	for name, source := range map[string]string{
		"config":    `rulez: []`,
		"rule":      `rules: [{host: example, port: "443", path: /, http_methods: [GET], query: {mode: empty}, unexpected: true}]`,
		"query":     `rules: [{host: example, port: "443", path: /, http_methods: [GET], query: {mode: empty, unexpected: true}}]`,
		"parameter": `rules: [{host: example, port: "443", path: /, http_methods: [GET], query: {mode: exact, parameters: [{name: key, required: true, exact_values: [value], unexpected: true}]}}]`,
		"pattern":   `rules: [{host: example, port: "443", path: /, http_methods: [GET], query: {mode: exact, parameters: [{name: key, required: true, value_patterns: value}]}}]`,
	} {
		t.Run(name, func(t *testing.T) {
			var document yaml.Node
			require.NoError(t, yaml.Unmarshal([]byte(source), &document))
			_, err := factory(*document.Content[0], slog.Default())
			require.Error(t, err)
			require.Contains(t, err.Error(), "field ")
			require.Contains(t, err.Error(), "not found")
		})
	}
}
