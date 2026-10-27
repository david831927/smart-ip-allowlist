package smart_ip_allowlist

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseIPValue(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"bare IPv4", "203.0.113.10", "203.0.113.10"},
		{"IPv4 with port", "203.0.113.10:8080", "203.0.113.10"},
		{"IPv4 with spaces", " 203.0.113.10 ", "203.0.113.10"},
		{"bracketed IPv6 with port", "[2001:db8::1]:443", "2001:db8::1"},
		{"bare IPv6", "2001:db8::1", "2001:db8::1"},
		{"invalid", "not-an-ip", ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseIPValue(tt.in); got != tt.want {
				t.Fatalf("parseIPValue(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestIPCheckerContainsExactIPAndCIDR(t *testing.T) {
	checker, err := newIPChecker([]string{
		"203.0.113.10",
		"198.51.100.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.10", true},
		{"203.0.113.11", false},
		{"198.51.100.42", true},
		{"198.51.101.42", false},
	}
	for _, tt := range tests {
		if got := checker.contains(net.ParseIP(tt.ip)); got != tt.want {
			t.Errorf("contains(%s) = %t, want %t", tt.ip, got, tt.want)
		}
	}
}

func TestDefaultPrivateSubnetsAppliedWhenEmpty(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mw, err := New(context.Background(), next, &Config{
		SourceRange: []string{"203.0.113.10/32"},
		IPHeaders:   []string{"X-Forwarded-For"},
		// 有意省略 PrivateSubnets。
	}, "test")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("X-Forwarded-For", "10.1.2.3, 203.0.113.10")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
}

func TestCreateConfigDefaults(t *testing.T) {
	config := CreateConfig()
	if config.Debug {
		t.Fatal("Debug = true, want false")
	}

	wantHeaders := []string{"X-Forwarded-For", "X-Real-Ip"}
	if len(config.IPHeaders) != len(wantHeaders) {
		t.Fatalf("IPHeaders = %v, want %v", config.IPHeaders, wantHeaders)
	}
	for i, want := range wantHeaders {
		if config.IPHeaders[i] != want {
			t.Fatalf("IPHeaders[%d] = %q, want %q", i, config.IPHeaders[i], want)
		}
	}

	wantPrivateSubnets := []string{
		"10.0.0.0/8",
		"100.64.0.0/10",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"198.18.0.0/15",
	}
	if len(config.PrivateSubnets) != len(wantPrivateSubnets) {
		t.Fatalf("PrivateSubnets = %v, want %v", config.PrivateSubnets, wantPrivateSubnets)
	}
	for i, want := range wantPrivateSubnets {
		if config.PrivateSubnets[i] != want {
			t.Fatalf("PrivateSubnets[%d] = %q, want %q", i, config.PrivateSubnets[i], want)
		}
	}
}

func TestNoIPHeadersConfiguredUsesDefaultHeaders(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mw, err := New(context.Background(), next, &Config{
		SourceRange: []string{"203.0.113.10/32"},
	}, "test")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestDefaultPrivateSubnetsSkipsCarrierGradeNAT(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mw, err := New(context.Background(), next, &Config{
		SourceRange: []string{"203.0.113.10/32"},
		IPHeaders:   []string{"X-Forwarded-For"},
	}, "test")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("X-Forwarded-For", "100.64.0.1")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestNonGlobalUnicastHeaderIsSkipped(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mw, err := New(context.Background(), next, &Config{
		SourceRange: []string{"203.0.113.10/32"},
		IPHeaders:   []string{"X-Real-IP"},
	}, "test")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("X-Real-IP", "127.0.0.1")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestPrivateHeaderSkippedAndRemoteAddrUsed(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mw, err := New(context.Background(), next, &Config{
		SourceRange: []string{"203.0.113.10/32"},
		IPHeaders:   []string{"X-Real-IP"},
	}, "test")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("X-Real-IP", "10.1.2.3")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestHeadersForceStillRequiresAllowlist(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mw, err := New(context.Background(), next, &Config{
		SourceRange:  []string{"203.0.113.10/32"},
		IPHeaders:    []string{"X-Real-IP"},
		HeadersForce: true,
	}, "test")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("X-Real-IP", "10.1.2.3")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestRepeatedHeaderValuesAreRejected(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mw, err := New(context.Background(), next, &Config{
		SourceRange: []string{"203.0.113.10/32"},
		IPHeaders:   []string{"X-Real-IP", "X-Forwarded-For"},
	}, "test")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("X-Real-IP", "203.0.113.10")
	req.Header.Add("X-Forwarded-For", "198.51.100.10")
	req.Header.Add("X-Forwarded-For", "203.0.113.10")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestNewRejectsBlankPrivateSubnetsEntry(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if _, err := New(context.Background(), next, &Config{
		SourceRange:    []string{"203.0.113.10/32"},
		PrivateSubnets: []string{"10.0.0.0/8", "  "},
	}, "test"); err == nil {
		t.Fatal("expected blank privateSubnets entry to be rejected")
	}
}

func TestNewRejectsBlankSourceRangeAndNilNext(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	if _, err := New(context.Background(), next, &Config{
		SourceRange: []string{"  "},
	}, "test"); err == nil {
		t.Fatal("expected blank sourceRange to be rejected")
	}
	if _, err := New(context.Background(), next, &Config{
		SourceRange: []string{"203.0.113.10", "  "},
	}, "test"); err == nil {
		t.Fatal("expected blank sourceRange entry to be rejected")
	}

	if _, err := New(context.Background(), nil, &Config{
		SourceRange: []string{"203.0.113.10"},
	}, "test"); err == nil {
		t.Fatal("expected nil next handler to be rejected")
	}
}

func TestCustomRejectStatusCode(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mw, err := New(context.Background(), next, &Config{
		SourceRange:      []string{"203.0.113.10/32"},
		RejectStatusCode: 499,
	}, "test")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)
	if rec.Code != 499 {
		t.Fatalf("status = %d, want %d", rec.Code, 499)
	}
}
