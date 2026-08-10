package ncm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestRuntimePolicyAllowsPairing(t *testing.T) {
	mk := func(enabled, blocked bool, reason, license string) runtimePolicy {
		var p runtimePolicy
		p.Pairing.Enabled = enabled
		p.Pairing.Blocked = blocked
		p.Pairing.Reason = reason
		p.License = license
		return p
	}

	if !mk(true, false, "none", "licensed").allowsPairing() {
		t.Fatal("expected pairing allowed for a licensed, unblocked policy")
	}

	blocked := map[string]runtimePolicy{
		// still "licensed" with a valid block, so the block must ride on Blocked
		"no capacity (0 licenses)": mk(true, true, "no-capacity", "licensed"),
		"pairing disabled":         mk(false, true, "pairing-disabled", "licensed"),
		"unlicensed":               mk(true, false, "none", "required"),
	}
	for name, p := range blocked {
		if p.allowsPairing() {
			t.Errorf("expected pairing blocked for %q", name)
		}
	}
}

func clearLicenseEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"NCM_LICENSE_POLICY_URL", "BACKEND_HOST", "BACKEND_PORT", "NCM_LICENSE_POLL_INTERVAL_SECONDS"} {
		os.Unsetenv(k)
	}
}

func TestLicensePolicyURLFromEnv(t *testing.T) {
	clearLicenseEnv(t)
	if got := licensePolicyURLFromEnv(); got != "" {
		t.Fatalf("expected gate disabled with no env, got %q", got)
	}

	clearLicenseEnv(t)
	t.Setenv("NCM_LICENSE_POLICY_URL", "http://example/api/settings/runtime-policy")
	t.Setenv("BACKEND_HOST", "ignored")
	if got := licensePolicyURLFromEnv(); got != "http://example/api/settings/runtime-policy" {
		t.Fatalf("explicit URL not honoured: %q", got)
	}

	clearLicenseEnv(t)
	t.Setenv("BACKEND_HOST", "localhost")
	t.Setenv("BACKEND_PORT", "8000")
	if got := licensePolicyURLFromEnv(); got != "http://localhost:8000/api/settings/runtime-policy" {
		t.Fatalf("derived URL wrong: %q", got)
	}

	clearLicenseEnv(t)
	t.Setenv("BACKEND_HOST", "back")
	if got := licensePolicyURLFromEnv(); got != "http://back:8000/api/settings/runtime-policy" {
		t.Fatalf("default port not applied: %q", got)
	}
}

func TestLicensePollIntervalFromEnv(t *testing.T) {
	clearLicenseEnv(t)
	if got := licensePollIntervalFromEnv(); got != defaultLicensePollInterval {
		t.Fatalf("expected default, got %v", got)
	}
	t.Setenv("NCM_LICENSE_POLL_INTERVAL_SECONDS", "12")
	if got := licensePollIntervalFromEnv(); got != 12*time.Second {
		t.Fatalf("expected 12s, got %v", got)
	}
	t.Setenv("NCM_LICENSE_POLL_INTERVAL_SECONDS", "bogus")
	if got := licensePollIntervalFromEnv(); got != defaultLicensePollInterval {
		t.Fatalf("expected default on bad value, got %v", got)
	}
}

func TestLicenseGateDisabledAlwaysAllows(t *testing.T) {
	clearLicenseEnv(t)
	g := newLicenseGate()
	if g.enabled() {
		t.Fatal("expected gate disabled with no env")
	}
	if !g.allow() {
		t.Fatal("disabled gate must always allow")
	}
}

func TestLicenseGateRefresh(t *testing.T) {
	var body string
	var status int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	g := &licenseGate{url: srv.URL, interval: time.Second, client: srv.Client()}
	g.allowed.Store(true)

	// A valid, blocked (0-license) policy blocks pairing.
	status = http.StatusOK
	body = `{"pairing":{"enabled":true,"blocked":true,"reason":"no-capacity"},"license":"licensed"}`
	g.refresh(context.Background())
	if g.allow() {
		t.Fatal("expected blocked after a valid no-capacity policy")
	}

	// A valid, licensed policy restores pairing.
	body = `{"pairing":{"enabled":true,"blocked":false,"reason":"none"},"license":"licensed"}`
	g.refresh(context.Background())
	if !g.allow() {
		t.Fatal("expected allowed after a valid licensed policy")
	}

	// A reachable-but-wrong endpoint (unrelated 200 JSON -> empty License) must
	// NOT flip the decision; keep the last known good (allowed).
	body = `{"unexpected":"payload"}`
	g.refresh(context.Background())
	if !g.allow() {
		t.Fatal("expected last decision retained for a schema-invalid 200 response")
	}

	// A non-200 keeps the last decision too.
	status = http.StatusInternalServerError
	body = ``
	g.refresh(context.Background())
	if !g.allow() {
		t.Fatal("expected last decision retained for a non-200 response")
	}
}
