package ncm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// The license gate lets an embedding system (ironport) stop go-ncm from bringing
// up the iPhone's USB-NCM interface when there are 0 available licenses. Without
// that interface the phone gets no USB networking and therefore cannot pair /
// have its trust collected. The gate is opt-in: unless a policy URL is provided
// (directly or derived from BACKEND_HOST) go-ncm behaves exactly like the stock
// go-ios tool and never blocks.

const (
	defaultLicensePollInterval  = 5 * time.Second
	licensePolicyRequestTimeout = 4 * time.Second
	licenseRuntimePolicyPath    = "/api/settings/runtime-policy"
)

// runtimePolicy mirrors the subset of the ironport backend's
// GET /api/settings/runtime-policy response that decides pairing.
type runtimePolicy struct {
	Pairing struct {
		Enabled bool   `json:"enabled"`
		Blocked bool   `json:"blocked"`
		Reason  string `json:"reason"`
	} `json:"pairing"`
	License string `json:"license"`
}

// allowsPairing mirrors common/go/domain.RuntimePolicy.AllowsPairing: pairing is
// permitted only when it is enabled, not blocked (e.g. reason "no-capacity"), and
// the system is licensed.
func (p runtimePolicy) allowsPairing() bool {
	return p.Pairing.Enabled && !p.Pairing.Blocked && p.License == "licensed"
}

type licenseGate struct {
	url      string
	interval time.Duration
	client   *http.Client
	allowed  atomic.Bool
}

// newLicenseGate builds the pairing-license gate from the environment.
func newLicenseGate() *licenseGate {
	g := &licenseGate{
		url:      licensePolicyURLFromEnv(),
		interval: licensePollIntervalFromEnv(),
		client:   &http.Client{Timeout: licensePolicyRequestTimeout},
	}
	// Default to allowed so a not-yet-ready backend never bricks USB networking
	// at startup; the first successful poll installs the real decision.
	g.allowed.Store(true)
	return g
}

func (g *licenseGate) enabled() bool { return g != nil && g.url != "" }

// allow reports whether NCM bring-up is currently permitted. A disabled gate
// always allows (stock go-ios behaviour).
func (g *licenseGate) allow() bool {
	if !g.enabled() {
		return true
	}
	return g.allowed.Load()
}

// run polls the runtime policy until ctx is cancelled, updating the decision on
// each successful fetch and retaining the last known decision across transient
// errors. Newly-attached phones observe the latest decision on the next poll.
func (g *licenseGate) run(ctx context.Context) {
	if !g.enabled() {
		slog.Info("license gate disabled; go-ncm will not block pairing (set NCM_LICENSE_POLICY_URL or BACKEND_HOST to enable)")
		return
	}
	slog.Info("license gate enabled", "url", g.url, "interval", g.interval.String())
	g.refresh(ctx)
	ticker := time.NewTicker(g.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.refresh(ctx)
		}
	}
}

func (g *licenseGate) refresh(ctx context.Context) {
	policy, err := g.fetch(ctx)
	if err != nil {
		slog.Warn("license gate: policy fetch failed; keeping last decision", "err", err, "allowed", g.allowed.Load())
		return
	}
	// Only trust a schema-valid policy. A reachable-but-wrong endpoint returning
	// unrelated JSON decodes to a zero-value policy (License==""); acting on that
	// would block all pairing, so keep the last known decision instead.
	if policy.License == "" {
		slog.Warn("license gate: policy missing license state; keeping last decision", "allowed", g.allowed.Load())
		return
	}
	allowed := policy.allowsPairing()
	if g.allowed.Swap(allowed) != allowed {
		slog.Info("license gate: pairing decision changed", "allowed", allowed, "reason", policy.Pairing.Reason, "license", policy.License)
	}
}

func (g *licenseGate) fetch(ctx context.Context) (runtimePolicy, error) {
	reqCtx, cancel := context.WithTimeout(ctx, licensePolicyRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, g.url, nil)
	if err != nil {
		return runtimePolicy{}, err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return runtimePolicy{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return runtimePolicy{}, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	var policy runtimePolicy
	if err := json.NewDecoder(resp.Body).Decode(&policy); err != nil {
		return runtimePolicy{}, err
	}
	return policy, nil
}

// licensePolicyURLFromEnv returns the runtime-policy URL to poll, or "" to keep
// the gate disabled. NCM_LICENSE_POLICY_URL takes precedence; otherwise it is
// derived from BACKEND_HOST/BACKEND_PORT (the convention used across ironport).
func licensePolicyURLFromEnv() string {
	if url := strings.TrimSpace(os.Getenv("NCM_LICENSE_POLICY_URL")); url != "" {
		return url
	}
	host := strings.TrimSpace(os.Getenv("BACKEND_HOST"))
	if host == "" {
		return ""
	}
	port := strings.TrimSpace(os.Getenv("BACKEND_PORT"))
	if port == "" {
		port = "8000"
	}
	return fmt.Sprintf("http://%s:%s%s", host, port, licenseRuntimePolicyPath)
}

func licensePollIntervalFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv("NCM_LICENSE_POLL_INTERVAL_SECONDS"))
	if raw == "" {
		return defaultLicensePollInterval
	}
	if n, err := strconv.Atoi(raw); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return defaultLicensePollInterval
}
