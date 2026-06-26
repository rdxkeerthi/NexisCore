// Package egress — AllowlistRouter: domain and CIDR allowlist enforcement.
//
// Configuration is loaded from egress_policy.yaml. Hot-reload via polling
// every 15 seconds. IsAllowed() performs:
//  1. Exact domain match against the allowlist.
//  2. Suffix domain match (e.g. "openai.com" matches "api.openai.com").
//  3. IP range containment check against configured CIDR blocks.
package egress

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// EgressPolicy is the YAML schema for egress_policy.yaml.
type EgressPolicy struct {
	Version        string   `yaml:"version"`
	AllowedDomains []string `yaml:"allowed_domains"`
	AllowedCIDRs   []string `yaml:"allowed_cidrs"`
}

// DefaultEgressPolicyYAML is the embedded default egress policy written to
// disk on first run when no egress_policy.yaml exists.
const DefaultEgressPolicyYAML = `version: "1"
# NexisCore Egress Allowlist Policy
# Only domains and CIDR ranges listed here may receive outbound traffic.
allowed_domains:
  - "api.openai.com"
  - "api.anthropic.com"
  - "generativelanguage.googleapis.com"
  - "openai.azure.com"
  - "api.cohere.ai"
  - "api.mistral.ai"
allowed_cidrs:
  - "127.0.0.0/8"
  - "::1/128"
`

// AllowlistRouter enforces the egress policy for all outbound connections.
type AllowlistRouter struct {
	policyPath   string
	mu           sync.RWMutex
	domains      []string   // lowercased allowed domain entries
	cidrs        []*net.IPNet
	lastModTime  time.Time
	pollInterval time.Duration
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

// NewAllowlistRouter creates and starts a router from the given policy file.
func NewAllowlistRouter(policyPath string) (*AllowlistRouter, error) {
	r := &AllowlistRouter{
		policyPath:   policyPath,
		pollInterval: 15 * time.Second,
		stopCh:       make(chan struct{}),
	}
	if err := r.load(); err != nil {
		return nil, err
	}
	r.wg.Add(1)
	go r.poller()
	log.Printf("[EGRESS] AllowlistRouter started from %q (%d domains, %d CIDRs)",
		policyPath, len(r.domains), len(r.cidrs))
	return r, nil
}

// IsAllowed returns true if the given host (hostname or IP string) is permitted
// by the current egress policy. It checks both domain suffix matching and
// CIDR containment for raw IP addresses.
func (r *AllowlistRouter) IsAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	// Strip port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	r.mu.RLock()
	domains := r.domains
	cidrs := r.cidrs
	r.mu.RUnlock()

	// Try resolving as IP address first
	ip := net.ParseIP(host)
	if ip != nil {
		// Explicit IP — check CIDRs only
		for _, cidr := range cidrs {
			if cidr.Contains(ip) {
				return true
			}
		}
		return false
	}

	// Domain suffix matching
	for _, allowed := range domains {
		// Exact match
		if host == allowed {
			return true
		}
		// Suffix match: "openai.com" permits "api.openai.com"
		if strings.HasSuffix(host, "."+allowed) {
			return true
		}
	}

	// Try resolving the hostname to IPs and check CIDRs
	resolvedIPs, err := net.LookupIP(host)
	if err == nil {
		for _, ip := range resolvedIPs {
			for _, cidr := range cidrs {
				if cidr.Contains(ip) {
					return true
				}
			}
		}
	}

	return false
}

// Shutdown stops the background policy poller.
func (r *AllowlistRouter) Shutdown() {
	close(r.stopCh)
	r.wg.Wait()
}

// AllowedDomains returns a snapshot of currently allowed domains.
func (r *AllowlistRouter) AllowedDomains() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, len(r.domains))
	copy(out, r.domains)
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

func (r *AllowlistRouter) load() error {
	var rawYAML []byte

	info, statErr := os.Stat(r.policyPath)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			log.Printf("[EGRESS] %q not found; applying embedded default egress policy", r.policyPath)
			rawYAML = []byte(DefaultEgressPolicyYAML)
			_ = os.WriteFile(r.policyPath, rawYAML, 0640)
		} else {
			return fmt.Errorf("egress: stat %q: %w", r.policyPath, statErr)
		}
	} else {
		r.mu.RLock()
		unchanged := !info.ModTime().After(r.lastModTime)
		r.mu.RUnlock()
		if unchanged {
			return nil
		}
		var err error
		rawYAML, err = os.ReadFile(r.policyPath)
		if err != nil {
			return fmt.Errorf("egress: read %q: %w", r.policyPath, err)
		}
		r.mu.Lock()
		r.lastModTime = info.ModTime()
		r.mu.Unlock()
	}

	var policy EgressPolicy
	if err := yaml.Unmarshal(rawYAML, &policy); err != nil {
		return fmt.Errorf("egress: YAML parse error: %w", err)
	}

	// Normalise domains to lowercase
	domains := make([]string, 0, len(policy.AllowedDomains))
	for _, d := range policy.AllowedDomains {
		domains = append(domains, strings.ToLower(strings.TrimSpace(d)))
	}

	// Parse CIDR blocks
	cidrs := make([]*net.IPNet, 0, len(policy.AllowedCIDRs))
	for _, cidrStr := range policy.AllowedCIDRs {
		_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidrStr))
		if err != nil {
			log.Printf("[EGRESS] WARNING: invalid CIDR %q: %v", cidrStr, err)
			continue
		}
		cidrs = append(cidrs, ipNet)
	}

	r.mu.Lock()
	r.domains = domains
	r.cidrs = cidrs
	r.mu.Unlock()

	log.Printf("[EGRESS] Allowlist reloaded: %d domains, %d CIDRs", len(domains), len(cidrs))
	return nil
}

func (r *AllowlistRouter) poller() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := r.load(); err != nil {
				log.Printf("[EGRESS] Allowlist reload error: %v", err)
			}
		case <-r.stopCh:
			return
		}
	}
}
