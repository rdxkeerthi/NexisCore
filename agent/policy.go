// Package agent — PolicyManager: YAML-based ACL loader for inter-agent routing.
//
// Policy file format (policy.yaml):
//
//	version: "1"
//	routes:
//	  - from: "spiffe://nexiscore.local/agent/supervisor"
//	    to:   "*"
//	    comment: "Supervisor may reach any agent"
//	  - from: "spiffe://nexiscore.local/agent/<uuid-a>"
//	    to:   "spiffe://nexiscore.local/agent/<uuid-b>"
//	    comment: "Agent A may send context to Agent B"
//
// Wildcard "*" in either field matches any SPIFFE ID.
// The policy is re-read from disk every 10 seconds (polling; no fsnotify dep).
package agent

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ─────────────────────────────────────────────────────────────────────────────
// Policy file schema
// ─────────────────────────────────────────────────────────────────────────────

// PolicyFile is the YAML schema for the inter-agent routing policy.
type PolicyFile struct {
	Version string        `yaml:"version"`
	Routes  []PolicyRoute `yaml:"routes"`
}

// PolicyRoute defines a single permitted unidirectional communication channel.
type PolicyRoute struct {
	// From is the SPIFFE ID of the initiating agent, or "*" for wildcard.
	From string `yaml:"from"`
	// To is the SPIFFE ID of the destination agent, or "*" for wildcard.
	To string `yaml:"to"`
	// Comment is an optional human-readable description.
	Comment string `yaml:"comment,omitempty"`
}

// DefaultPolicyYAML is embedded as the in-memory fallback when no policy.yaml
// exists on disk. It allows no lateral movement by default.
const DefaultPolicyYAML = `version: "1"
# NexisCore Inter-Agent ACL Policy
# Modify to grant specific agent-to-agent communication channels.
routes:
  # Supervisor agent (well-known SPIFFE ID) may reach any agent
  - from: "spiffe://nexiscore.local/agent/supervisor"
    to:   "*"
    comment: "Supervisor has unrestricted routing authority"
  # System introspection agent may broadcast to all
  - from: "spiffe://nexiscore.local/agent/introspection"
    to:   "*"
    comment: "Introspection agent may read any agent state"
  # Default: no lateral movement (all other agent-to-agent traffic DENIED)
`

// ─────────────────────────────────────────────────────────────────────────────
// PolicyManager
// ─────────────────────────────────────────────────────────────────────────────

// PolicyManager loads, caches, and hot-reloads the inter-agent routing ACL.
// It is safe for concurrent read access via IsRoutePermitted().
type PolicyManager struct {
	policyPath   string
	mu           sync.RWMutex
	routes       []PolicyRoute
	lastModTime  time.Time
	pollInterval time.Duration
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

// NewPolicyManager creates a PolicyManager and loads the policy from policyPath.
// If the file does not exist, the embedded DefaultPolicyYAML is used.
// Hot-reload polling begins immediately.
func NewPolicyManager(policyPath string) (*PolicyManager, error) {
	pm := &PolicyManager{
		policyPath:   policyPath,
		pollInterval: 10 * time.Second,
		stopCh:       make(chan struct{}),
	}

	if err := pm.load(); err != nil {
		return nil, err
	}

	pm.wg.Add(1)
	go pm.poller()

	log.Printf("[POLICY] PolicyManager initialized from %q (%d routes)", policyPath, len(pm.routes))
	return pm, nil
}

// IsRoutePermitted returns true if the fromSPIFFE → toSPIFFE route is
// explicitly allowed by the current policy. Wildcard "*" in either
// From or To field matches any SPIFFE ID.
func (pm *PolicyManager) IsRoutePermitted(fromSPIFFE, toSPIFFE string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for _, r := range pm.routes {
		fromMatch := r.From == "*" || r.From == fromSPIFFE
		toMatch := r.To == "*" || r.To == toSPIFFE
		if fromMatch && toMatch {
			return true
		}
	}
	return false
}

// Routes returns a snapshot of the currently loaded routes.
func (pm *PolicyManager) Routes() []PolicyRoute {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	out := make([]PolicyRoute, len(pm.routes))
	copy(out, pm.routes)
	return out
}

// Shutdown stops the background poller goroutine.
func (pm *PolicyManager) Shutdown() {
	close(pm.stopCh)
	pm.wg.Wait()
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

func (pm *PolicyManager) load() error {
	var rawYAML []byte

	info, err := os.Stat(pm.policyPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[POLICY] %q not found; applying embedded default policy", pm.policyPath)
			rawYAML = []byte(DefaultPolicyYAML)
			// Write the default to disk for operator visibility
			_ = os.WriteFile(pm.policyPath, rawYAML, 0640)
		} else {
			return fmt.Errorf("policy: stat %q failed: %w", pm.policyPath, err)
		}
	} else {
		// Check if file has changed since last load
		pm.mu.RLock()
		unchanged := !info.ModTime().After(pm.lastModTime)
		pm.mu.RUnlock()
		if unchanged {
			return nil // no change
		}
		rawYAML, err = os.ReadFile(pm.policyPath)
		if err != nil {
			return fmt.Errorf("policy: read %q failed: %w", pm.policyPath, err)
		}
		pm.mu.Lock()
		pm.lastModTime = info.ModTime()
		pm.mu.Unlock()
	}

	var policy PolicyFile
	if err := yaml.Unmarshal(rawYAML, &policy); err != nil {
		return fmt.Errorf("policy: YAML parse error in %q: %w", pm.policyPath, err)
	}

	if len(policy.Routes) == 0 {
		log.Printf("[POLICY] WARNING: policy loaded with 0 routes — all inter-agent comms will be denied")
	}

	pm.mu.Lock()
	pm.routes = policy.Routes
	pm.mu.Unlock()

	log.Printf("[POLICY] Loaded %d routes from %q", len(policy.Routes), pm.policyPath)
	return nil
}

func (pm *PolicyManager) poller() {
	defer pm.wg.Done()
	ticker := time.NewTicker(pm.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := pm.load(); err != nil {
				log.Printf("[POLICY] Hot-reload error: %v", err)
			}
		case <-pm.stopCh:
			return
		}
	}
}
