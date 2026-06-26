// Package integrity — KillSwitch: centralized kill-switch protocol for NexisCore.
//
// When any tampering is detected, Trigger() is called exactly once:
//  1. Emits an OCSF Security Finding (Critical) via the telemetry engine.
//  2. Flushes a synchronous stderr log.
//  3. Terminates the process with exit code 137 (SIGKILL convention).
//
// The kill-switch is a singleton — it fires at most once per process lifetime,
// preventing any race condition from triggering double-shutdown.
package integrity

import (
	"fmt"
	"log"
	"os"
	"sync"

	"nexiscore/telemetry"
)

// KillSwitch is the process-level termination authority. Activated at most once.
type KillSwitch struct {
	once      sync.Once
	agentID   string
	engine    *telemetry.TelemetryEngine
	triggered chan struct{}
}

var (
	globalKS   *KillSwitch
	globalKSMu sync.RWMutex
)

// NewKillSwitch creates a new KillSwitch. agentID identifies the process in
// OCSF events. engine may be nil (events will fall back to stderr).
func NewKillSwitch(agentID string, engine *telemetry.TelemetryEngine) *KillSwitch {
	return &KillSwitch{
		agentID:   agentID,
		engine:    engine,
		triggered: make(chan struct{}),
	}
}

// RegisterGlobal installs ks as the process-global kill-switch. Modules that
// don't hold a direct reference use TriggerGlobal().
func RegisterGlobal(ks *KillSwitch) {
	globalKSMu.Lock()
	defer globalKSMu.Unlock()
	globalKS = ks
}

// TriggerGlobal calls Trigger on the globally registered kill-switch.
// If none is registered, it falls back to a direct os.Exit(137).
func TriggerGlobal(reason string, context map[string]string) {
	globalKSMu.RLock()
	ks := globalKS
	globalKSMu.RUnlock()
	if ks != nil {
		ks.Trigger(reason, context)
		return
	}
	// Emergency fallback
	log.Fatalf("[KILLSWITCH][EMERGENCY] No global kill-switch registered. Terminating. Reason: %s", reason)
}

// Trigger fires the kill-switch exactly once, regardless of how many goroutines
// call it concurrently. It is safe to call from any goroutine.
func (ks *KillSwitch) Trigger(reason string, context map[string]string) {
	ks.once.Do(func() {
		close(ks.triggered) // signal all waiters

		// Format a clear, structured kill message to stderr
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "╔══════════════════════════════════════════════════════════════╗\n")
		fmt.Fprintf(os.Stderr, "║  NEXISCORE KILL-SWITCH TRIGGERED                             ║\n")
		fmt.Fprintf(os.Stderr, "╠══════════════════════════════════════════════════════════════╣\n")
		fmt.Fprintf(os.Stderr, "║  Reason  : %-52s║\n", reason)
		fmt.Fprintf(os.Stderr, "║  AgentID : %-52s║\n", ks.agentID)
		for k, v := range context {
			fmt.Fprintf(os.Stderr, "║  %-8s: %-52s║\n", k, v)
		}
		fmt.Fprintf(os.Stderr, "╚══════════════════════════════════════════════════════════════╝\n")
		fmt.Fprintf(os.Stderr, "\n")

		// Emit OCSF Critical Security Finding
		event := telemetry.NewKillSwitchEvent(ks.agentID, reason, context)
		if ks.engine != nil {
			// Synchronous submission — we need this event out before we exit
			ks.engine.Submit(event)
			// Give the engine a brief moment to write the event to the local log
			// before we call os.Exit. Workers run in goroutines so we flush manually.
			ks.engine.Shutdown()
		} else {
			telemetry.SubmitGlobal(event)
		}

		log.Printf("[KILLSWITCH] Terminating process. Exit code 137.")
		os.Exit(137)
	})
}

// Triggered returns a channel that is closed when the kill-switch fires.
// Useful for select-based shutdown coordination.
func (ks *KillSwitch) Triggered() <-chan struct{} {
	return ks.triggered
}

// HasTriggered returns true if the kill-switch has already fired.
func (ks *KillSwitch) HasTriggered() bool {
	select {
	case <-ks.triggered:
		return true
	default:
		return false
	}
}
