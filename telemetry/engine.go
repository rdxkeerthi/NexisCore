// Package telemetry — TelemetryEngine: asynchronous worker-pool OCSF event dispatcher.
//
// Architecture:
//   - A single buffered channel (cap 8192) acts as the event queue.
//   - N goroutine workers drain the queue concurrently.
//   - Workers persist events to a local rotating log AND enqueue to the SIEM forwarder.
//   - Submit() is non-blocking; if the queue is full the event is counted as dropped.
//   - Shutdown() drains the queue with a configurable grace period before returning.
package telemetry

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// EngineConfig holds configuration for the TelemetryEngine.
type EngineConfig struct {
	// WorkerCount is the number of goroutines draining the event channel. Default: 4.
	WorkerCount int
	// ChannelBufferSize is the capacity of the internal event channel. Default: 8192.
	ChannelBufferSize int
	// LocalLogPath is the path to write OCSF events as JSON lines. "" disables local log.
	LocalLogPath string
	// ShutdownGrace is the time allowed to drain the queue on Shutdown(). Default: 5s.
	ShutdownGrace time.Duration
}

// DefaultEngineConfig returns a sensible production default configuration.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		WorkerCount:       4,
		ChannelBufferSize: 8192,
		LocalLogPath:      "nexiscore_ocsf.jsonl",
		ShutdownGrace:     5 * time.Second,
	}
}

// TelemetryEngine is the central asynchronous event dispatcher. It is safe for
// concurrent use by all modules simultaneously.
type TelemetryEngine struct {
	cfg      EngineConfig
	queue    chan OCSFEvent
	wg       sync.WaitGroup
	once     sync.Once
	stopCh   chan struct{}
	forwarder *SIEMForwarder // may be nil if no SIEM configured

	// Metrics — all accessed via sync/atomic
	submitted int64
	dropped   int64
	processed int64

	// local log file handle; nil if disabled
	logFile *os.File
	logMu   sync.Mutex
}

// NewTelemetryEngine constructs and starts the engine with the given config.
// If forwarder is nil, events are only written to the local log.
func NewTelemetryEngine(cfg EngineConfig, forwarder *SIEMForwarder) (*TelemetryEngine, error) {
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = 4
	}
	if cfg.ChannelBufferSize <= 0 {
		cfg.ChannelBufferSize = 8192
	}
	if cfg.ShutdownGrace <= 0 {
		cfg.ShutdownGrace = 5 * time.Second
	}

	e := &TelemetryEngine{
		cfg:       cfg,
		queue:     make(chan OCSFEvent, cfg.ChannelBufferSize),
		stopCh:    make(chan struct{}),
		forwarder: forwarder,
	}

	// Open local JSONL log file if configured
	if cfg.LocalLogPath != "" {
		f, err := os.OpenFile(cfg.LocalLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			return nil, fmt.Errorf("telemetry: failed opening local log %q: %w", cfg.LocalLogPath, err)
		}
		e.logFile = f
	}

	// Start worker pool
	for i := 0; i < cfg.WorkerCount; i++ {
		e.wg.Add(1)
		go e.worker(i)
	}

	log.Printf("[TELEMETRY] Engine started (%d workers, buffer=%d)", cfg.WorkerCount, cfg.ChannelBufferSize)
	return e, nil
}

// Submit enqueues an OCSFEvent for asynchronous processing. It is non-blocking:
// if the internal channel is full the event is counted as dropped and this
// function returns immediately without blocking the caller.
func (e *TelemetryEngine) Submit(event OCSFEvent) {
	atomic.AddInt64(&e.submitted, 1)
	select {
	case e.queue <- event:
	default:
		// Channel full — count drop, never block
		atomic.AddInt64(&e.dropped, 1)
		log.Printf("[TELEMETRY] WARNING: event queue full, dropped event action=%s agent=%s",
			event.Action, event.AgentID)
	}
}

// Shutdown gracefully drains the event queue. It signals workers to stop
// accepting new events, then waits up to ShutdownGrace for the queue to drain.
func (e *TelemetryEngine) Shutdown() {
	e.once.Do(func() {
		log.Println("[TELEMETRY] Initiating graceful shutdown...")
		close(e.stopCh)

		// Give workers time to drain remaining queued events
		done := make(chan struct{})
		go func() {
			e.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			log.Println("[TELEMETRY] Queue drained successfully.")
		case <-time.After(e.cfg.ShutdownGrace):
			remaining := len(e.queue)
			log.Printf("[TELEMETRY] Shutdown grace exceeded; %d events unprocessed.", remaining)
		}

		if e.logFile != nil {
			e.logMu.Lock()
			_ = e.logFile.Sync()
			_ = e.logFile.Close()
			e.logMu.Unlock()
		}

		// Shutdown SIEM forwarder if present
		if e.forwarder != nil {
			e.forwarder.Shutdown()
		}

		log.Printf("[TELEMETRY] Shutdown complete. submitted=%d processed=%d dropped=%d",
			atomic.LoadInt64(&e.submitted),
			atomic.LoadInt64(&e.processed),
			atomic.LoadInt64(&e.dropped),
		)
	})
}

// Metrics returns a snapshot of the engine's internal counters.
func (e *TelemetryEngine) Metrics() (submitted, processed, dropped int64) {
	return atomic.LoadInt64(&e.submitted),
		atomic.LoadInt64(&e.processed),
		atomic.LoadInt64(&e.dropped)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal worker
// ─────────────────────────────────────────────────────────────────────────────

func (e *TelemetryEngine) worker(id int) {
	defer e.wg.Done()
	for {
		select {
		case event, ok := <-e.queue:
			if !ok {
				return
			}
			e.process(event)
		case <-e.stopCh:
			// Drain any remaining events before exiting
			for {
				select {
				case event := <-e.queue:
					e.process(event)
				default:
					return
				}
			}
		}
	}
}

func (e *TelemetryEngine) process(event OCSFEvent) {
	atomic.AddInt64(&e.processed, 1)

	data, err := event.Marshal()
	if err != nil {
		log.Printf("[TELEMETRY] Failed marshalling OCSF event: %v", err)
		return
	}

	// 1. Write to local JSONL file
	if e.logFile != nil {
		e.logMu.Lock()
		_, _ = e.logFile.Write(data)
		_, _ = e.logFile.Write([]byte("\n"))
		e.logMu.Unlock()
	}

	// 2. Enqueue to SIEM forwarder (if configured)
	if e.forwarder != nil {
		e.forwarder.Enqueue(event)
	}

	// 3. Critical events always get an immediate stderr log line
	if event.SeverityID >= SeverityCritical {
		log.Printf("[TELEMETRY][CRITICAL] action=%s agent=%s detail=%s findingUID=%s",
			event.Action, event.AgentID, event.StatusDetail, event.FindingUID)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Global singleton accessor (optional convenience)
// ─────────────────────────────────────────────────────────────────────────────

var (
	globalEngine     *TelemetryEngine
	globalEngineOnce sync.Once
	globalEngineMu   sync.RWMutex
)

// SetGlobalEngine registers a global engine instance for modules that don't
// hold a direct reference. Safe for concurrent use.
func SetGlobalEngine(e *TelemetryEngine) {
	globalEngineMu.Lock()
	defer globalEngineMu.Unlock()
	globalEngine = e
}

// GlobalEngine returns the registered global engine, or nil.
func GlobalEngine() *TelemetryEngine {
	globalEngineMu.RLock()
	defer globalEngineMu.RUnlock()
	return globalEngine
}

// SubmitGlobal is a convenience wrapper that submits to the global engine if
// one is registered, otherwise marshals to stderr as a fallback.
func SubmitGlobal(event OCSFEvent) {
	e := GlobalEngine()
	if e != nil {
		e.Submit(event)
		return
	}
	// Fallback: write directly to stderr so no event is ever silently lost
	data, _ := json.Marshal(event)
	log.Printf("[TELEMETRY][FALLBACK] %s", string(data))
}
