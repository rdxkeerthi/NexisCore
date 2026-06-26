// Package telemetry — SIEMForwarder: Splunk HTTP Event Collector (HEC) client.
//
// Architecture:
//   - Internal batch buffer protected by sync.Mutex.
//   - Background goroutine flushes on interval OR when BatchSize is reached.
//   - HTTP POST to <EndpointURL>/services/collector/event over TLS.
//   - Retries transient failures with exponential backoff (max 3 attempts).
//   - Dead-letters undeliverable batches to a local fallback file.
package telemetry

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// SIEMConfig holds configuration for the Splunk HEC forwarder.
type SIEMConfig struct {
	// EndpointURL is the full Splunk HEC base URL, e.g. "https://splunk.corp.local:8088".
	// Read from env NEXISCORE_SIEM_URL if empty.
	EndpointURL string
	// Token is the Splunk HEC authentication token.
	// Read from env NEXISCORE_SIEM_TOKEN if empty.
	Token string
	// TLSSkipVerify disables TLS certificate verification (dev/test only).
	TLSSkipVerify bool
	// BatchSize is the maximum events per HTTP POST. Default: 50.
	BatchSize int
	// FlushInterval is how often the background goroutine flushes. Default: 2s.
	FlushInterval time.Duration
	// MaxRetries is the number of retry attempts for transient HTTP failures. Default: 3.
	MaxRetries int
	// DeadLetterPath is the path to write undeliverable batches. Default: "siem_deadletter.jsonl".
	DeadLetterPath string
	// Index is the Splunk index name to target. Optional.
	Index string
	// Sourcetype is the Splunk sourcetype. Default: "nexiscore:ocsf".
	Sourcetype string
}

// DefaultSIEMConfig returns a sensible default SIEM config. Environment
// variables NEXISCORE_SIEM_URL and NEXISCORE_SIEM_TOKEN override the fields.
func DefaultSIEMConfig() SIEMConfig {
	url := os.Getenv("NEXISCORE_SIEM_URL")
	token := os.Getenv("NEXISCORE_SIEM_TOKEN")
	return SIEMConfig{
		EndpointURL:    url,
		Token:          token,
		TLSSkipVerify:  false,
		BatchSize:      50,
		FlushInterval:  2 * time.Second,
		MaxRetries:     3,
		DeadLetterPath: "siem_deadletter.jsonl",
		Sourcetype:     "nexiscore:ocsf",
	}
}

// splunkHECEvent wraps an OCSF event in the Splunk HEC envelope format.
type splunkHECEvent struct {
	Time       float64     `json:"time"`
	Host       string      `json:"host,omitempty"`
	Source     string      `json:"source,omitempty"`
	Sourcetype string      `json:"sourcetype,omitempty"`
	Index      string      `json:"index,omitempty"`
	Event      interface{} `json:"event"`
}

// SIEMForwarder batches OCSF events and forwards them to a Splunk HEC endpoint.
// It is safe for concurrent use.
type SIEMForwarder struct {
	cfg        SIEMConfig
	client     *http.Client
	batch      []OCSFEvent
	mu         sync.Mutex
	stopCh     chan struct{}
	wg         sync.WaitGroup
	hostname   string

	// Atomic metrics
	flushed   int64 // total events successfully sent to SIEM
	failed    int64 // total events dead-lettered
	deadletter *os.File
	dlMu       sync.Mutex
}

// NewSIEMForwarder creates and starts a SIEMForwarder. Returns nil (not an error)
// if no endpoint URL is configured — the engine will operate in local-log-only mode.
func NewSIEMForwarder(cfg SIEMConfig) (*SIEMForwarder, error) {
	// Resolve from env if not explicitly set
	if cfg.EndpointURL == "" {
		cfg.EndpointURL = os.Getenv("NEXISCORE_SIEM_URL")
	}
	if cfg.Token == "" {
		cfg.Token = os.Getenv("NEXISCORE_SIEM_TOKEN")
	}

	if cfg.EndpointURL == "" {
		log.Println("[SIEM] No SIEM endpoint configured (NEXISCORE_SIEM_URL not set). Running in local-log-only mode.")
		return nil, nil
	}

	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 2 * time.Second
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.DeadLetterPath == "" {
		cfg.DeadLetterPath = "siem_deadletter.jsonl"
	}
	if cfg.Sourcetype == "" {
		cfg.Sourcetype = "nexiscore:ocsf"
	}

	hostname, _ := os.Hostname()

	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.TLSSkipVerify, //nolint:gosec — controlled by explicit operator flag
		MinVersion:         tls.VersionTLS12,
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg}
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	// Open dead-letter file (append mode)
	dl, err := os.OpenFile(cfg.DeadLetterPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("siem: failed opening dead-letter file %q: %w", cfg.DeadLetterPath, err)
	}

	f := &SIEMForwarder{
		cfg:        cfg,
		client:     client,
		batch:      make([]OCSFEvent, 0, cfg.BatchSize),
		stopCh:     make(chan struct{}),
		hostname:   hostname,
		deadletter: dl,
	}

	// Start background flush goroutine
	f.wg.Add(1)
	go f.backgroundFlusher()

	log.Printf("[SIEM] Forwarder started → %s (batchSize=%d, interval=%s)",
		cfg.EndpointURL, cfg.BatchSize, cfg.FlushInterval)
	return f, nil
}

// Enqueue adds an event to the pending batch. If the batch reaches BatchSize,
// it is immediately flushed in the calling goroutine (workers call this).
func (f *SIEMForwarder) Enqueue(event OCSFEvent) {
	f.mu.Lock()
	f.batch = append(f.batch, event)
	shouldFlush := len(f.batch) >= f.cfg.BatchSize
	var toFlush []OCSFEvent
	if shouldFlush {
		toFlush = f.batch
		f.batch = make([]OCSFEvent, 0, f.cfg.BatchSize)
	}
	f.mu.Unlock()

	if shouldFlush {
		f.flush(toFlush)
	}
}

// Shutdown flushes any remaining events and releases resources.
func (f *SIEMForwarder) Shutdown() {
	close(f.stopCh)
	f.wg.Wait()

	// Final flush of any remaining events
	f.mu.Lock()
	remaining := f.batch
	f.batch = nil
	f.mu.Unlock()

	if len(remaining) > 0 {
		f.flush(remaining)
	}

	if f.deadletter != nil {
		f.dlMu.Lock()
		_ = f.deadletter.Sync()
		_ = f.deadletter.Close()
		f.dlMu.Unlock()
	}

	log.Printf("[SIEM] Forwarder shutdown. flushed=%d failed=%d",
		atomic.LoadInt64(&f.flushed), atomic.LoadInt64(&f.failed))
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal implementation
// ─────────────────────────────────────────────────────────────────────────────

func (f *SIEMForwarder) backgroundFlusher() {
	defer f.wg.Done()
	ticker := time.NewTicker(f.cfg.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			f.mu.Lock()
			if len(f.batch) == 0 {
				f.mu.Unlock()
				continue
			}
			toFlush := f.batch
			f.batch = make([]OCSFEvent, 0, f.cfg.BatchSize)
			f.mu.Unlock()
			f.flush(toFlush)
		case <-f.stopCh:
			return
		}
	}
}

// flush sends a batch of events to the Splunk HEC endpoint. Retries up to
// MaxRetries times with exponential back-off; dead-letters if all retries fail.
func (f *SIEMForwarder) flush(events []OCSFEvent) {
	if len(events) == 0 {
		return
	}

	body, err := f.buildHECBody(events)
	if err != nil {
		log.Printf("[SIEM] Failed building HEC payload: %v", err)
		f.deadLetter(events, fmt.Sprintf("marshal_error: %v", err))
		return
	}

	url := f.cfg.EndpointURL + "/services/collector/event"
	var lastErr error

	for attempt := 1; attempt <= f.cfg.MaxRetries; attempt++ {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			lastErr = err
			break
		}
		req.Header.Set("Authorization", "Splunk "+f.cfg.Token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-NexisCore-Batch-Size", fmt.Sprintf("%d", len(events)))

		resp, err := f.client.Do(req)
		if err != nil {
			lastErr = err
			backoff := time.Duration(attempt*attempt) * 500 * time.Millisecond
			log.Printf("[SIEM] Attempt %d/%d failed (network): %v — retrying in %s",
				attempt, f.cfg.MaxRetries, err, backoff)
			time.Sleep(backoff)
			continue
		}
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
			atomic.AddInt64(&f.flushed, int64(len(events)))
			log.Printf("[SIEM] Flushed %d events (HTTP %d)", len(events), resp.StatusCode)
			return
		}

		lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		// 4xx errors are not retriable
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			log.Printf("[SIEM] Non-retriable error %d for batch of %d events", resp.StatusCode, len(events))
			break
		}

		backoff := time.Duration(attempt*attempt) * 500 * time.Millisecond
		log.Printf("[SIEM] Attempt %d/%d: HTTP %d — retrying in %s",
			attempt, f.cfg.MaxRetries, resp.StatusCode, backoff)
		time.Sleep(backoff)
	}

	log.Printf("[SIEM] All retries exhausted for batch of %d events: %v", len(events), lastErr)
	f.deadLetter(events, fmt.Sprintf("retries_exhausted: %v", lastErr))
}

// buildHECBody serialises events as a sequence of JSON objects (Splunk raw HEC format).
func (f *SIEMForwarder) buildHECBody(events []OCSFEvent) ([]byte, error) {
	var buf bytes.Buffer
	for _, ev := range events {
		wrapper := splunkHECEvent{
			Time:       float64(ev.Time) / 1000.0, // HEC expects Unix seconds
			Host:       f.hostname,
			Source:     "nexiscore",
			Sourcetype: f.cfg.Sourcetype,
			Index:      f.cfg.Index,
			Event:      ev,
		}
		b, err := json.Marshal(wrapper)
		if err != nil {
			return nil, fmt.Errorf("failed marshalling event: %w", err)
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

// deadLetter writes undeliverable events to the dead-letter file for later replay.
func (f *SIEMForwarder) deadLetter(events []OCSFEvent, reason string) {
	atomic.AddInt64(&f.failed, int64(len(events)))
	if f.deadletter == nil {
		return
	}
	f.dlMu.Lock()
	defer f.dlMu.Unlock()
	for _, ev := range events {
		entry := map[string]interface{}{
			"dead_letter_reason": reason,
			"dead_letter_time":   time.Now().UTC().Format(time.RFC3339),
			"event":              ev,
		}
		b, _ := json.Marshal(entry)
		_, _ = f.deadletter.Write(b)
		_, _ = f.deadletter.Write([]byte("\n"))
	}
}
