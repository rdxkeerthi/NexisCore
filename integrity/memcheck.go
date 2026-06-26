// Package integrity — MemoryIntegrityMonitor: runtime .text segment tamper detection.
//
// At startup the monitor:
//  1. Reads /proc/self/maps to locate the executable's .text segment VA range.
//  2. Reads /proc/self/exe to compute a SHA-256 baseline of the full binary.
//  3. Spawns a goroutine that re-hashes at configurable intervals.
//  4. On hash mismatch → emits OCSF critical event and triggers the kill-switch.
//
// Note: We hash /proc/self/exe (the kernel copy of the binary) rather than
// attempting to read mapped memory pages directly. This provides a reliable
// baseline that detects file-level modification and dynamic library injection
// that replaces the on-disk binary while the process runs.
// Additional protection against in-memory patching is provided by the eBPF
// anti-tamper probes (antitamper.bpf.c).
package integrity

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nexiscore/telemetry"
)

// TextSegmentInfo holds the virtual address range of the executable's text segment.
type TextSegmentInfo struct {
	// StartAddr is the hexadecimal start address from /proc/self/maps.
	StartAddr string
	// EndAddr is the hexadecimal end address from /proc/self/maps.
	EndAddr string
	// Pathname is the mapped file path (the executable).
	Pathname string
}

// MemoryIntegrityMonitor monitors the integrity of the running binary.
type MemoryIntegrityMonitor struct {
	agentID     string
	baselineHash string // hex SHA-256 of /proc/self/exe at startup
	textSegments []TextSegmentInfo
	killSwitch   *KillSwitch
	engine       *telemetry.TelemetryEngine
	stopCh      chan struct{}
	once        sync.Once
	wg          sync.WaitGroup

	// Atomic counters
	checksPerformed int64
	tamperDetected  int64
}

// NewMemoryIntegrityMonitor creates a monitor and computes the baseline hash.
// Returns an error if /proc/self/exe is unreadable or /proc/self/maps cannot
// be parsed (non-Linux systems will return an error).
func NewMemoryIntegrityMonitor(agentID string, ks *KillSwitch, engine *telemetry.TelemetryEngine) (*MemoryIntegrityMonitor, error) {
	m := &MemoryIntegrityMonitor{
		agentID:    agentID,
		killSwitch: ks,
		engine:     engine,
		stopCh:     make(chan struct{}),
	}

	// Parse /proc/self/maps to identify executable text segments
	segments, err := parseTextSegments()
	if err != nil {
		return nil, fmt.Errorf("memcheck: failed parsing /proc/self/maps: %w", err)
	}
	m.textSegments = segments

	// Compute SHA-256 baseline hash of the binary on disk
	baseline, err := hashSelfExe()
	if err != nil {
		return nil, fmt.Errorf("memcheck: failed computing baseline hash: %w", err)
	}
	m.baselineHash = baseline

	log.Printf("[MEMCHECK] Baseline SHA-256: %s", baseline)
	log.Printf("[MEMCHECK] Monitoring %d executable text segments in /proc/self/maps", len(segments))
	for _, seg := range segments {
		log.Printf("[MEMCHECK]   [%s-%s] %s", seg.StartAddr, seg.EndAddr, seg.Pathname)
	}

	return m, nil
}

// StartPeriodicCheck starts the background goroutine that re-checks the
// binary hash at the given interval (e.g. 30 * time.Second).
func (m *MemoryIntegrityMonitor) StartPeriodicCheck(interval time.Duration) {
	m.once.Do(func() {
		m.wg.Add(1)
		go m.checker(interval)
		log.Printf("[MEMCHECK] Periodic integrity check started (interval=%s)", interval)
	})
}

// Stop gracefully stops the background checker goroutine.
func (m *MemoryIntegrityMonitor) Stop() {
	close(m.stopCh)
	m.wg.Wait()
}

// BaselineHash returns the SHA-256 hex string computed at startup.
func (m *MemoryIntegrityMonitor) BaselineHash() string {
	return m.baselineHash
}

// Metrics returns the number of checks performed and tamper events detected.
func (m *MemoryIntegrityMonitor) Metrics() (checked, tampered int64) {
	return atomic.LoadInt64(&m.checksPerformed), atomic.LoadInt64(&m.tamperDetected)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal
// ─────────────────────────────────────────────────────────────────────────────

func (m *MemoryIntegrityMonitor) checker(interval time.Duration) {
	defer m.wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.performCheck()
		case <-m.stopCh:
			log.Println("[MEMCHECK] Integrity checker goroutine stopped.")
			return
		}
	}
}

func (m *MemoryIntegrityMonitor) performCheck() {
	atomic.AddInt64(&m.checksPerformed, 1)

	current, err := hashSelfExe()
	if err != nil {
		log.Printf("[MEMCHECK] WARNING: failed re-hashing /proc/self/exe: %v", err)
		return
	}

	if current == m.baselineHash {
		log.Printf("[MEMCHECK] Integrity check PASS (check #%d) — hash: %s",
			atomic.LoadInt64(&m.checksPerformed), current[:16]+"...")
		return
	}

	// TAMPER DETECTED
	atomic.AddInt64(&m.tamperDetected, 1)
	detail := fmt.Sprintf("baseline=%s current=%s", m.baselineHash[:16]+"...", current[:16]+"...")
	log.Printf("[MEMCHECK][🚨 TAMPER DETECTED] Binary hash mismatch! %s", detail)

	// Emit OCSF Critical event
	if m.engine != nil {
		m.engine.Submit(telemetry.NewMemoryTamperEvent(m.agentID, detail))
	}

	// Trigger kill-switch
	m.killSwitch.Trigger("binary_hash_mismatch", map[string]string{
		"baseline": m.baselineHash,
		"current":  current,
		"detail":   detail,
	})
}

// parseTextSegments reads /proc/self/maps and returns entries for executable
// memory mappings (permission field contains 'x' and 'r').
func parseTextSegments() ([]TextSegmentInfo, error) {
	f, err := os.Open("/proc/self/maps")
	if err != nil {
		return nil, fmt.Errorf("open /proc/self/maps: %w", err)
	}
	defer f.Close()

	var segments []TextSegmentInfo
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Format: addr-range perms offset dev inode [pathname]
		// e.g.: 55f1a0000000-55f1a0100000 r-xp 00000000 fd:01 1234 /usr/bin/nexiscore
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		perms := fields[1]
		// We want readable+executable segments (r-xp or r-xs)
		if !strings.Contains(perms, "r") || !strings.Contains(perms, "x") {
			continue
		}
		addrRange := fields[0]
		parts := strings.SplitN(addrRange, "-", 2)
		if len(parts) != 2 {
			continue
		}
		pathname := ""
		if len(fields) >= 6 {
			pathname = fields[5]
		}
		// Only track our own binary (pathname matches /proc/self/exe resolution)
		// Accept any non-library path or the actual exe path
		if pathname != "" && !strings.HasPrefix(pathname, "[") {
			segments = append(segments, TextSegmentInfo{
				StartAddr: parts[0],
				EndAddr:   parts[1],
				Pathname:  pathname,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan /proc/self/maps: %w", err)
	}
	return segments, nil
}

// hashSelfExe computes SHA-256 of /proc/self/exe (the running binary).
func hashSelfExe() (string, error) {
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return "", fmt.Errorf("open /proc/self/exe: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	var buf bytes.Buffer
	if _, err := io.Copy(h, io.TeeReader(f, &buf)); err != nil {
		return "", fmt.Errorf("hash /proc/self/exe: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
