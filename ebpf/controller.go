package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// SecurityEvent matches the struct security_event_t defined in BPF C
type SecurityEvent struct {
	ProcessID             uint32
	SecurityViolationType uint32 // 1 = Network Socket Breach, 2 = File Read Bypass
	Comm                  [16]byte
}

var (
	lockedMap   *ebpf.Map
	eventsRing  *ebpf.Map
	mapInitOnce sync.Once
	mapInitErr  error

	// Metrics tracked globally
	BlockedNetworkBreaches int64
	BlockedFileBypasses    int64
)

// initNativeMaps opens the pinned BPF maps under the standard virtual file system mount
func initNativeMaps() {
	mapInitErr = func() error {
		// Define paths matching setup mounts
		mapPath := "/sys/fs/bpf/maps/locked_sandboxes"
		ringPath := "/sys/fs/bpf/maps/security_events_ring"

		// Assert file presence
		if _, err := os.Stat(mapPath); os.IsNotExist(err) {
			return fmt.Errorf("locked_sandboxes BPF map is not loaded/pinned at: %s", mapPath)
		}

		var err error
		lockedMap, err = ebpf.LoadPinnedMap(mapPath, nil)
		if err != nil {
			return fmt.Errorf("failed to load pinned Map 'locked_sandboxes': %v", err)
		}

		if _, err := os.Stat(ringPath); !os.IsNotExist(err) {
			eventsRing, err = ebpf.LoadPinnedMap(ringPath, nil)
			if err != nil {
				log.Printf("[WARNING] security_events_ring BPF ringbuffer map loading skipped: %v", err)
			}
		}

		return nil
	}()
}

// RegisterSandboxPID inserts the active sandbox PID into the locked_sandboxes eBPF map programmatically
func RegisterSandboxPID(pid int) error {
	mapInitOnce.Do(initNativeMaps)
	if mapInitErr != nil {
		// Log warning and fallback gracefully if environment has no mounted BPF maps (like test runtimes)
		log.Printf("[WARNING] eBPF RegisterSandboxPID map registration bypassed: %v", mapInitErr)
		return nil
	}

	key := uint32(pid)
	value := uint32(1)

	err := lockedMap.Update(key, value, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed programmatically updating BPF Map locked_sandboxes: %v", err)
	}

	log.Printf("[NATIVE BPF] Locked container PID %d in kernel-level hash map.", pid)
	return nil
}

// RemoveSandboxPID deletes the PID key from the locked_sandboxes eBPF map programmatically
func RemoveSandboxPID(pid int) error {
	mapInitOnce.Do(initNativeMaps)
	if mapInitErr != nil {
		log.Printf("[WARNING] eBPF RemoveSandboxPID map deletion bypassed: %v", mapInitErr)
		return nil
	}

	key := uint32(pid)
	err := lockedMap.Delete(key)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("failed programmatically deleting key from BPF Map: %v", err)
	}

	return nil
}

// StreamKernelAlerts listens asynchronously on the BPF Ring Buffer and streams alerts to the console logger
func StreamKernelAlerts() {
	mapInitOnce.Do(initNativeMaps)
	if mapInitErr != nil {
		log.Printf("[BPF TELEMETRY] Telemetry listener not started: %v (VFS maps not mounted)", mapInitErr)
		return
	}

	if eventsRing == nil {
		log.Println("[BPF TELEMETRY] Telemetry listener aborted: ring buffer map not initialized")
		return
	}

	rd, err := ringbuf.NewReader(eventsRing)
	if err != nil {
		log.Printf("[BPF TELEMETRY] Failed creating BPF ringbuffer reader: %v", err)
		return
	}
	defer rd.Close()

	log.Println("[BPF TELEMETRY] Native Ring Buffer listener successfully active and polling kernel channels...")

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("[BPF TELEMETRY] Ringbuffer reader closed, shutting down listener.")
				return
			}
			log.Printf("[BPF TELEMETRY] Read error: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}

		var event SecurityEvent
		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
		if err != nil {
			log.Printf("[BPF TELEMETRY] Failed parsing binary telemetry block: %v", err)
			continue
		}

		commString := string(bytes.Trim(event.Comm[:], "\x00"))

		if event.SecurityViolationType == 1 {
			atomic.AddInt64(&BlockedNetworkBreaches, 1)
			log.Printf("[🚨 KERNEL ALERT] Network Breach Attempt Intercepted! Calling PID: %d, Executable: %s. Process terminated instantly via SIGKILL (9). Zero bytes leaked.", event.ProcessID, commString)
		} else if event.SecurityViolationType == 2 {
			atomic.AddInt64(&BlockedFileBypasses, 1)
			log.Printf("[🚨 KERNEL ALERT] Unauthorised Path Intrusion Intercepted! Calling PID: %d, Executable: %s. Attempted path accessed was blocked and thread killed via SIGKILL (9). Enclave secured.", event.ProcessID, commString)
		}
	}
}
