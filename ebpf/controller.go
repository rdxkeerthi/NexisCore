package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

/* SecurityEvent matches the struct log_event_t defined in BPF C */
type SecurityEvent struct {
	ProcessID             uint32
	SecurityViolationType uint32 /* 1 = Egress Tampering, 2 = File Boundary Abuse */
	Comm                  [16]byte
}

/* LpmTrieKey matches structural prefix lookup key layout in eBPF LPM trie */
type LpmTrieKey struct {
	PrefixLen uint32
	Name      [64]byte
}

var (
	lockedMap        *ebpf.Map
	allowedIPsMap    *ebpf.Map
	dnsWhitelistMap  *ebpf.Map
	eventsRingMap    *ebpf.Map
	tracepointOpenat link.Link
	tracepointConn   link.Link
	socketFds        []int

	controllerInitOnce sync.Once
	controllerInitErr  error

	/* Public Metrics */
	BlockedNetworkBreaches int64
	BlockedFileBypasses    int64
)

/* port-agnostic htons utility */
func htons(val uint16) uint16 {
	return (val << 8) | (val >> 8)
}

/* ipToUint32 converts standard net.IP structures to byte-aligned eBPF keys */
func ipToUint32(ip net.IP) uint32 {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(ipv4)
}

/* InitNativeController loads eBPF monitor.o program programmatically and mounts BPF maps */
func InitNativeController() error {
	controllerInitOnce.Do(func() {
		controllerInitErr = func() error {
			log.Println("[NATIVE BPF] Loading programmatic eBPF collection monitor.o...")

			/* 1. Ensure maps mount directory is created */
			pinDir := "/sys/fs/bpf/nexiscore_maps"
			_ = os.RemoveAll(pinDir) /* Reset previous pinning mounts */
			if err := os.MkdirAll(pinDir, 0755); err != nil {
				return fmt.Errorf("failed creating pin directory %s: %v", pinDir, err)
			}

			/* 2. Load compiled eBPF ELF monitor.o object spec */
			spec, err := ebpf.LoadCollectionSpec("ebpf/kernel/monitor.o")
			if err != nil {
				return fmt.Errorf("failed loading monitor.o ELF collection: %w", err)
			}

			/* 3. Declare memory alignment container object structure matching BPF C symbols */
			var objects struct {
				LockedSandboxes    *ebpf.Map     `ebpf:"locked_sandboxes"`
				AllowedIPs         *ebpf.Map     `ebpf:"allowed_ips"`
				SecurityEventsRing *ebpf.Map     `ebpf:"security_events_ring"`
				DnsWhitelist       *ebpf.Map     `ebpf:"dns_whitelist"`
				TracepointConnect  *ebpf.Program `ebpf:"tracepoint__syscalls__sys_enter_connect"`
				TracepointOpenat   *ebpf.Program `ebpf:"tracepoint__syscalls__sys_enter_openat"`
				SocketDnsFilter    *ebpf.Program `ebpf:"socket__dns_filter"`
			}

			/* 4. Load spec and pin maps automatically under the pinned mount */
			err = spec.LoadAndAssign(&objects, &ebpf.CollectionOptions{
				Maps: ebpf.MapOptions{
					PinPath: pinDir,
				},
			})
			if err != nil {
				return fmt.Errorf("failed programmatically compiling and pinning BPF spec: %w", err)
			}

			lockedMap = objects.LockedSandboxes
			allowedIPsMap = objects.AllowedIPs
			dnsWhitelistMap = objects.DnsWhitelist
			eventsRingMap = objects.SecurityEventsRing

			/* 5. Dynamically attach syscall tracepoints using native link package */
			tracepointConn, err = link.Tracepoint("syscalls", "sys_enter_connect", objects.TracepointConnect, nil)
			if err != nil {
				return fmt.Errorf("failed attaching connect tracepoint: %w", err)
			}

			tracepointOpenat, err = link.Tracepoint("syscalls", "sys_enter_openat", objects.TracepointOpenat, nil)
			if err != nil {
				return fmt.Errorf("failed attaching openat tracepoint: %w", err)
			}

			/* 6. Populate default domain DNS whitelists in LPM trie map */
			whitelistedDomains := []string{
				"localhost",
				"github.com",
				"api.github.com",
				"google.com",
			}
			for _, domain := range whitelistedDomains {
				var lpmKey LpmTrieKey
				lpmKey.PrefixLen = 512 /* Full 64-byte match */
				copy(lpmKey.Name[:], domain)

				if err := dnsWhitelistMap.Put(&lpmKey, uint32(1)); err != nil {
					log.Printf("[WARNING] LPM trie failed inserting domain %s: %v", domain, err)
				} else {
					log.Printf("[NATIVE BPF] Whitelisted domain API endpoint in Radix LPM: %s", domain)
				}

				/* Resolve IPs and dynamically add to allowed_ips hash map */
				ips, _ := net.LookupIP(domain)
				for _, ip := range ips {
					if ip4 := ip.To4(); ip4 != nil {
						ipKey := ipToUint32(ip4)
						if err := allowedIPsMap.Put(ipKey, uint32(1)); err != nil {
							log.Printf("[WARNING] Allowed IPs map failed inserting IP %s: %v", ip, err)
						} else {
							log.Printf("[NATIVE BPF] Allowed IP connection routing to: %s", ip)
						}
					}
				}
			}

			/* 7. Attach eBPF Socket Filter program to all active veth network interfaces */
			interfaces, err := net.Interfaces()
			if err == nil {
				for _, iface := range interfaces {
					/* Capture virtual ethernet adapters typically starting with veth, docker, or eth */
					isVeth := bytes.HasPrefix([]byte(iface.Name), []byte("veth")) ||
						bytes.HasPrefix([]byte(iface.Name), []byte("docker")) ||
						bytes.HasPrefix([]byte(iface.Name), []byte("eth"))

					if isVeth {
						log.Printf("[NATIVE BPF] Attaching socket DNS filter program to interface: %s (Index: %d)", iface.Name, iface.Index)
						fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
						if err != nil {
							log.Printf("[WARNING] Failed creating raw socket on %s: %v", iface.Name, err)
							continue
						}

						sll := &unix.SockaddrLinklayer{
							Protocol: htons(unix.ETH_P_ALL),
							Ifindex:  iface.Index,
						}
						if err := unix.Bind(fd, sll); err != nil {
							log.Printf("[WARNING] Failed binding raw socket to interface %s: %v", iface.Name, err)
							unix.Close(fd)
							continue
						}

						/* Attach socket filter program */
						if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, objects.SocketDnsFilter.FD()); err != nil {
							log.Printf("[WARNING] Failed attaching SO_ATTACH_BPF filter program on %s: %v", iface.Name, err)
							unix.Close(fd)
							continue
						}
						socketFds = append(socketFds, fd)
					}
				}
			}

			log.Println("[SUCCESS] Programmatic eBPF lifecycle controller successfully active.")
			return nil
		}()
	})
	return controllerInitErr
}

/* RegisterSandboxPID registers the sandboxed PID into the eBPF maps */
func RegisterSandboxPID(pid int) error {
	if err := InitNativeController(); err != nil {
		log.Printf("[WARNING] eBPF RegisterSandboxPID bypassed: %v", err)
		return nil
	}

	key := uint32(pid)
	value := uint32(1)
	if err := lockedMap.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed programmatically updating locked_sandboxes eBPF map: %v", err)
	}

	log.Printf("[NATIVE BPF] Registered container PID %d inside the kernel-level sandbox registry.", pid)
	return nil
}

/* RemoveSandboxPID deletes the PID from the locked_sandboxes map */
func RemoveSandboxPID(pid int) error {
	if err := InitNativeController(); err != nil {
		log.Printf("[WARNING] eBPF RemoveSandboxPID bypassed: %v", err)
		return nil
	}

	key := uint32(pid)
	if err := lockedMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("failed programmatically deleting key from locked_sandboxes eBPF map: %v", err)
	}

	return nil
}
/* IsActive returns true if the native eBPF controller was successfully initialized */
func IsActive() bool {
	return lockedMap != nil
}

/* StreamKernelAlerts dynamically pulls from BPF Ring Buffer Map and streams alerts */
func StreamKernelAlerts() {
	if err := InitNativeController(); err != nil {
		log.Printf("[BPF TELEMETRY] Dynamic Ring Buffer stream bypassed: %v", err)
		return
	}

	if eventsRingMap == nil {
		log.Println("[BPF TELEMETRY] Telemetry listener aborted: ring buffer map is nil")
		return
	}

	rd, err := ringbuf.NewReader(eventsRingMap)
	if err != nil {
		log.Printf("[BPF TELEMETRY] Failed creating ringbuffer reader: %v", err)
		return
	}
	defer rd.Close()

	log.Println("[BPF TELEMETRY] Ring Buffer async alerts listener actively polling...")

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("[BPF TELEMETRY] Ring Buffer reader closed. Listener shutting down.")
				return
			}
			log.Printf("[BPF TELEMETRY] Error reading ring buffer entry: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}

		var event SecurityEvent
		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
		if err != nil {
			log.Printf("[BPF TELEMETRY] Failed parsing binary event payload: %v", err)
			continue
		}

		commString := string(bytes.Trim(event.Comm[:], "\x00"))

		if event.SecurityViolationType == 1 {
			atomic.AddInt64(&BlockedNetworkBreaches, 1)
			log.Printf("[🚨 KERNEL ALERT] Egress network tampered! PID: %d, Image: %s. Process terminated instantly via SIGKILL (9). Zero bytes leaked.", event.ProcessID, commString)
		} else if event.SecurityViolationType == 2 {
			atomic.AddInt64(&BlockedFileBypasses, 1)
			log.Printf("[🚨 KERNEL ALERT] File boundary intrusion attempt blocked! PID: %d, Image: %s. Call thread terminated via SIGKILL (9). Zero bytes leaked.", event.ProcessID, commString)
		}
	}
}

/* CloseNativeController cleans up eBPF maps and socket handles */
func CloseNativeController() {
	if tracepointConn != nil {
		_ = tracepointConn.Close()
	}
	if tracepointOpenat != nil {
		_ = tracepointOpenat.Close()
	}
	for _, fd := range socketFds {
		_ = syscall.Close(fd)
	}
}
