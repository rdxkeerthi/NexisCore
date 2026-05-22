package ebpf

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// RegisterSandboxPID inserts the active sandbox PID into the locked_sandboxes eBPF map
func RegisterSandboxPID(pid int) error {
	pid32 := uint32(pid)

	// Correctly pack PID into native little-endian byte array format for bpftool key parameter
	keyBytes := []string{
		fmt.Sprintf("0x%02x", byte(pid32)),
		fmt.Sprintf("0x%02x", byte(pid32>>8)),
		fmt.Sprintf("0x%02x", byte(pid32>>16)),
		fmt.Sprintf("0x%02x", byte(pid32>>24)),
	}

	// Execution parameters targeting 'locked_sandboxes' BPF Map by name
	args := []string{
		"bpftool",
		"map", "update",
		"name", "locked_sandboxes",
		"key", keyBytes[0], keyBytes[1], keyBytes[2], keyBytes[3],
		"value", "0x01", "0x00", "0x00", "0x00",
	}

	// Spawn the executive command under sudo (required to edit kernel maps)
	cmd := exec.Command("sudo", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to register sandbox PID %d in eBPF map: %v (stdout: %s, stderr: %s)",
			pid, err, strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()))
	}

	return nil
}

// RemoveSandboxPID deletes the PID key from the locked_sandboxes eBPF map
func RemoveSandboxPID(pid int) error {
	pid32 := uint32(pid)

	// Correctly pack PID into native little-endian byte array format
	keyBytes := []string{
		fmt.Sprintf("0x%02x", byte(pid32)),
		fmt.Sprintf("0x%02x", byte(pid32>>8)),
		fmt.Sprintf("0x%02x", byte(pid32>>16)),
		fmt.Sprintf("0x%02x", byte(pid32>>24)),
	}

	// Execution parameters for deleting from 'locked_sandboxes' BPF Map by name
	args := []string{
		"bpftool",
		"map", "delete",
		"name", "locked_sandboxes",
		"key", keyBytes[0], keyBytes[1], keyBytes[2], keyBytes[3],
	}

	cmd := exec.Command("sudo", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to remove sandbox PID %d from eBPF map: %v (stdout: %s, stderr: %s)",
			pid, err, strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()))
	}

	return nil
}
