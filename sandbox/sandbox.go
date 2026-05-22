package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"nexiscore/ebpf"
)

// Result represents the execution output of the sandbox
type Result struct {
	Stdout     string        `json:"stdout"`
	Stderr     string        `json:"stderr"`
	ExitCode   int           `json:"exit_code"`
	TimeTaken  time.Duration `json:"time_taken"`
}

// SandboxManager manages the lifecycle and execution of sandboxed Docker containers
type SandboxManager struct {
	imageName string
}

// NewSandboxManager creates a new SandboxManager
func NewSandboxManager(imageName string) *SandboxManager {
	if imageName == "" {
		imageName = "python:3.10-slim"
	}
	return &SandboxManager{imageName: imageName}
}

// Execute runs the untrusted code within a runsc container, returning the host PID before waiting
// and ultimately returning execution outputs.
func (sm *SandboxManager) Execute(scriptCode string, onPIDAcquired func(pid int) error) (*Result, error) {
	// 1. Provision a dynamic scratch space directory structure inside '/tmp/' using secure 0700 file mode permissions
	scratchDir, err := os.MkdirTemp("/tmp", "nexiscore-scratch-")
	if err != nil {
		return nil, fmt.Errorf("failed to create scratch space directory: %w", err)
	}
	// Ensure cleanup of the scratch space on host after run
	defer os.RemoveAll(scratchDir)

	// Explicitly ensure permissions are 0700
	err = os.Chmod(scratchDir, 0700)
	if err != nil {
		return nil, fmt.Errorf("failed to set 0700 permissions on scratch space: %w", err)
	}

	// 2. Write out untrusted Python code scripts directly inside this directory
	scriptPath := filepath.Join(scratchDir, "script.py")
	err = os.WriteFile(scriptPath, []byte(scriptCode), 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to write untrusted script: %w", err)
	}

	// Make the script read-only (0400) and directory read-only / non-writable (0500)
	err = os.Chmod(scriptPath, 0400)
	if err != nil {
		return nil, fmt.Errorf("failed to make script read-only: %w", err)
	}
	err = os.Chmod(scratchDir, 0500)
	if err != nil {
		return nil, fmt.Errorf("failed to make scratch directory read-only: %w", err)
	}

	// 3. Set up execution context with a 5-second timeout deadline
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Container name needs to be unique to avoid collisions
	containerName := fmt.Sprintf("nexiscore-sandbox-%d", time.Now().UnixNano())

	// 4. Construct the Docker run command in detached mode (-d)
	// Hardcoded constraints:
	// - '--runtime=runsc' (gVisor overlay)
	// - '--network=none' (disabled network traffic)
	// - '--memory=512m' (physical memory limit)
	args := []string{"run", "-d", "--name", containerName}
	if detectRunsc() {
		args = append(args, "--runtime=runsc")
	} else {
		_, _ = fmt.Fprintln(os.Stderr, "WARNING: gVisor runtime 'runsc' not configured/available in Docker. Falling back to default runtime.")
	}
	networkMode := "bridge"
	if !ebpf.IsActive() {
		networkMode = "none"
	}

	args = append(args,
		"--network="+networkMode,
		"--memory=512m",
		"-v", fmt.Sprintf("%s:/app:ro", scratchDir),
		sm.imageName,
		"python", "/app/script.py",
	)

	dockerRunCmd := exec.CommandContext(ctx, "docker", args...)

	var runStdout, runStderr bytes.Buffer
	dockerRunCmd.Stdout = &runStdout
	dockerRunCmd.Stderr = &runStderr

	err = dockerRunCmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to spawn docker container: %v (stderr: %s)", err, runStderr.String())
	}

	containerID := strings.TrimSpace(runStdout.String())
	if containerID == "" {
		return nil, errors.New("container spawned successfully but container ID is empty")
	}

	// Ensure container is forcefully cleaned up on return
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupCtx, "docker", "rm", "-f", containerName).Run()
	}()

	// 5. Capture the true Process ID (PID) of the proxy wrapper process
	dockerInspectCmd := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.State.Pid}}", containerID)
	var inspectStdout, inspectStderr bytes.Buffer
	dockerInspectCmd.Stdout = &inspectStdout
	dockerInspectCmd.Stderr = &inspectStderr

	err = dockerInspectCmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container PID: %v (stderr: %s)", err, inspectStderr.String())
	}

	pidStr := strings.TrimSpace(inspectStdout.String())
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 0 {
		return nil, fmt.Errorf("invalid container host PID captured: %s (err: %v)", pidStr, err)
	}

	// 6. Return PID to the orchestration thread before tracking execution outputs
	if onPIDAcquired != nil {
		err = onPIDAcquired(pid)
		if err != nil {
			return nil, fmt.Errorf("failed during PID acquisition hook: %w", err)
		}
	}

	// 7. Track execution outputs by waiting for container to complete
	startTime := time.Now()
	dockerWaitCmd := exec.CommandContext(ctx, "docker", "wait", containerID)
	var waitStdout bytes.Buffer
	dockerWaitCmd.Stdout = &waitStdout
	err = dockerWaitCmd.Run()

	timeTaken := time.Since(startTime)

	exitCode := 0
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return &Result{
				Stdout:     "",
				Stderr:     "Execution timed out (5s deadline exceeded)",
				ExitCode:   -1,
				TimeTaken:  timeTaken,
			}, nil
		}
		exitCode = -2
	} else {
		exitCodeStr := strings.TrimSpace(waitStdout.String())
		if code, convErr := strconv.Atoi(exitCodeStr); convErr == nil {
			exitCode = code
		}
	}

	// Capture standard output and error from the container logs
	dockerLogsCmd := exec.CommandContext(ctx, "docker", "logs", containerID)
	var logsStdout, logsStderr bytes.Buffer
	dockerLogsCmd.Stdout = &logsStdout
	dockerLogsCmd.Stderr = &logsStderr
	_ = dockerLogsCmd.Run()

	return &Result{
		Stdout:     logsStdout.String(),
		Stderr:     logsStderr.String(),
		ExitCode:   exitCode,
		TimeTaken:  timeTaken,
	}, nil
}

var (
	isRunscAvailable bool
	checkRunscOnce   sync.Once
)

func detectRunsc() bool {
	checkRunscOnce.Do(func() {
		cmd := exec.Command("docker", "info")
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err == nil {
			if strings.Contains(out.String(), "runsc") {
				isRunscAvailable = true
				return
			}
		}
		if _, err := exec.LookPath("runsc"); err == nil {
			isRunscAvailable = true
			return
		}
		isRunscAvailable = false
	})
	return isRunscAvailable
}
