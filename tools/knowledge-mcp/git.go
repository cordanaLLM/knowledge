package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	gitExecutablePath     = "/usr/bin/git"
	gitCommandTimeout     = 10 * time.Second
	maxGitDiagnosticBytes = 64 << 10
	maxGitRootOutputBytes = 64 << 10
	maxGitFileOutputBytes = 64 << 20
)

type commandCapture struct {
	maximum  int
	value    bytes.Buffer
	overflow bool
}

func (capture *commandCapture) Write(value []byte) (int, error) {
	original := len(value)
	remaining := capture.maximum - capture.value.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
			capture.overflow = true
		}
		_, _ = capture.value.Write(value)
	} else {
		capture.overflow = true
	}
	return original, nil
}

func validateGitExecutable() error {
	if err := validateDirectoryPathNoSymlinks(filepath.Dir(gitExecutablePath)); err != nil {
		return fmt.Errorf("validate fixed Git parent: %w", err)
	}
	info, err := os.Lstat(gitExecutablePath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("fixed Git executable is unavailable or unsafe")
	}
	return nil
}

func runGitCommand(root string, outputLimit int, arguments ...string) ([]byte, bool, error) {
	return runGitCommandWithTimeout(root, outputLimit, gitCommandTimeout, arguments...)
}

func runGitCommandWithTimeout(root string, outputLimit int, timeout time.Duration, arguments ...string) ([]byte, bool, error) {
	if outputLimit < 1 {
		return nil, false, errors.New("Git output limit must be positive")
	}
	if timeout <= 0 {
		return nil, false, errors.New("Git command timeout must be positive")
	}
	if err := validateGitExecutable(); err != nil {
		return nil, false, err
	}
	commandArguments := make([]string, 0, len(arguments)+2)
	if root != "" {
		commandArguments = append(commandArguments, "-C", root)
	}
	commandArguments = append(commandArguments, arguments...)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, gitExecutablePath, commandArguments...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = 100 * time.Millisecond
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
	stdout := &commandCapture{maximum: outputLimit}
	stderr := &commandCapture{maximum: maxGitDiagnosticBytes}
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	if ctx.Err() != nil {
		return stdout.value.Bytes(), stdout.overflow, errors.New("Git command timed out")
	}
	if err != nil {
		diagnostic := strings.TrimSpace(stderr.value.String())
		if stderr.overflow {
			diagnostic += " [diagnostic truncated]"
		}
		return stdout.value.Bytes(), stdout.overflow, fmt.Errorf("Git command failed: %w: %s", err, diagnostic)
	}
	return append([]byte(nil), stdout.value.Bytes()...), stdout.overflow, nil
}

func discoverRepositoryRoot(root string) (string, error) {
	output, overflow, err := runGitCommand(root, maxGitRootOutputBytes, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", err
	}
	if overflow {
		return "", errors.New("Git repository-root output exceeded its bound")
	}
	value := stringTrimSpace(string(output))
	if value == "" || strings.ContainsRune(value, '\x00') || strings.ContainsAny(value, "\r\n") {
		return "", errors.New("Git returned an invalid repository root")
	}
	return value, nil
}
