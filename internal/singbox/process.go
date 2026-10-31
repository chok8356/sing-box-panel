package singbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Process supervises one `sing-box run` child process.
// It is not safe for concurrent use; the caller serializes access.
type Process struct {
	Binary string   // path to the sing-box executable
	Dir    string   // working directory for the applied and checked configs
	Logs   *TailLog // receives sing-box output and panel status lines

	cmd     *exec.Cmd
	done    chan struct{} // closed when cmd exits
	current []byte        // config of the last successful Apply
}

// Running reports whether the child process is alive.
func (p *Process) Running() bool {
	if p.done == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

// Current returns the config of the last successful Apply, or nil.
func (p *Process) Current() []byte { return bytes.Clone(p.current) }

// PID returns the child process ID, or 0 when nothing was started.
func (p *Process) PID() int {
	if p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

// Stop terminates the child and forgets the applied config.
func (p *Process) Stop() {
	p.stop()
	p.current = nil
}

func (p *Process) stop() {
	if !p.Running() {
		return
	}
	// Interrupt works for the supported Linux production runtime.
	_ = p.cmd.Process.Signal(os.Interrupt)
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}

// Check runs `sing-box check` on body without touching the running process.
func (p *Process) Check(ctx context.Context, body []byte) error {
	if err := os.MkdirAll(p.Dir, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(p.Dir, "check-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(body); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var output limitedOutput
	cmd := exec.CommandContext(ctx, p.Binary, "check", "--disable-color", "-c", file.Name())
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		p.log("Validation failed: " + output.String())
		if ctx.Err() != nil {
			return errors.New("sing-box validation timed out or was cancelled")
		}
		return fmt.Errorf("sing-box check failed: %s", strings.TrimSpace(output.String()))
	}
	return nil
}

// Apply checks body, restarts sing-box with it and rolls back to the
// previous config if the new one does not start.
func (p *Process) Apply(ctx context.Context, body []byte) error {
	return p.apply(ctx, body, false)
}

// apply with force restarts even when body is already running.
func (p *Process) apply(ctx context.Context, body []byte, force bool) error {
	if p.Logs == nil {
		p.Logs = &TailLog{}
	}
	if !force && bytes.Equal(body, p.current) && p.Running() {
		return nil
	}
	if err := p.Check(ctx, body); err != nil {
		return err
	}

	old := p.current
	p.log("Applying server configuration.")
	p.stop()
	if err := p.start(body); err != nil {
		p.log("Startup failed; restoring previous configuration.")
		p.stop()
		// Restarting the same config that just failed would only fail again.
		if len(old) > 0 && !bytes.Equal(old, body) {
			if rollback := p.start(old); rollback != nil {
				return errors.New("new config and rollback failed; inspect server status")
			}
		}
		return err
	}
	p.current = bytes.Clone(body)
	p.log("sing-box is running.")
	return nil
}

// Restart runs the current config again, for example after its certificate files changed.
func (p *Process) Restart(ctx context.Context) error {
	if p.current == nil {
		return nil
	}
	// current stays set on failure, so the watcher and later renewals still see it.
	return p.apply(ctx, p.current, true)
}

// start launches sing-box and waits until the managed inbound accepts TCP.
func (p *Process) start(body []byte) error {
	filename := filepath.Join(p.Dir, "server.json")
	if err := os.WriteFile(filename+".new", body, 0600); err != nil {
		return err
	}
	if err := os.Rename(filename+".new", filename); err != nil {
		return err
	}

	p.cmd = exec.Command(p.Binary, "run", "--disable-color", "-c", filename)
	p.cmd.Stdout, p.cmd.Stderr = p.Logs, p.Logs
	if err := p.cmd.Start(); err != nil {
		return err
	}
	p.done = make(chan struct{})
	done, cmd := p.done, p.cmd
	go func() { _ = cmd.Wait(); close(done) }()

	address, ok := probeAddress(body)
	if !ok {
		// Only UDP inbounds (or none): give sing-box a moment to fail on bad config.
		time.Sleep(500 * time.Millisecond)
		if !p.Running() {
			return errors.New("sing-box exited during startup; see Logs")
		}
		return nil
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !p.Running() {
			return errors.New("sing-box exited during startup; see Logs")
		}
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			connection.Close()
			time.Sleep(100 * time.Millisecond)
			if p.Running() {
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	p.stop()
	return errors.New("sing-box did not open its inbound " + address)
}

func (p *Process) log(message string) {
	if p.Logs != nil {
		_, _ = p.Logs.Write([]byte("[panel] " + message + "\n"))
	}
}

// limitedOutput keeps the first 8 KiB of validator output.
// It is only shown to authenticated administrators.
type limitedOutput struct{ bytes.Buffer }

func (b *limitedOutput) Write(data []byte) (int, error) {
	n := len(data)
	if remaining := 8192 - b.Len(); remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = b.Buffer.Write(data)
	}
	return n, nil
}
