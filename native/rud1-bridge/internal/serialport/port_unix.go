//go:build !windows

package serialport

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/creack/pty"
	"github.com/rud1-es/rud1-bridge/internal/bridge"
)

// unixEndpoint exposes a pty pair. PTYs don't carry modem-control
// signals, so PollControlChange returns nil — Arduino reset cannot be
// reproduced on Linux/macOS via this path. Operators who need it stay
// on USB/IP.
type unixEndpoint struct {
	master *os.File
	slave  *os.File
	path   string
	link   string

	mu     sync.Mutex
	closed bool
}

func openPlatform(_ context.Context, opts OpenOpts) (bridge.Endpoint, error) {
	master, slave, err := pty.Open()
	if err != nil {
		return nil, fmt.Errorf("open pty: %w", err)
	}

	// pty.Name() returns /dev/pts/N. Close the slave fd here; the
	// kernel keeps the node alive for the opener.
	path := slave.Name()
	if err := slave.Close(); err != nil {
		_ = master.Close()
		return nil, fmt.Errorf("close pty slave: %w", err)
	}

	if opts.LinkPath != "" {
		// Best-effort symlink — failure falls back to /dev/pts/N.
		_ = os.Remove(opts.LinkPath) // overwrite stale link
		if err := os.Symlink(path, opts.LinkPath); err != nil {
			fmt.Fprintf(os.Stderr,
				"rud1-bridge: warning: could not create symlink %s: %v\n",
				opts.LinkPath, err)
		}
	}

	return &unixEndpoint{
		master: master,
		path:   path,
		link:   opts.LinkPath,
	}, nil
}

func (e *unixEndpoint) Read(p []byte) (int, error) {
	return e.master.Read(p)
}

func (e *unixEndpoint) Write(p []byte) (int, error) {
	return e.master.Write(p)
}

// Close is idempotent so the bridge.Run watchdog and the deferred Close
// can both run without surfacing "file already closed".
func (e *unixEndpoint) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.mu.Unlock()
	if e.link != "" {
		_ = os.Remove(e.link)
	}
	return e.master.Close()
}

// Path prefers LinkPath when set — it's what the operator was told to open.
func (e *unixEndpoint) Path() string {
	if e.link != "" {
		return e.link
	}
	return e.path
}

// PollControlChange returns (nil, nil) — pty pairs don't propagate
// modem-control signals. The bridge core treats nil as "no event".
func (e *unixEndpoint) PollControlChange(_ context.Context) (*bridge.ControlState, error) {
	return nil, nil
}

// ErrNoSlavePath is for callers that want to assert the pty path matches
// an expected pattern. Currently unused outside tests.
var ErrNoSlavePath = errors.New("pty slave path unresolved")
