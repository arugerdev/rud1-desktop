// Package bridge implements the desktop side of the rud1 serial bridge:
// it bridges a local serial endpoint (Windows COM via com0com or a Unix
// pty) to a TCP socket talking RFC 2217 against rud1-fw on the Pi.
package bridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// Endpoint is the abstraction over the local "device" — the user-facing
// side. On Windows it's a com0com COM port; on Unix it's a pty pair.
// Implementations live in internal/serialport/.
type Endpoint interface {
	io.ReadWriteCloser

	// Path returns the OS-visible path/name the user opens. Logged so
	// the desktop can echo it to the operator. Stable for life of endpoint.
	Path() string

	// PollControlChange returns the next control-signal transition the
	// other side caused, or nil on cancellation. The interface
	// deliberately doesn't expose the polling cadence.
	PollControlChange(ctx context.Context) (*ControlState, error)
}

// ControlState is the modem-control snapshot we forward to the Pi.
// Always carries "what the operator set", regardless of which physical
// pin we read (on Windows com0com, the operator's DTR/RTS arrives as
// our DSR/CTS).
type ControlState struct {
	DTR bool
	RTS bool
}

// LineSettings is the baud / framing applied at session start. Empty
// parity defaults to "N", empty stop bits defaults to "1".
type LineSettings struct {
	BaudRate int
	DataBits int
	Parity   string // "N" / "E" / "O"
	StopBits string // "1" / "2" / "1.5"
}

// Defaults returns 115200 8N1 — the universal Arduino upload speed.
func Defaults() LineSettings {
	return LineSettings{
		BaudRate: 115200,
		DataBits: 8,
		Parity:   "N",
		StopBits: "1",
	}
}

// Config is the runtime configuration handed to Run().
type Config struct {
	// PiHost is the Pi's reachable hostname or IP (typically a WG VPN
	// address like 10.99.91.243 or 10.77.X.1).
	PiHost string
	// PiPort is the bridge's TCP port on the Pi.
	PiPort int
	// Endpoint is the opened local serial side. Run takes ownership
	// and closes it on return.
	Endpoint Endpoint
	// Settings is the initial line state. Zero values resolve to Defaults().
	Settings LineSettings
	// Logger sinks structured events. Nil means silent (NoopLogger).
	Logger Logger
	// ControlPollInterval cadence. Arduino reset pulse is ~50ms; 10ms
	// gives 5 samples per pulse. Zero means 10ms.
	ControlPollInterval time.Duration
	// HandshakeTimeout caps TCP connect + initial RFC 2217 round-trip.
	// Default 10s.
	HandshakeTimeout time.Duration
}

// Validate cross-checks the config. Messages surface as desktop IPC replies.
func (c *Config) Validate() error {
	if c.PiHost == "" {
		return errors.New("PiHost is empty")
	}
	if c.PiPort <= 0 || c.PiPort > 65535 {
		return fmt.Errorf("PiPort %d out of range", c.PiPort)
	}
	if c.Endpoint == nil {
		return errors.New("Endpoint is nil")
	}
	return nil
}

// Run brings up the bridge, runs the RFC 2217 handshake, starts the
// bidirectional pump, and blocks until either side EOFs or ctx is
// cancelled. Returns nil on clean shutdown.
func Run(ctx context.Context, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if cfg.Settings.BaudRate == 0 {
		cfg.Settings = Defaults()
	}
	if cfg.Logger == nil {
		cfg.Logger = NoopLogger{}
	}
	if cfg.ControlPollInterval <= 0 {
		cfg.ControlPollInterval = 10 * time.Millisecond
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}

	cfg.Logger.Event("bridge.start", map[string]any{
		"piHost":   cfg.PiHost,
		"piPort":   cfg.PiPort,
		"endpoint": cfg.Endpoint.Path(),
		"baudRate": cfg.Settings.BaudRate,
		"dataBits": cfg.Settings.DataBits,
		"parity":   cfg.Settings.Parity,
		"stopBits": cfg.Settings.StopBits,
	})
	defer cfg.Endpoint.Close()

	tcpCtx, tcpCancel := context.WithTimeout(ctx, cfg.HandshakeTimeout)
	conn, err := dialAndHandshake(tcpCtx, cfg)
	tcpCancel()
	if err != nil {
		return fmt.Errorf("connect to %s:%d: %w", cfg.PiHost, cfg.PiPort, err)
	}
	defer conn.Close()
	cfg.Logger.Event("bridge.handshake", map[string]any{
		"remote": fmt.Sprintf("%s:%d", cfg.PiHost, cfg.PiPort),
	})

	pumpCtx, pumpCancel := context.WithCancel(ctx)
	defer pumpCancel()

	// Watchdog: close the endpoint when pumpCtx ends so a blocked Read
	// on the Unix pty (no SetReadDeadline) unblocks. Close is idempotent.
	go func() {
		<-pumpCtx.Done()
		_ = cfg.Endpoint.Close()
	}()

	var wg sync.WaitGroup
	errCh := make(chan error, 3)

	// Pump 1: TCP -> endpoint.
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := pumpTCPToEndpoint(pumpCtx, conn, cfg.Endpoint, cfg.Logger)
		if err != nil && !errors.Is(err, context.Canceled) {
			errCh <- fmt.Errorf("tcp→endpoint: %w", err)
		}
		pumpCancel()
	}()

	// Pump 2: endpoint -> TCP (with IAC escaping).
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := pumpEndpointToTCP(pumpCtx, cfg.Endpoint, conn, cfg.Logger)
		if err != nil && !errors.Is(err, context.Canceled) {
			errCh <- fmt.Errorf("endpoint→tcp: %w", err)
		}
		pumpCancel()
	}()

	// Pump 3: modem-control forwarder.
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := forwardModemControl(pumpCtx, cfg.Endpoint, conn, cfg.ControlPollInterval, cfg.Logger)
		if err != nil && !errors.Is(err, context.Canceled) {
			errCh <- fmt.Errorf("modem-control: %w", err)
		}
		pumpCancel()
	}()

	wg.Wait()
	close(errCh)
	cfg.Logger.Event("bridge.stop", map[string]any{})

	// Surface FIRST error only — subsequents are usually downstream of it.
	if first, ok := <-errCh; ok {
		return first
	}
	return nil
}
