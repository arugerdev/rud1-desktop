//go:build windows

package serialport

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rud1-es/rud1-bridge/internal/bridge"
	gserial "go.bug.st/serial"
)

// windowsEndpoint wraps a com0com B-side port. com0com's default pin
// layout maps user DTR→our DSR and user RTS→our CTS.
type windowsEndpoint struct {
	port     gserial.Port
	portName string

	mu       sync.Mutex
	closed   bool
	lastRead time.Time
}

func openPlatform(_ context.Context, opts OpenOpts) (bridge.Endpoint, error) {
	if opts.PortName == "" {
		return nil, errors.New("PortName required on Windows (com0com B-side COM name)")
	}
	mode := &gserial.Mode{
		BaudRate: opts.Settings.BaudRate,
		DataBits: opts.Settings.DataBits,
		Parity:   parseParity(opts.Settings.Parity),
		StopBits: parseStopBits(opts.Settings.StopBits),
	}
	// com0com is virtual: BaudRate/DataBits/Parity are metadata. Real
	// rate is set Pi-side via RFC 2217 SET-BAUDRATE.
	port, err := gserial.Open(opts.PortName, mode)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", opts.PortName, err)
	}
	// Assert DTR/RTS so the Pi-side ttyACMx mirrors "port open".
	_ = port.SetDTR(true)
	_ = port.SetRTS(true)

	// Short read timeout lets PollControlChange and the read pump share
	// the port without blocking each other.
	_ = port.SetReadTimeout(50 * time.Millisecond)

	return &windowsEndpoint{port: port, portName: opts.PortName}, nil
}

func (e *windowsEndpoint) Read(p []byte) (int, error) {
	n, err := e.port.Read(p)
	// go.bug.st/serial returns (0, nil) on read timeout — let the pump retry.
	if err == nil && n == 0 {
		return 0, nil
	}
	return n, err
}

func (e *windowsEndpoint) Write(p []byte) (int, error) {
	return e.port.Write(p)
}

func (e *windowsEndpoint) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	return e.port.Close()
}

func (e *windowsEndpoint) Path() string { return e.portName }

// PollControlChange reads modem status bits and returns the user-side
// DTR/RTS. com0com default pin map: user DTR (pin 4) → our DSR (pin 6),
// user RTS (pin 7) → our CTS (pin 8). Operators with non-default com0com
// mappings must reconfigure to the default.
func (e *windowsEndpoint) PollControlChange(ctx context.Context) (*bridge.ControlState, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	bits, err := e.port.GetModemStatusBits()
	if err != nil {
		return nil, err
	}
	return &bridge.ControlState{
		DTR: bits.DSR,
		RTS: bits.CTS,
	}, nil
}

func parseParity(s string) gserial.Parity {
	switch s {
	case "E", "e":
		return gserial.EvenParity
	case "O", "o":
		return gserial.OddParity
	default:
		return gserial.NoParity
	}
}

func parseStopBits(s string) gserial.StopBits {
	switch s {
	case "2":
		return gserial.TwoStopBits
	case "1.5":
		return gserial.OnePointFiveStopBits
	default:
		return gserial.OneStopBit
	}
}
