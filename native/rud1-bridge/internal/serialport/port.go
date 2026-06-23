// Package serialport opens the local endpoint — COM (com0com on Windows)
// or pty (Unix) — behind the bridge.Endpoint interface.
package serialport

import (
	"context"
	"fmt"

	"github.com/rud1-es/rud1-bridge/internal/bridge"
)

// OpenOpts is the platform-agnostic open request.
//
//   - Windows: PortName is the com0com B-side COM (A-side is what the user opens).
//   - Unix: PortName ignored; creates a pty pair, symlinks LinkPath to the slave.
type OpenOpts struct {
	PortName string
	LinkPath string
	Settings bridge.LineSettings
}

// Open returns a bridge.Endpoint for the platform-appropriate device.
func Open(ctx context.Context, opts OpenOpts) (bridge.Endpoint, error) {
	ep, err := openPlatform(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("open serial endpoint: %w", err)
	}
	return ep, nil
}
