// rud1-bridge is the desktop-side TCP-serial proxy. Runs as a subprocess
// of rud1-desktop, opens a local endpoint (com0com COM on Windows, pty
// on Unix), and forwards bytes + modem-control to rud1-fw over TCP using
// an RFC 2217 dialect.
//
// Protocol: flag args, one "ready" line on stdout, JSON events on stderr.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rud1-es/rud1-bridge/internal/bridge"
	"github.com/rud1-es/rud1-bridge/internal/serialport"
)

// Version stamped at build time via -ldflags.
var Version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "rud1-bridge: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		piHost   = flag.String("pi-host", "", "Pi VPN address (e.g. 10.99.91.243)")
		piPort   = flag.Int("pi-port", 0, "Pi serial bridge TCP port (from /api/serial-bridge/sessions/{busId})")
		port     = flag.String("local-port", "", "Local COM port (Windows: com0com B-side, e.g. COM7)")
		linkPath = flag.String("link-path", "", "Symlink path for the pty slave (Unix only, e.g. /tmp/rud1-bridge-1-3)")
		baud     = flag.Int("baud", 115200, "Baud rate to negotiate with the Pi (RFC 2217 SET-BAUDRATE)")
		dataBits = flag.Int("data-bits", 8, "Data bits (5/6/7/8)")
		parity   = flag.String("parity", "N", "Parity: N/E/O")
		stopBits = flag.String("stop-bits", "1", "Stop bits: 1/1.5/2")
		showVer  = flag.Bool("version", false, "Print version and exit")
		readyTag = flag.String("ready-tag", "BRIDGE-READY",
			"Token printed on stdout once the endpoint is bound; the desktop "+
				"manager parses this line to learn the local path. Override only "+
				"when running standalone for debugging.")
	)
	flag.Parse()

	if *showVer {
		fmt.Println(Version)
		return nil
	}

	if *piHost == "" || *piPort == 0 {
		flag.Usage()
		return fmt.Errorf("--pi-host and --pi-port are required")
	}

	settings := bridge.LineSettings{
		BaudRate: *baud,
		DataBits: *dataBits,
		Parity:   strings.ToUpper(*parity),
		StopBits: *stopBits,
	}

	logger := bridge.NewStderrLogger()

	// Open endpoint BEFORE dialing Pi — surfaces local errors faster.
	openCtx, openCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer openCancel()
	ep, err := serialport.Open(openCtx, serialport.OpenOpts{
		PortName: *port,
		LinkPath: *linkPath,
		Settings: settings,
	})
	if err != nil {
		logger.Event("bridge.open.fail", map[string]any{"error": err.Error()})
		return err
	}

	// Ready line on stdout: "<readyTag> <JSON>". Token-prefixed so the
	// desktop can grep without committing to JSON-only stdout.
	ready := map[string]any{
		"version":  Version,
		"path":     ep.Path(),
		"piHost":   *piHost,
		"piPort":   *piPort,
		"baudRate": settings.BaudRate,
	}
	readyBytes, _ := json.Marshal(ready)
	fmt.Printf("%s %s\n", *readyTag, string(readyBytes))

	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg := bridge.Config{
		PiHost:   *piHost,
		PiPort:   *piPort,
		Endpoint: ep,
		Settings: settings,
		Logger:   logger,
	}

	if err := bridge.Run(ctx, cfg); err != nil {
		logger.Event("bridge.run.error", map[string]any{"error": err.Error()})
		return err
	}
	logger.Event("bridge.run.done", map[string]any{})
	return nil
}
