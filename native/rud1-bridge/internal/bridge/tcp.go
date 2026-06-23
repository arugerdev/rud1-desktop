package bridge

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Telnet / RFC 2217 byte constants. Keep synced with rud1-fw's rfc2217.go.
const (
	iac     byte = 0xff
	iacWill byte = 0xfb
	iacWont byte = 0xfc
	iacDo   byte = 0xfd
	iacDont byte = 0xfe
	iacSB   byte = 0xfa
	iacSE   byte = 0xf0

	optBinary  byte = 0x00
	optEcho    byte = 0x01
	optSGA     byte = 0x03
	optComPort byte = 0x2c

	cpcSetBaudRate byte = 1
	cpcSetDataSize byte = 2
	cpcSetParity   byte = 3
	cpcSetStopSize byte = 4
	cpcSetControl  byte = 5

	ctrlSetDTROn  byte = 8
	ctrlSetDTROff byte = 9
	ctrlSetRTSOn  byte = 11
	ctrlSetRTSOff byte = 12
)

// dialAndHandshake opens TCP and runs the RFC 2217 negotiation (WILL
// COM-PORT-OPTION + the four SET-* packets). SET-* replies are handled
// by the same IAC parser as the data stream.
func dialAndHandshake(ctx context.Context, cfg Config) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: cfg.HandshakeTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(cfg.PiHost, strconv.Itoa(cfg.PiPort)))
	if err != nil {
		return nil, err
	}

	// TCP_NODELAY: avrdude STK500 handshake needs reply within ~20ms;
	// Nagle would coalesce small payloads and miss the window.
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		// Keepalive catches a silently-broken WG tunnel.
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}

	// Telnet preamble + BINARY + SGA so 0xff data bytes don't get
	// interpreted as IAC commands.
	preamble := []byte{
		iac, iacWill, optComPort,
		iac, iacDo, optComPort,
		iac, iacDo, optBinary,
		iac, iacWill, optBinary,
		iac, iacWill, optSGA,
	}
	if _, err := conn.Write(preamble); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write preamble: %w", err)
	}

	// Initial line settings — applied synchronously by the Pi.
	settings := buildSetCommands(cfg.Settings)
	if _, err := conn.Write(settings); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write settings: %w", err)
	}

	return conn, nil
}

// buildSetCommands assembles the four RFC 2217 SET-* sub-negotiations.
// Baud is sent last as a defensive measure (most likely typo).
func buildSetCommands(s LineSettings) []byte {
	out := make([]byte, 0, 32)

	out = append(out, iac, iacSB, optComPort, cpcSetDataSize, byte(s.DataBits), iac, iacSE)
	out = append(out, iac, iacSB, optComPort, cpcSetParity, encodeParity(s.Parity), iac, iacSE)
	out = append(out, iac, iacSB, optComPort, cpcSetStopSize, encodeStopSize(s.StopBits), iac, iacSE)
	// SET-BAUDRATE — 4 bytes big-endian.
	baudBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(baudBytes, uint32(s.BaudRate))
	out = append(out, iac, iacSB, optComPort, cpcSetBaudRate)
	out = append(out, baudBytes...)
	out = append(out, iac, iacSE)

	return out
}

func encodeParity(p string) byte {
	switch p {
	case "N", "n", "":
		return 1
	case "O", "o":
		return 2
	case "E", "e":
		return 3
	}
	return 1
}

func encodeStopSize(s string) byte {
	switch s {
	case "1", "":
		return 1
	case "2":
		return 2
	case "1.5":
		return 3
	}
	return 1
}

// pumpTCPToEndpoint pumps TCP -> local endpoint, stripping IAC.
// Returns nil on EOF.
func pumpTCPToEndpoint(ctx context.Context, conn net.Conn, ep Endpoint, log Logger) error {
	parser := newServerIACParser()
	buf := make([]byte, 8192)
	bytesIn, bytesOut := uint64(0), uint64(0)
	defer func() {
		log.Event("bridge.pump.tcp2ep.done", map[string]any{
			"bytesIn":  bytesIn,
			"bytesOut": bytesOut,
		})
	}()
	for {
		// 1s read deadline so ctx.Done is checked per tick. A blocking
		// Read can't be unblocked by Close reliably across platforms.
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := conn.Read(buf)
		bytesIn += uint64(n)
		if n > 0 {
			payload := parser.Feed(buf[:n])
			if len(payload) > 0 {
				if _, werr := ep.Write(payload); werr != nil {
					return fmt.Errorf("write endpoint: %w", werr)
				}
				bytesOut += uint64(len(payload))
			}
		}
		if err != nil {
			if isTimeout(err) {
				select {
				case <-ctx.Done():
					return nil
				default:
					continue
				}
			}
			if errors.Is(err, io.EOF) || isClosedConn(err) {
				return nil
			}
			return err
		}
	}
}

// pumpEndpointToTCP pumps local endpoint -> TCP, doubling literal 0xff
// (RFC 2217 IAC escape).
func pumpEndpointToTCP(ctx context.Context, ep Endpoint, conn net.Conn, log Logger) error {
	buf := make([]byte, 8192)
	out := make([]byte, 0, 8192*2) // doubled if every byte happens to be 0xff
	bytesIn, bytesOut := uint64(0), uint64(0)
	defer func() {
		log.Event("bridge.pump.ep2tcp.done", map[string]any{
			"bytesIn":  bytesIn,
			"bytesOut": bytesOut,
		})
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, err := ep.Read(buf)
		bytesIn += uint64(n)
		if n > 0 {
			out = out[:0]
			for _, b := range buf[:n] {
				if b == iac {
					out = append(out, iac, iac)
				} else {
					out = append(out, b)
				}
			}
			if _, werr := conn.Write(out); werr != nil {
				return fmt.Errorf("write tcp: %w", werr)
			}
			bytesOut += uint64(len(out))
		}
		if err != nil {
			if errors.Is(err, io.EOF) || isClosedConn(err) {
				return nil
			}
			return err
		}
	}
}

// forwardModemControl polls endpoint DTR/RTS and emits SET-CONTROL on
// every edge. Coalesces no-change polls.
func forwardModemControl(ctx context.Context, ep Endpoint, conn net.Conn, interval time.Duration, log Logger) error {
	last := ControlState{DTR: true, RTS: true}
	first := true
	pollCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Producer is rate-limited by `interval`. Windows
	// PollControlChange returns synchronously, so without this gate we
	// hammer GetCommModemStatus IOCTLs and starve the data path.
	stateCh := make(chan ControlState, 4)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-pollCtx.Done():
				return
			default:
			}
			st, err := ep.PollControlChange(pollCtx)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				log.Event("bridge.modem.poll.error", map[string]any{"error": err.Error()})
				return
			}
			if st != nil {
				select {
				case stateCh <- *st:
				case <-pollCtx.Done():
					return
				}
			}
			// Always gate on the ticker. A `continue` past it on
			// synchronous endpoints pinned a CPU core.
			select {
			case <-pollCtx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	defer func() {
		cancel()
		wg.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case st := <-stateCh:
			if !first && st.DTR == last.DTR && st.RTS == last.RTS {
				continue
			}
			first = false
			pkt := buildControlPacket(st, last)
			if _, err := conn.Write(pkt); err != nil {
				return fmt.Errorf("write modem ctl: %w", err)
			}
			log.Event("bridge.modem.set", map[string]any{
				"dtr": st.DTR, "rts": st.RTS,
			})
			last = st
		}
	}
}

// buildControlPacket emits one or two SET-CONTROL packets. DTR-first so
// the Arduino bootloader sees a clean DTR pulse on remotes that read
// packets independently.
func buildControlPacket(now, prev ControlState) []byte {
	out := make([]byte, 0, 14)
	if now.DTR != prev.DTR {
		v := ctrlSetDTROff
		if now.DTR {
			v = ctrlSetDTROn
		}
		out = append(out, iac, iacSB, optComPort, cpcSetControl, v, iac, iacSE)
	}
	if now.RTS != prev.RTS {
		v := ctrlSetRTSOff
		if now.RTS {
			v = ctrlSetRTSOn
		}
		out = append(out, iac, iacSB, optComPort, cpcSetControl, v, iac, iacSE)
	}
	return out
}

// isTimeout matches the net package's timeout interface.
func isTimeout(err error) bool {
	type timeouter interface{ Timeout() bool }
	t, ok := err.(timeouter)
	return ok && t.Timeout()
}

// isClosedConn detects "use of closed network connection" without pinning
// the exact stdlib message — defensive backup for wrappers that swallow
// net.ErrClosed.
func isClosedConn(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	if err == nil {
		return false
	}
	msg := err.Error()
	return contains(msg, "use of closed network connection") ||
		contains(msg, "connection reset by peer")
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
