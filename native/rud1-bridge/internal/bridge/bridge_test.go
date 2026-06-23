package bridge

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestServerIACParser(t *testing.T) {
	t.Run("plain bytes pass through", func(t *testing.T) {
		p := newServerIACParser()
		got := p.Feed([]byte{1, 2, 3, 4})
		if !bytes.Equal(got, []byte{1, 2, 3, 4}) {
			t.Errorf("Feed = %v, want [1 2 3 4]", got)
		}
	})

	t.Run("IAC IAC unescapes to single 0xff", func(t *testing.T) {
		p := newServerIACParser()
		got := p.Feed([]byte{1, iac, iac, 2})
		if !bytes.Equal(got, []byte{1, 0xff, 2}) {
			t.Errorf("Feed = %v, want [1 0xff 2]", got)
		}
	})

	t.Run("IAC WILL OPT is stripped", func(t *testing.T) {
		p := newServerIACParser()
		got := p.Feed([]byte{1, iac, iacWill, optComPort, 2})
		if !bytes.Equal(got, []byte{1, 2}) {
			t.Errorf("Feed = %v, want [1 2]", got)
		}
	})

	t.Run("sub-negotiation is stripped", func(t *testing.T) {
		p := newServerIACParser()
		// IAC SB COM-PORT-OPTION SET-BAUDRATE-REPLY 0 1 0xC2 0 IAC SE
		// (115200 BE = 00 01 C2 00).
		input := []byte{
			'A',
			iac, iacSB, optComPort, cpcSetBaudRate + 100,
			0x00, 0x01, 0xC2, 0x00,
			iac, iacSE,
			'B',
		}
		got := p.Feed(input)
		if !bytes.Equal(got, []byte{'A', 'B'}) {
			t.Errorf("Feed = %v, want [A B]", got)
		}
	})

	t.Run("split sub-negotiation across feeds", func(t *testing.T) {
		p := newServerIACParser()
		got1 := p.Feed([]byte{'A', iac, iacSB, optComPort})
		got2 := p.Feed([]byte{cpcSetBaudRate + 100, 0x00, 0x01, 0xC2, 0x00, iac, iacSE, 'B'})
		got := append(got1, got2...)
		if !bytes.Equal(got, []byte{'A', 'B'}) {
			t.Errorf("split Feed = %v, want [A B]", got)
		}
	})

	t.Run("escaped 0xff inside sub-negotiation", func(t *testing.T) {
		p := newServerIACParser()
		input := []byte{
			'A',
			iac, iacSB, optComPort, 99, 0xff, 0xff, /* escaped 0xff */
			iac, iacSE,
			'B',
		}
		got := p.Feed(input)
		if !bytes.Equal(got, []byte{'A', 'B'}) {
			t.Errorf("Feed = %v, want [A B]", got)
		}
	})
}

func TestBuildSetCommands(t *testing.T) {
	got := buildSetCommands(LineSettings{
		BaudRate: 115200, DataBits: 8, Parity: "N", StopBits: "1",
	})
	// SET-DATASIZE 8 + SET-PARITY N(1) + SET-STOPSIZE 1 + SET-BAUDRATE 115200
	want := []byte{
		iac, iacSB, optComPort, cpcSetDataSize, 8, iac, iacSE,
		iac, iacSB, optComPort, cpcSetParity, 1, iac, iacSE,
		iac, iacSB, optComPort, cpcSetStopSize, 1, iac, iacSE,
		iac, iacSB, optComPort, cpcSetBaudRate,
		0x00, 0x01, 0xC2, 0x00, // 115200 BE
		iac, iacSE,
	}
	if !bytes.Equal(got, want) {
		t.Errorf("buildSetCommands mismatch\n got = %x\nwant = %x", got, want)
	}
}

func TestBuildControlPacket(t *testing.T) {
	t.Run("DTR change emits one packet", func(t *testing.T) {
		got := buildControlPacket(
			ControlState{DTR: false, RTS: true},
			ControlState{DTR: true, RTS: true},
		)
		want := []byte{iac, iacSB, optComPort, cpcSetControl, ctrlSetDTROff, iac, iacSE}
		if !bytes.Equal(got, want) {
			t.Errorf("buildControlPacket = %x, want %x", got, want)
		}
	})

	t.Run("DTR + RTS change emits two packets, DTR first", func(t *testing.T) {
		got := buildControlPacket(
			ControlState{DTR: false, RTS: false},
			ControlState{DTR: true, RTS: true},
		)
		want := []byte{
			iac, iacSB, optComPort, cpcSetControl, ctrlSetDTROff, iac, iacSE,
			iac, iacSB, optComPort, cpcSetControl, ctrlSetRTSOff, iac, iacSE,
		}
		if !bytes.Equal(got, want) {
			t.Errorf("buildControlPacket = %x, want %x", got, want)
		}
	})

	t.Run("no change emits empty", func(t *testing.T) {
		got := buildControlPacket(
			ControlState{DTR: true, RTS: true},
			ControlState{DTR: true, RTS: true},
		)
		if len(got) != 0 {
			t.Errorf("buildControlPacket on no-change = %x, want empty", got)
		}
	})
}

func TestEncodeParityStopSize(t *testing.T) {
	parityCases := []struct {
		in   string
		want byte
	}{
		{"N", 1}, {"n", 1}, {"", 1},
		{"O", 2}, {"o", 2},
		{"E", 3}, {"e", 3},
		{"X", 1}, // unknown defaults to N
	}
	for _, c := range parityCases {
		if got := encodeParity(c.in); got != c.want {
			t.Errorf("encodeParity(%q) = %d, want %d", c.in, got, c.want)
		}
	}

	stopCases := []struct {
		in   string
		want byte
	}{
		{"1", 1}, {"", 1},
		{"2", 2},
		{"1.5", 3},
		{"X", 1},
	}
	for _, c := range stopCases {
		if got := encodeStopSize(c.in); got != c.want {
			t.Errorf("encodeStopSize(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	t.Run("empty PiHost rejected", func(t *testing.T) {
		c := Config{PiPort: 7700, Endpoint: stubEndpoint{}}
		if err := c.Validate(); err == nil {
			t.Error("Validate accepted empty PiHost")
		}
	})

	t.Run("invalid port rejected", func(t *testing.T) {
		c := Config{PiHost: "1.2.3.4", PiPort: 0, Endpoint: stubEndpoint{}}
		if err := c.Validate(); err == nil {
			t.Error("Validate accepted PiPort=0")
		}
		c.PiPort = 70000
		if err := c.Validate(); err == nil {
			t.Error("Validate accepted PiPort=70000")
		}
	})

	t.Run("nil endpoint rejected", func(t *testing.T) {
		c := Config{PiHost: "1.2.3.4", PiPort: 7700, Endpoint: nil}
		if err := c.Validate(); err == nil {
			t.Error("Validate accepted nil Endpoint")
		}
	})

	t.Run("happy path", func(t *testing.T) {
		c := Config{PiHost: "1.2.3.4", PiPort: 7700, Endpoint: stubEndpoint{}}
		if err := c.Validate(); err != nil {
			t.Errorf("Validate failed on valid config: %v", err)
		}
	})
}

type stubEndpoint struct{}

func (stubEndpoint) Read(_ []byte) (int, error)  { return 0, nil }
func (stubEndpoint) Write(_ []byte) (int, error) { return 0, nil }
func (stubEndpoint) Close() error                { return nil }
func (stubEndpoint) Path() string                { return "stub" }
func (stubEndpoint) PollControlChange(_ context.Context) (*ControlState, error) {
	return nil, nil
}

// pollCounterEndpoint counts PollControlChange calls and returns a
// constant non-nil snapshot. Asserts the producer doesn't spin past the
// configured ticker on synchronous endpoints (Windows path).
type pollCounterEndpoint struct {
	mu    sync.Mutex
	calls int
}

func (e *pollCounterEndpoint) Read(_ []byte) (int, error)  { return 0, nil }
func (e *pollCounterEndpoint) Write(_ []byte) (int, error) { return 0, nil }
func (e *pollCounterEndpoint) Close() error                { return nil }
func (e *pollCounterEndpoint) Path() string                { return "poll-counter" }
func (e *pollCounterEndpoint) PollControlChange(_ context.Context) (*ControlState, error) {
	e.mu.Lock()
	e.calls++
	e.mu.Unlock()
	return &ControlState{DTR: true, RTS: true}, nil
}
func (e *pollCounterEndpoint) Calls() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

// fakeConn is a no-op net.Conn for forwardModemControl tests.
type fakeConn struct{}

func (fakeConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (fakeConn) Write(p []byte) (int, error)        { return len(p), nil }
func (fakeConn) Close() error                       { return nil }
func (fakeConn) LocalAddr() net.Addr                { return fakeAddr{} }
func (fakeConn) RemoteAddr() net.Addr               { return fakeAddr{} }
func (fakeConn) SetDeadline(_ time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(_ time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(_ time.Time) error { return nil }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "fake" }
func (fakeAddr) String() string  { return "fake" }

// TestForwardModemControlRateLimit pins the regression where a
// synchronous PollControlChange used to `continue` past the ticker and
// pin a CPU core. Pre-fix produced 100k+ calls in this window.
func TestForwardModemControlRateLimit(t *testing.T) {
	ep := &pollCounterEndpoint{}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- forwardModemControl(ctx, ep, fakeConn{}, 10*time.Millisecond, NoopLogger{})
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("forwardModemControl did not return after ctx cancel")
	}

	calls := ep.Calls()
	// 200ms at 10ms cadence ≈ 20 polls. 100 leaves room for jitter.
	if calls > 100 {
		t.Errorf("forwardModemControl polled %d times in 200ms (expected <= 100); the rate limit regressed", calls)
	}
	if calls < 5 {
		t.Errorf("forwardModemControl polled only %d times in 200ms (expected at least 5); the ticker may not be firing", calls)
	}
}
