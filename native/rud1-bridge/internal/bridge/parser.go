package bridge

// serverIACParser strips IAC sequences from inbound TCP and returns the
// raw payload bytes. Mirrors rud1-fw's rfc2217.go but inverted.
type serverIACParser struct {
	state iacState
	cmd   byte
}

type iacState int

const (
	stateData iacState = iota
	stateIAC
	stateOption
	stateSubneg
	stateSubnegIAC
)

func newServerIACParser() *serverIACParser {
	return &serverIACParser{state: stateData}
}

// Feed pushes inbound bytes through the parser and returns payload
// bytes. State persists across calls so a sub-negotiation split across
// Reads still parses correctly.
func (p *serverIACParser) Feed(in []byte) []byte {
	out := in[:0:cap(in)]
	for _, b := range in {
		switch p.state {
		case stateData:
			if b == iac {
				p.state = stateIAC
				continue
			}
			out = append(out, b)

		case stateIAC:
			switch b {
			case iac:
				// Escaped 0xff — pass through as payload.
				out = append(out, iac)
				p.state = stateData
			case iacSB:
				p.state = stateOption
			case iacWill, iacWont, iacDo, iacDont:
				p.cmd = b
				p.state = stateOption
			default:
				// Unknown 1-byte verb (NOP/Break/etc.) — drop.
				p.state = stateData
			}

		case stateOption:
			if p.cmd == iacWill || p.cmd == iacWont || p.cmd == iacDo || p.cmd == iacDont {
				p.cmd = 0
				p.state = stateData
				continue
			}
			p.state = stateSubneg

		case stateSubneg:
			if b == iac {
				p.state = stateSubnegIAC
				continue
			}

		case stateSubnegIAC:
			if b == iacSE {
				p.state = stateData
			} else if b == iac {
				// Literal 0xff inside sub-negotiation; keep dropping.
				p.state = stateSubneg
			} else {
				p.state = stateData
			}
		}
	}
	return out
}
