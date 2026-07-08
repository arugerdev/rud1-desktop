// rud1shim — generic flasher interceptor.
//
// Drop-in replacement for a CLI flasher (avrdude.exe, esptool.exe, …). When the
// target port belongs to a rud1 device it ships the identical invocation to an
// endpoint (the local rud1-desktop orchestrator in production, or a device's
// job-runner directly in the lab) which runs the real flasher next to the
// hardware at ~0ms — immune to WAN/VPN latency — and relays the log + exit code.
// For anything else it transparently passes through to the real flasher
// (<name>-real.exe), so non-rud1 uploads are never disturbed ("no molestar").
//
// Config file `rud1shim.json` next to the exe (see rud1shim.example.json).
// If it is missing, the endpoint is unreachable (desktop not running), or the
// endpoint replies {"handled":false}, the shim passes through — so when rud1 is
// not in use its behaviour is identical to not being installed at all.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type config struct {
	// Endpoint the job is POSTed to. Production: the desktop orchestrator
	// (http://127.0.0.1:<port>/flash). PiURL is a lab/direct-mode alias.
	Endpoint string            `json:"endpoint"`
	PiURL    string            `json:"pi_url"`
	Ports    map[string]string `json:"ports"`     // COMx -> busid (optional hint)
	Reattach bool              `json:"reattach"`  // lab mode: shim re-attaches
	UsbipExe string            `json:"usbip_exe"` // lab-mode re-attach
	PiHost   string            `json:"pi_host"`   // lab-mode re-attach (-r host)
}

func (c config) endpoint() string {
	if c.Endpoint != "" {
		return c.Endpoint
	}
	return c.PiURL
}

type job struct {
	ComPort string            `json:"comPort"`
	Busid   string            `json:"busid"`
	Tool    string            `json:"tool"`
	Argv    []string          `json:"argv"`
	Files   map[string]string `json:"files"`
}

type reply struct {
	Handled *bool  `json:"handled"` // absent => handled (device job-runner)
	RC      int    `json:"rc"`
	Log     string `json:"log"`
}

var (
	comRe   = regexp.MustCompile(`COM[0-9]+`)
	memOpRe = regexp.MustCompile(`^[A-Za-z0-9_]+:[rwvRWV]:`)
	fmtRe   = regexp.MustCompile(`^[A-Za-z]+$`)
)

func selfDir() string { p, _ := os.Executable(); return filepath.Dir(p) }

func loadConfig() config {
	var c config
	if b, err := os.ReadFile(filepath.Join(selfDir(), "rud1shim.json")); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	return c
}

// passthrough execs the real flasher (<name>-real.exe) unchanged and exits with
// its code. This is the default whenever rud1 is not involved.
func passthrough(logf *os.File) {
	name := filepath.Base(os.Args[0])
	real := strings.TrimSuffix(name, ".exe") + "-real"
	if strings.HasSuffix(strings.ToLower(name), ".exe") {
		real += ".exe"
	}
	if logf != nil {
		fmt.Fprintf(logf, "  -> passthrough %s\n", real)
	}
	cmd := exec.Command(filepath.Join(selfDir(), real), os.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "rud1shim passthrough error:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func isFile(p string) bool {
	if p == "" {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// extractFile finds an embedded local file in a flasher arg token and returns
// (file, tokenWithPlaceholder). Handles avrdude memory ops (attached -Uflash:w:
// FILE:fmt, with Windows drive-letter colons), attached flags (-CFILE), and
// bare file tokens.
func extractFile(tok, ph string) (string, string, bool) {
	lead, body := "", tok
	if strings.HasPrefix(tok, "-U") {
		lead, body = "-U", tok[2:]
	}
	if m := memOpRe.FindStringIndex(body); m != nil {
		prefix, rest := body[:m[1]], body[m[1]:]
		if i := strings.LastIndex(rest, ":"); i > 0 && fmtRe.MatchString(rest[i+1:]) && isFile(rest[:i]) {
			return rest[:i], lead + prefix + ph + rest[i:], true
		}
		if isFile(rest) {
			return rest, lead + prefix + ph, true
		}
	}
	if isFile(tok) {
		return tok, ph, true
	}
	if len(tok) > 2 && tok[0] == '-' && isFile(tok[2:]) {
		return tok[2:], tok[:2] + ph, true
	}
	return "", tok, false
}

func main() {
	logf, _ := os.OpenFile(filepath.Join(selfDir(), "rud1shim.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if logf != nil {
		defer logf.Close()
		fmt.Fprintf(logf, "\n[%s] argv=%q\n", time.Now().Format(time.RFC3339), os.Args)
	}
	cfg := loadConfig()

	comPort := ""
	for _, a := range os.Args[1:] {
		if m := comRe.FindString(a); m != "" {
			comPort = m
			break
		}
	}
	// Route only ports the desktop has registered as live rud1 devices; any
	// other port (or no config/endpoint) passes straight through, untouched.
	busid, known := cfg.Ports[comPort]
	if comPort == "" || !known || cfg.endpoint() == "" {
		passthrough(logf)
	}

	tool := strings.TrimSuffix(strings.ToLower(filepath.Base(os.Args[0])), ".exe")
	in := os.Args[1:]
	files := map[string]string{}
	argv := []string{filepath.Base(os.Args[0])}
	fi := 0
	for i := 0; i < len(in); i++ {
		tok := in[i]
		// avrdude -C is the HOST's config; the device runs its own — drop it.
		if tool == "avrdude" && strings.HasPrefix(tok, "-C") {
			if tok == "-C" {
				i++
			}
			continue
		}
		// PORT before file detection: on Windows "COM3" is itself a device file.
		if comRe.MatchString(tok) {
			argv = append(argv, comRe.ReplaceAllString(tok, "{{PORT}}"))
			continue
		}
		ph := fmt.Sprintf("{{F%d}}", fi)
		if f, newTok, ok := extractFile(tok, ph); ok {
			if b, err := os.ReadFile(f); err == nil {
				files[ph] = base64.StdEncoding.EncodeToString(b)
				argv = append(argv, newTok)
				fi++
				continue
			}
		}
		argv = append(argv, tok)
	}

	body, _ := json.Marshal(job{
		ComPort: comPort, Busid: busid, Tool: tool, Argv: argv, Files: files,
	})
	if logf != nil {
		fmt.Fprintf(logf, "  -> post %s comPort=%s busid=%s files=%d\n",
			cfg.endpoint(), comPort, busid, len(files))
	}

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Post(cfg.endpoint(), "application/json", bytes.NewReader(body))
	if err != nil {
		if logf != nil {
			fmt.Fprintf(logf, "  endpoint unreachable: %v\n", err)
		}
		passthrough(logf) // desktop not running / device offline → transparent
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var rep reply
	if err := json.Unmarshal(rb, &rep); err != nil {
		fmt.Fprintln(os.Stderr, "rud1: bad reply:", string(rb))
		os.Exit(1)
	}
	if rep.Handled != nil && !*rep.Handled {
		passthrough(logf) // orchestrator says: not a rud1 device
	}

	fmt.Fprintf(os.Stderr, "rud1: routing upload to %s (local flash, latency-immune)\n", comPort)
	if cfg.Reattach {
		reattach(cfg, busid, logf)
	}
	fmt.Print(rep.Log)
	if !strings.HasSuffix(rep.Log, "\n") {
		fmt.Println()
	}
	os.Exit(rep.RC)
}

// reattach re-attaches the usbip port after a lab/direct-mode flash (in
// production the desktop orchestrator owns attach/detach). Best-effort.
func reattach(cfg config, busid string, logf *os.File) {
	if busid == "" {
		return
	}
	exe := cfg.UsbipExe
	if exe == "" {
		exe = `C:\Program Files\USBip\usbip.exe`
	}
	host := cfg.PiHost
	if host == "" {
		host = strings.TrimPrefix(strings.TrimPrefix(cfg.endpoint(), "http://"), "https://")
		if i := strings.IndexAny(host, ":/"); i >= 0 {
			host = host[:i]
		}
	}
	for i := 0; i < 3; i++ {
		time.Sleep(1 * time.Second)
		out, err := exec.Command(exe, "attach", "-r", host, "-b", busid).CombinedOutput()
		if logf != nil {
			fmt.Fprintf(logf, "  reattach %d: err=%v out=%s\n", i, err, strings.TrimSpace(string(out)))
		}
		if err == nil || strings.Contains(strings.ToLower(string(out)), "already") {
			return
		}
	}
}
