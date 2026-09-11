package scanner

import (
	"bufio"
	"context"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// Hop is one line of a traceroute's output.
type Hop struct {
	Number   int     `json:"number"`
	IP       string  `json:"ip,omitempty"`
	RTTMs    float64 `json:"rttMs,omitempty"`
	TimedOut bool    `json:"timedOut"`
}

var (
	hopLineRe = regexp.MustCompile(`^\s*(\d+)\s+(.*)$`)
	hopIPRe   = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3})`)
	hopRTTRe  = regexp.MustCompile(`([\d.]+)\s*ms`)
)

// Traceroute runs the OS's traceroute binary and reports each hop through
// onHop as it's parsed, so the UI can show the path resolving live rather
// than waiting for the whole (possibly 20-30 second) run to finish. Both
// macOS's and Linux's traceroute run unprivileged by default (UDP probes),
// same rationale as shelling out to ping elsewhere in this package.
func Traceroute(ctx context.Context, ip string, maxHops int, onHop func(Hop)) error {
	if maxHops <= 0 || maxHops > 30 {
		maxHops = 20
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "tracert", "-d", "-h", strconv.Itoa(maxHops), ip)
	default:
		cmd = exec.CommandContext(ctx, "traceroute", "-n", "-m", strconv.Itoa(maxHops), "-w", "2", ip)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	s := bufio.NewScanner(stdout)
	for s.Scan() {
		hop, ok := parseHopLine(s.Text())
		if !ok {
			continue
		}
		onHop(hop)
		if hop.IP == ip {
			break
		}
	}
	_ = cmd.Wait()
	return nil
}

// parseHopLine extracts a Hop from one line of traceroute/tracert output,
// e.g. " 3  192.168.1.1  1.234 ms" or " 4  * * *" for a timed-out hop.
func parseHopLine(line string) (Hop, bool) {
	m := hopLineRe.FindStringSubmatch(line)
	if m == nil {
		return Hop{}, false
	}
	num, err := strconv.Atoi(m[1])
	if err != nil {
		return Hop{}, false
	}
	rest := m[2]
	hop := Hop{Number: num}

	if ipMatch := hopIPRe.FindStringSubmatch(rest); ipMatch != nil {
		hop.IP = ipMatch[1]
	} else if strings.Contains(rest, "*") {
		hop.TimedOut = true
	} else {
		return Hop{}, false
	}

	if rttMatch := hopRTTRe.FindStringSubmatch(rest); rttMatch != nil {
		if v, err := strconv.ParseFloat(rttMatch[1], 64); err == nil {
			hop.RTTMs = v
		}
	}
	return hop, true
}
