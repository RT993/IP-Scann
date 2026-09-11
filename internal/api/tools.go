package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/rt993/ip-scann/internal/netutil"
	"github.com/rt993/ip-scann/internal/scanner"
)

// validIP reports whether s is a literal IP address. Every tool handler
// that shells out to an external binary (ping, traceroute, nmap) with the
// client-supplied IP as one argv element uses this first: exec.Command
// never invokes a shell, so this isn't about shell injection, but a string
// like "-oN /tmp/x" would still be parsed as a flag by the target binary's
// own argument parser if passed through unchecked. A valid IP literal can
// never start with "-", which closes that off.
func validIP(s string) bool {
	return net.ParseIP(s) != nil
}

// ---------- Ping / latency ----------

type pingRequest struct {
	IP        string `json:"ip"`
	Count     int    `json:"count"`
	TimeoutMs int    `json:"timeoutMs"`
}

func (s *Server) handleToolPing(w http.ResponseWriter, r *http.Request) {
	var req pingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !validIP(req.IP) {
		writeError(w, http.StatusBadRequest, "a valid ip address is required")
		return
	}
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 700 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, scanner.Ping(ctx, req.IP, req.Count, timeout))
}

// ---------- OS guess ----------

type osGuessRequest struct {
	IP        string `json:"ip"`
	Vendor    string `json:"vendor,omitempty"`
	OpenPorts []int  `json:"openPorts,omitempty"`
	TTL       int    `json:"ttl,omitempty"`
}

func (s *Server) handleToolOSGuess(w http.ResponseWriter, r *http.Request) {
	var req osGuessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !validIP(req.IP) {
		writeError(w, http.StatusBadRequest, "a valid ip address is required")
		return
	}
	ttl := req.TTL
	if ttl <= 0 {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		ttl = scanner.Ping(ctx, req.IP, 1, 700*time.Millisecond).TTL
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ttl": ttl,
		"os":  scanner.GuessOS(ttl, req.Vendor, req.OpenPorts),
	})
}

// ---------- Port scan (on-demand, per host) ----------

type portScanRequest struct {
	IP    string `json:"ip"`
	Ports []int  `json:"ports,omitempty"`
}

type portResult struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
}

func (s *Server) handleToolPortScan(w http.ResponseWriter, r *http.Request) {
	var req portScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !validIP(req.IP) {
		writeError(w, http.StatusBadRequest, "a valid ip address is required")
		return
	}
	ports := req.Ports
	if len(ports) == 0 {
		ports = scanner.ExtendedPorts
	}
	if len(ports) > 4096 {
		writeError(w, http.StatusBadRequest, "too many ports requested")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	open := scanner.ScanPorts(ctx, req.IP, ports, 500*time.Millisecond)

	results := make([]portResult, 0, len(open))
	for _, p := range open {
		results = append(results, portResult{Port: p, Service: scanner.PortName(p)})
	}
	writeJSON(w, http.StatusOK, results)
}

// ---------- Service / version detection (banner grab) ----------

type serviceRequest struct {
	IP    string `json:"ip"`
	Ports []int  `json:"ports"`
}

func (s *Server) handleToolService(w http.ResponseWriter, r *http.Request) {
	var req serviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !validIP(req.IP) || len(req.Ports) == 0 {
		writeError(w, http.StatusBadRequest, "a valid ip address and ports are required")
		return
	}
	if len(req.Ports) > 64 {
		writeError(w, http.StatusBadRequest, "too many ports requested")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	results := make([]scanner.ServiceInfo, len(req.Ports))
	var wg sync.WaitGroup
	for i, p := range req.Ports {
		wg.Add(1)
		go func(i, port int) {
			defer wg.Done()
			results[i] = scanner.DetectService(ctx, req.IP, port, 2500*time.Millisecond)
		}(i, p)
	}
	wg.Wait()

	sort.Slice(results, func(a, b int) bool { return results[a].Port < results[b].Port })
	writeJSON(w, http.StatusOK, results)
}

// ---------- Traceroute ----------

type tracerouteRequest struct {
	IP string `json:"ip"`
}

func (s *Server) handleToolTracerouteStart(w http.ResponseWriter, r *http.Request) {
	var req tracerouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !validIP(req.IP) {
		writeError(w, http.StatusBadRequest, "a valid ip address is required")
		return
	}
	tj, err := s.tools.startTraceroute(req.IP)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": tj.id})
}

func (s *Server) handleToolTracerouteStream(w http.ResponseWriter, r *http.Request) {
	tj, ok := s.tools.getTraceroute(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "traceroute not found")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	tj.bc.subscribe(r.Context(), func(e tracerouteEvent) bool {
		data, err := json.Marshal(e)
		if err != nil {
			return true
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Type, data); err != nil {
			return false
		}
		flusher.Flush()
		return true
	})
}

// ---------- Deep scan (optional, nmap) ----------

type capabilitiesResponse struct {
	NmapAvailable bool `json:"nmapAvailable"`
	IsRoot        bool `json:"isRoot"`
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, capabilitiesResponse{
		NmapAvailable: scanner.NmapAvailable(),
		IsRoot:        scanner.IsRoot(),
	})
}

type deepScanRequest struct {
	IP             string `json:"ip"`
	ServiceVersion bool   `json:"serviceVersion"`
	OSDetection    bool   `json:"osDetection"`
}

func (s *Server) handleToolDeepScan(w http.ResponseWriter, r *http.Request) {
	var req deepScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !validIP(req.IP) {
		writeError(w, http.StatusBadRequest, "a valid ip address is required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	result, err := scanner.DeepScan(ctx, req.IP, scanner.DeepScanOptions{
		ServiceVersion: req.ServiceVersion,
		OSDetection:    req.OSDetection,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// ---------- Wake-on-LAN ----------

type wolRequest struct {
	MAC  string `json:"mac"`
	CIDR string `json:"cidr,omitempty"`
}

func (s *Server) handleToolWakeOnLAN(w http.ResponseWriter, r *http.Request) {
	var req wolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MAC == "" {
		writeError(w, http.StatusBadRequest, "mac is required")
		return
	}
	broadcast := ""
	if req.CIDR != "" {
		if b, err := netutil.BroadcastAddr(req.CIDR); err == nil {
			broadcast = b
		}
	}
	if err := scanner.WakeOnLAN(req.MAC, broadcast); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"sent": true})
}
