package api

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/rt993/ip-scann/internal/netutil"
	"github.com/rt993/ip-scann/internal/scanner"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := netutil.ListInterfaces()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ifaces)
}

func (s *Server) handleScanStart(w http.ResponseWriter, r *http.Request) {
	var opts scanner.Options
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	j, err := s.manager.start(opts)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": j.id})
}

func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	j, ok := s.manager.get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	writeJSON(w, http.StatusOK, j.snapshotStatus())
}

func (s *Server) handleScanStop(w http.ResponseWriter, r *http.Request) {
	j, ok := s.manager.get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	j.cancel()
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopping"})
}

func (s *Server) handleScanStream(w http.ResponseWriter, r *http.Request) {
	j, ok := s.manager.get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "scan not found")
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

	j.bc.subscribe(r.Context(), func(e scanner.Event) bool {
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

func (s *Server) handleScanExport(w http.ResponseWriter, r *http.Request) {
	j, ok := s.manager.get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	hosts := j.snapshotHosts()

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="ip-scan-`+j.id+`.csv"`)

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"IP", "Hostname", "MAC Address", "Vendor", "Latency (ms)", "Open Ports", "Detection", "Conflict"})
	for _, h := range hosts {
		ports := ""
		for i, p := range h.OpenPorts {
			if i > 0 {
				ports += ";"
			}
			ports += strconv.Itoa(p)
		}
		conflict := ""
		if h.Conflict {
			conflict = h.ConflictReason
		}
		_ = cw.Write([]string{
			h.IP, h.Hostname, h.MAC, h.Vendor,
			strconv.FormatFloat(h.LatencyMs, 'f', 1, 64),
			ports, h.Method, conflict,
		})
	}
	cw.Flush()
}
