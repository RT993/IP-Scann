// Package api wires up the HTTP surface: the embedded web UI plus the JSON
// and Server-Sent Events endpoints the frontend uses to drive scans.
package api

import (
	"net/http"

	"github.com/rt993/ip-scann/internal/webui"
)

// Server holds the shared state behind every HTTP handler.
type Server struct {
	manager *manager
	tools   *toolsManager
}

// NewRouter builds the complete HTTP handler for the application: the
// embedded static frontend plus the JSON/SSE API it talks to.
func NewRouter() http.Handler {
	s := &Server{manager: newManager(), tools: newToolsManager()}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(webui.FS())))

	mux.HandleFunc("GET /api/interfaces", s.handleInterfaces)
	mux.HandleFunc("POST /api/scan", s.handleScanStart)
	mux.HandleFunc("GET /api/scan/{id}", s.handleScanStatus)
	mux.HandleFunc("POST /api/scan/{id}/stop", s.handleScanStop)
	mux.HandleFunc("GET /api/scan/{id}/stream", s.handleScanStream)
	mux.HandleFunc("GET /api/scan/{id}/export.csv", s.handleScanExport)

	mux.HandleFunc("GET /api/capabilities", s.handleCapabilities)

	// Per-host, on-demand diagnostic tools.
	mux.HandleFunc("POST /api/tools/ping", s.handleToolPing)
	mux.HandleFunc("POST /api/tools/osguess", s.handleToolOSGuess)
	mux.HandleFunc("POST /api/tools/portscan", s.handleToolPortScan)
	mux.HandleFunc("POST /api/tools/service", s.handleToolService)
	mux.HandleFunc("POST /api/tools/traceroute", s.handleToolTracerouteStart)
	mux.HandleFunc("GET /api/tools/traceroute/{id}/stream", s.handleToolTracerouteStream)
	mux.HandleFunc("POST /api/tools/deepscan", s.handleToolDeepScan)
	mux.HandleFunc("POST /api/tools/wol", s.handleToolWakeOnLAN)

	return mux
}
