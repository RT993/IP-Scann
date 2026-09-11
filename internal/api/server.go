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
}

// NewRouter builds the complete HTTP handler for the application: the
// embedded static frontend plus the JSON/SSE API it talks to.
func NewRouter() http.Handler {
	s := &Server{manager: newManager()}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(webui.FS())))

	mux.HandleFunc("GET /api/interfaces", s.handleInterfaces)
	mux.HandleFunc("POST /api/scan", s.handleScanStart)
	mux.HandleFunc("GET /api/scan/{id}", s.handleScanStatus)
	mux.HandleFunc("POST /api/scan/{id}/stop", s.handleScanStop)
	mux.HandleFunc("GET /api/scan/{id}/stream", s.handleScanStream)
	mux.HandleFunc("GET /api/scan/{id}/export.csv", s.handleScanExport)

	return mux
}
