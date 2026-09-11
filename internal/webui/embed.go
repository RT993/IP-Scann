// Package webui embeds the static frontend (HTML/CSS/JS) directly into the
// compiled binary so the whole application ships as a single executable.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed static
var embedded embed.FS

// FS returns the embedded frontend rooted at its own directory, ready to
// hand to http.FileServer.
func FS() fs.FS {
	sub, err := fs.Sub(embedded, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
