// Package web serves the embedded single-page playground UI, so a single
// isoboxd binary ships both the API and a usable front end — no separate web
// root for self-hosters to deploy.
package web

import (
	_ "embed"
	"net/http"
)

//go:embed index.html
var indexHTML []byte

// Handler serves the playground at the path it is mounted on.
func Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(indexHTML)
	}
}
