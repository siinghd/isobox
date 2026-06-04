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

//go:embed llms.txt
var llmsTxt []byte

//go:embed openapi.yaml
var openapiYAML []byte

// Handler serves the playground at the path it is mounted on.
func Handler() http.HandlerFunc {
	return serve(indexHTML, "text/html; charset=utf-8")
}

// LLMs serves llms.txt — the agent-readable API description (llmstxt.org).
func LLMs() http.HandlerFunc { return serve(llmsTxt, "text/plain; charset=utf-8") }

// OpenAPI serves the OpenAPI 3.1 spec.
func OpenAPI() http.HandlerFunc { return serve(openapiYAML, "application/yaml") }

func serve(body []byte, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	}
}
