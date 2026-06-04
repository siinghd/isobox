// Package web serves the embedded single-page playground UI, so a single
// isoboxd binary ships both the API and a usable front end — no separate web
// root for self-hosters to deploy.
package web

import (
	"embed"
	_ "embed"
	"net/http"
	"path"
	"strings"
)

//go:embed index.html
var indexHTML []byte

//go:embed llms.txt
var llmsTxt []byte

//go:embed openapi.yaml
var openapiYAML []byte

// assetsFS holds the self-hosted flux-md bundle (JS + Web Worker + WASM + CSS)
// served at /assets/. Embedded at compile time, so a rebuild is required after
// the bundle changes. The worker + wasm filenames are load-bearing: flux-md.js
// references them by absolute /assets/ URL via new URL(asset, import.meta.url).
//
//go:embed assets/*
var assetsFS embed.FS

// Handler serves the playground at the path it is mounted on.
func Handler() http.HandlerFunc {
	return serve(indexHTML, "text/html; charset=utf-8")
}

// LLMs serves llms.txt — the agent-readable API description (llmstxt.org).
func LLMs() http.HandlerFunc { return serve(llmsTxt, "text/plain; charset=utf-8") }

// OpenAPI serves the OpenAPI 3.1 spec.
func OpenAPI() http.HandlerFunc { return serve(openapiYAML, "application/yaml") }

// Assets serves the embedded flux-md bundle under /assets/. It sets the
// Content-Type deterministically from the file extension rather than trusting
// the stdlib mime table, because two of these are runtime-critical for the
// browser: a .wasm must be application/wasm (WebAssembly.instantiateStreaming
// rejects any other type) and the module Web Worker .js must be text/javascript
// (a module worker won't load otherwise). embed.FS already rejects ".." paths,
// so directory traversal is not possible here.
func Assets() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/assets/")
		name = path.Clean(name)
		if name == "." || name == "/" || strings.Contains(name, "..") {
			http.NotFound(w, r)
			return
		}
		body, err := assetsFS.ReadFile("assets/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", assetContentType(name))
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(body)
	}
}

// assetContentType maps an asset filename to its MIME type. The .wasm and module
// .js entries are load-bearing for the flux-md runtime (see Assets).
func assetContentType(name string) string {
	switch {
	case strings.HasSuffix(name, ".wasm"):
		return "application/wasm"
	case strings.HasSuffix(name, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".json"):
		return "application/json"
	case strings.HasSuffix(name, ".map"):
		return "application/json"
	default:
		return "application/octet-stream"
	}
}

func serve(body []byte, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	}
}
