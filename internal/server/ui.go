package server

import (
	"embed"
	"net/http"
	"simplesecretsmanager/internal/version"
	"strings"
)

// Assets are compiled into the server; deployments need no separate web root.
//
//go:embed web/*
var assets embed.FS

func (s *Server) ui(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(405)
		return
	}
	file := "index.html"
	mime := "text/html; charset=utf-8"
	if r.URL.Path == "/app.js" || r.URL.Path == "/browse.js" {
		file = strings.TrimPrefix(r.URL.Path, "/")
		mime = "application/javascript"
	}
	if r.URL.Path == "/style.css" {
		file = "style.css"
		mime = "text/css"
	}
	b, e := assets.ReadFile("web/" + file)
	if e != nil {
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", mime)
	_, _ = w.Write([]byte(strings.ReplaceAll(string(b), "{{VERSION}}", version.Version)))
}
