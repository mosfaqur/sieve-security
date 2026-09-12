package server

import (
	_ "embed"
	"net/http"
)

//go:embed index.html
var htmlDashboard []byte

func (s *Server) handleWebUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(htmlDashboard)
}
