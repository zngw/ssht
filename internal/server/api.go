package server

import (
	"encoding/json"
	"net/http"
)

// handleStatus 返回所有转发的实时状态, 供前端轮询刷新
func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	mgr := a.currentManager()
	if mgr == nil {
		_, _ = w.Write([]byte("[]"))
		return
	}
	_ = json.NewEncoder(w).Encode(mgr.AllStatus())
}
