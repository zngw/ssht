package server

import (
	"net/http"
	"os"
	"time"

	"github.com/zngw/ssht/internal/store"
)

type LoginPage struct {
	Mode  string // "login" | "setup"
	Hint  string
	Error string
}

func (a *App) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	if a.authed(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	s := a.currentStore()
	mode := "login"
	hint := ""
	if s == nil {
		if fileExists(a.dataPath) {
			mode = "login" // 数据文件存在但当前进程未解锁(如重启后)
		} else {
			mode = "setup" // 首次使用
		}
	} else {
		hint = s.Hint()
	}
	a.render(w, "login", "login", LoginPage{Mode: mode, Hint: hint})
}

func (a *App) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	pw := r.FormValue("password")
	if pw == "" {
		a.renderLoginError(w, "密码不能为空")
		return
	}

	s := a.currentStore()
	if s == nil {
		if fileExists(a.dataPath) {
			st, err := store.LoadStore(a.dataPath, pw)
			if err != nil {
				a.renderLoginError(w, err.Error())
				return
			}
			s = st
		} else {
			st, err := store.CreateStore(a.dataPath, pw)
			if err != nil {
				a.renderLoginError(w, "创建数据文件失败: "+err.Error())
				return
			}
			s = st
		}
		a.setStore(s)
	} else {
		if !s.VerifyPassword(pw) {
			a.renderLoginError(w, "密码错误")
			return
		}
		a.setStore(s) // 重建管理器, 重新开始
	}
	a.createSession(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *App) renderLoginError(w http.ResponseWriter, msg string) {
	mode := "login"
	hint := ""
	if s := a.currentStore(); s != nil {
		hint = s.Hint()
	} else if !fileExists(a.dataPath) {
		mode = "setup"
	}
	a.render(w, "login", "login", LoginPage{Mode: mode, Hint: hint, Error: msg})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	a.destroySession(w, r)
	a.stopAll()
	http.Redirect(w, r, "/login", http.StatusFound)
}

// handleReset 清空全部数据, 回到首次使用状态(忘记密码时的最后手段)
func (a *App) handleReset(w http.ResponseWriter, r *http.Request) {
	a.destroySession(w, r)
	a.stopAll()
	a.mu.Lock()
	a.store = nil
	a.mgr = nil
	a.sessions = map[string]time.Time{}
	a.mu.Unlock()
	_ = os.Remove(a.dataPath)
	_ = os.Remove(a.dataPath + ".tmp")
	http.Redirect(w, r, "/login", http.StatusFound)
}
