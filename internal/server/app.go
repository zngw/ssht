// Package server 提供 Web 界面与 HTTP 接口
package server

import (
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/zngw/ssht/internal/forward"
	"github.com/zngw/ssht/internal/store"
)

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

const sessionCookie = "ssht_sid"
const sessionTTL = 24 * time.Hour

// App 保存全局运行时状态: 当前解锁的数据、转发管理器、会话
type App struct {
	mu       sync.Mutex
	dataPath string
	store    *store.Store
	mgr      *forward.Manager
	sessions map[string]time.Time
	tmpls    map[string]*template.Template
}

// NewApp 创建服务实例, 每个页面独立解析一套模板(layout + 页面), 避免公共 define 名冲突
func NewApp(dataPath string, funcs template.FuncMap) *App {
	mk := func(files ...string) *template.Template {
		return template.Must(template.New("").Funcs(funcs).ParseFS(embedFS, files...))
	}
	return &App{
		dataPath: dataPath,
		sessions: map[string]time.Time{},
		tmpls: map[string]*template.Template{
			"login":    mk("templates/login.html"),
			"forwards": mk("templates/layout.html", "templates/forwards.html"),
			"keys":     mk("templates/layout.html", "templates/keys.html"),
			"password": mk("templates/layout.html", "templates/password.html"),
		},
	}
}

// setStore 加载/切换数据, 同时重建转发管理器(旧的先全部断开)
func (a *App) setStore(s *store.Store) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mgr != nil {
		a.mgr.StopAll()
	}
	a.store = s
	a.mgr = forward.NewManager(s)
}

func (a *App) currentStore() *store.Store {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.store
}

func (a *App) currentManager() *forward.Manager {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.mgr
}

func (a *App) authed(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.sessions[c.Value]
	return ok && time.Now().Before(exp)
}

func (a *App) createSession(w http.ResponseWriter) {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	a.mu.Lock()
	a.sessions[token] = time.Now().Add(sessionTTL)
	now := time.Now()
	for k, exp := range a.sessions {
		if now.After(exp) {
			delete(a.sessions, k)
		}
	}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL / time.Second),
	})
}

func (a *App) destroySession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true})
}

// requireAuth 保护需要登录的页面和接口
func (a *App) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.authed(r) {
			next(w, r)
			return
		}
		if r.URL.Path == "/api/status" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`[{"status":"unauthorized"}]`))
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

// stopAll 停止所有转发(退出登录/重置/关服务时调用)
func (a *App) stopAll() {
	a.mu.Lock()
	mgr := a.mgr
	a.mu.Unlock()
	if mgr != nil {
		mgr.StopAll()
	}
}

func (a *App) render(w http.ResponseWriter, page, tplName string, data any) {
	t := a.tmpls[page]
	if t == nil {
		http.Error(w, "模板不存在: "+page, http.StatusInternalServerError)
		return
	}
	if err := t.ExecuteTemplate(w, tplName, data); err != nil {
		log.Printf("渲染模板 %s/%s 失败: %v", page, tplName, err)
	}
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"urlquery": url.QueryEscape,
		"statusText": func(s string) string {
			switch s {
			case "connected":
				return "已连接"
			case "connecting":
				return "连接中"
			case "error":
				return "连接失败"
			default:
				return "未连接"
			}
		},
	}
}
