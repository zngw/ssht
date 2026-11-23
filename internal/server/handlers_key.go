package server

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/zngw/ssht/internal/store"
)

type KeyView struct {
	store.KeyEntry
	UsedBy      int
	CreatedText string
}

type KeysPage struct {
	Active  string
	Keys    []KeyView
	Edit    *store.KeyEntry
	Error   string
	Message string
}

func redirectKeys(w http.ResponseWriter, r *http.Request, errMsg, msg string) {
	target := "/keys"
	if errMsg != "" {
		target += "?error=" + url.QueryEscape(errMsg)
	} else if msg != "" {
		target += "?msg=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (a *App) handleKeys(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s := a.currentStore()
	if s == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	data := s.Snapshot()

	var list []KeyView
	for _, k := range data.Keys {
		used := 0
		for _, f := range data.Forwards {
			if f.KeyID == k.ID {
				used++
			}
		}
		text := ""
		if k.CreatedAt > 0 {
			text = time.Unix(k.CreatedAt, 0).Format("2006-01-02 15:04:05")
		}
		list = append(list, KeyView{KeyEntry: k, UsedBy: used, CreatedText: text})
	}

	var edit *store.KeyEntry
	if id := q.Get("edit"); id != "" {
		for i := range data.Keys {
			if data.Keys[i].ID == id {
				k := data.Keys[i]
				edit = &k
				break
			}
		}
	}

	a.render(w, "keys", "layout", KeysPage{
		Active:  "keys",
		Keys:    list,
		Edit:    edit,
		Error:   q.Get("error"),
		Message: q.Get("msg"),
	})
}

func (a *App) handleKeySave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	id := strings.TrimSpace(r.FormValue("id"))
	name := strings.TrimSpace(r.FormValue("name"))
	content := strings.TrimSpace(r.FormValue("content"))
	if name == "" || content == "" {
		redirectKeys(w, r, "密钥名称和内容不能为空", "")
		return
	}
	if !strings.Contains(content, "PRIVATE KEY") {
		redirectKeys(w, r, "内容不像有效的私钥（应包含 PRIVATE KEY 字样）", "")
		return
	}
	if _, err := ssh.ParsePrivateKey([]byte(content)); err != nil {
		redirectKeys(w, r, "私钥解析失败: "+err.Error(), "")
		return
	}
	s := a.currentStore()
	if s == nil {
		redirectKeys(w, r, "会话已失效，请重新登录", "")
		return
	}
	created := time.Now().Unix()
	if id != "" {
		if old, ok := s.GetKey(id); ok {
			created = old.CreatedAt
		}
	}
	s.UpsertKey(store.KeyEntry{ID: id, Name: name, Content: content, CreatedAt: created})
	if err := s.Save(); err != nil {
		redirectKeys(w, r, "保存失败: "+err.Error(), "")
		return
	}
	if id == "" {
		redirectKeys(w, r, "", "已添加密钥「"+name+"」")
	} else {
		redirectKeys(w, r, "", "已保存密钥「"+name+"」")
	}
}

func (a *App) handleKeyDelete(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	id := strings.TrimSpace(r.FormValue("id"))
	s := a.currentStore()
	if s == nil {
		redirectKeys(w, r, "会话已失效，请重新登录", "")
		return
	}
	name := ""
	if k, ok := s.GetKey(id); ok {
		name = k.Name
	}
	if n := s.KeyUsageCount(id); n > 0 {
		redirectKeys(w, r, "该密钥正被 "+strconv.Itoa(n)+" 条转发使用，请先修改这些转发", "")
		return
	}
	if !s.DeleteKey(id) {
		redirectKeys(w, r, "未找到该密钥", "")
		return
	}
	if err := s.Save(); err != nil {
		redirectKeys(w, r, "保存失败: "+err.Error(), "")
		return
	}
	redirectKeys(w, r, "", "已删除密钥「"+name+"」")
}
