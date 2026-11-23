package server

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/zngw/ssht/internal/store"
)

type ForwardView struct {
	store.Forward
	KeyName   string
	Status    string
	StatusErr string
	Conns     int32
}

type ForwardsPage struct {
	Active      string
	Forwards    []ForwardView
	Keys        []store.KeyEntry
	KeyNames    map[string]string
	Tags        []string
	SelectedTag string
	Edit        *store.Forward
	Error       string
	Message     string
}

func (a *App) handleForwards(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tag := q.Get("tag")
	editID := q.Get("edit")

	s := a.currentStore()
	if s == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	data := s.Snapshot()
	mgr := a.currentManager()

	keyNames := make(map[string]string, len(data.Keys))
	for _, k := range data.Keys {
		keyNames[k.ID] = k.Name
	}

	var list []ForwardView
	for _, f := range data.Forwards {
		if tag != "" && f.Tag != tag {
			continue
		}
		fv := ForwardView{Forward: f, KeyName: keyNames[f.KeyID], Status: "disconnected"}
		if mgr != nil {
			st := mgr.State(f.ID)
			fv.Status, fv.StatusErr, fv.Conns = st.Status, st.Err, st.Conns
		}
		list = append(list, fv)
	}

	var edit *store.Forward
	if editID != "" {
		for i := range data.Forwards {
			if data.Forwards[i].ID == editID {
				f := data.Forwards[i]
				edit = &f
				break
			}
		}
	}

	a.render(w, "forwards", "layout", ForwardsPage{
		Active:      "forwards",
		Forwards:    list,
		Keys:        data.Keys,
		KeyNames:    keyNames,
		Tags:        tagsOf(data),
		SelectedTag: tag,
		Edit:        edit,
		Error:       q.Get("error"),
		Message:     q.Get("msg"),
	})
}

func tagsOf(data store.StoreData) []string {
	seen := map[string]bool{}
	var tags []string
	for _, f := range data.Forwards {
		if f.Tag != "" && !seen[f.Tag] {
			seen[f.Tag] = true
			tags = append(tags, f.Tag)
		}
	}
	sort.Strings(tags)
	return tags
}

func redirectForwards(w http.ResponseWriter, r *http.Request, tag, errMsg, msg string) {
	target := "/?tag=" + url.QueryEscape(tag)
	if errMsg != "" {
		target += "&error=" + url.QueryEscape(errMsg)
	}
	if msg != "" {
		target += "&msg=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func parseForwardForm(r *http.Request) (store.Forward, string) {
	port, err := strconv.Atoi(strings.TrimSpace(r.FormValue("local_port")))
	if err != nil || port < 1 || port > 65535 {
		return store.Forward{}, "本地端口必须是 1-65535 的数字"
	}
	target := strings.TrimSpace(r.FormValue("target_addr"))
	if _, _, err := net.SplitHostPort(target); err != nil {
		return store.Forward{}, "远程目标地址格式不正确, 应为 host:port, 如 localhost:5432"
	}
	server := strings.TrimSpace(r.FormValue("server_addr"))
	if server == "" {
		return store.Forward{}, "请填写远程服务器地址"
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = server + ":22" // 默认 SSH 端口
	}
	user := strings.TrimSpace(r.FormValue("user"))
	if user == "" {
		return store.Forward{}, "请填写远程用户"
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		return store.Forward{}, "请填写名字"
	}
	pw := r.FormValue("password")
	keyID := r.FormValue("key_id")
	if pw == "" && keyID == "" {
		return store.Forward{}, "远程密码与远程密钥必须二选一"
	}
	if pw != "" && keyID != "" {
		return store.Forward{}, "远程密码与远程密钥只能二选一"
	}
	return store.Forward{
		ID:         strings.TrimSpace(r.FormValue("id")),
		Name:       name,
		Tag:        strings.TrimSpace(r.FormValue("tag")),
		LocalPort:  port,
		TargetAddr: target,
		ServerAddr: server,
		User:       user,
		Password:   pw,
		KeyID:      keyID,
	}, ""
}

func (a *App) handleForwardSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	tag := r.FormValue("tag_filter")
	f, errMsg := parseForwardForm(r)
	if errMsg != "" {
		redirectForwards(w, r, tag, errMsg, "")
		return
	}
	s := a.currentStore()
	if s == nil {
		redirectForwards(w, r, tag, "会话已失效，请重新登录", "")
		return
	}
	isNew := f.ID == ""
	if isNew {
		f.ID = store.NewID()
	}
	s.UpsertForward(f)
	if err := s.Save(); err != nil {
		redirectForwards(w, r, tag, "保存失败: "+err.Error(), "")
		return
	}
	if mgr := a.currentManager(); mgr != nil {
		mgr.Disconnect(f.ID) // 配置变更后如处于连接状态则先断开
	}
	if isNew {
		redirectForwards(w, r, tag, "", "已添加转发「"+f.Name+"」")
	} else {
		redirectForwards(w, r, tag, "", "已保存转发「"+f.Name+"」")
	}
}

func (a *App) handleForwardDelete(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	id := strings.TrimSpace(r.FormValue("id"))
	tag := r.FormValue("tag_filter")
	s := a.currentStore()
	if s == nil {
		redirectForwards(w, r, tag, "会话已失效，请重新登录", "")
		return
	}
	name := ""
	if f, ok := s.GetForward(id); ok {
		name = f.Name
	}
	if mgr := a.currentManager(); mgr != nil {
		mgr.Disconnect(id)
	}
	if !s.DeleteForward(id) {
		redirectForwards(w, r, tag, "未找到该转发", "")
		return
	}
	if err := s.Save(); err != nil {
		redirectForwards(w, r, tag, "保存失败: "+err.Error(), "")
		return
	}
	redirectForwards(w, r, tag, "", "已删除转发「"+name+"」")
}

func (a *App) handleForwardConnect(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	id := strings.TrimSpace(r.FormValue("id"))
	tag := r.FormValue("tag_filter")
	s := a.currentStore()
	if s == nil {
		redirectForwards(w, r, tag, "会话已失效，请重新登录", "")
		return
	}
	mgr := a.currentManager()
	if mgr == nil {
		redirectForwards(w, r, tag, "服务尚未就绪", "")
		return
	}
	f, ok := s.GetForward(id)
	if !ok {
		redirectForwards(w, r, tag, "未找到该转发", "")
		return
	}
	if err := mgr.Connect(f); err != nil {
		redirectForwards(w, r, tag, "连接失败: "+err.Error(), "")
		return
	}
	redirectForwards(w, r, tag, "", "已发起连接「"+f.Name+"」")
}

func (a *App) handleForwardDisconnect(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	id := strings.TrimSpace(r.FormValue("id"))
	tag := r.FormValue("tag_filter")
	if mgr := a.currentManager(); mgr != nil {
		mgr.Disconnect(id)
	}
	redirectForwards(w, r, tag, "", "已断开连接")
}

func (a *App) handleForwardBatch(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	action := r.FormValue("action")
	tag := r.FormValue("tag_filter")
	s := a.currentStore()
	if s == nil {
		redirectForwards(w, r, tag, "会话已失效，请重新登录", "")
		return
	}
	mgr := a.currentManager()
	if mgr == nil {
		redirectForwards(w, r, tag, "服务尚未就绪", "")
		return
	}
	okCount, failCount := 0, 0
	for _, id := range strings.Split(r.FormValue("ids"), ",") {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		f, found := s.GetForward(id)
		if !found {
			failCount++
			continue
		}
		if action == "connect" {
			if err := mgr.Connect(f); err != nil {
				failCount++
			} else {
				okCount++
			}
		} else {
			mgr.Disconnect(id)
			okCount++
		}
	}
	redirectForwards(w, r, tag, "", fmt.Sprintf("批量操作完成：成功 %d 条，失败 %d 条", okCount, failCount))
}
