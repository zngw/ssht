package server

import (
	"net/http"
	"net/url"
	"strings"
)

type PasswordPage struct {
	Active  string
	Hint    string
	Error   string
	Message string
}

func (a *App) handlePasswordPage(w http.ResponseWriter, r *http.Request) {
	s := a.currentStore()
	if s == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	q := r.URL.Query()
	a.render(w, "password", "layout", PasswordPage{
		Active:  "password",
		Hint:    s.Hint(),
		Error:   q.Get("error"),
		Message: q.Get("msg"),
	})
}

func (a *App) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	redirect := func(errMsg, msg string) {
		target := "/password"
		if errMsg != "" {
			target += "?error=" + url.QueryEscape(errMsg)
		} else if msg != "" {
			target += "?msg=" + url.QueryEscape(msg)
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
	}

	oldPw := r.FormValue("old_password")
	newPw := r.FormValue("new_password")
	confirmPw := r.FormValue("confirm_password")
	hint := strings.TrimSpace(r.FormValue("hint"))

	if newPw != confirmPw {
		redirect("两次输入的新密码不一致", "")
		return
	}
	if len([]rune(newPw)) < 6 {
		redirect("新密码至少 6 位", "")
		return
	}
	s := a.currentStore()
	if s == nil {
		redirect("会话已失效，请重新登录", "")
		return
	}
	if !s.VerifyPassword(oldPw) {
		redirect("原密码不正确", "")
		return
	}
	if err := s.ChangePassword(newPw, hint); err != nil {
		redirect("修改失败: "+err.Error(), "")
		return
	}
	redirect("", "密码已修改，下次登录请使用新密码")
}
