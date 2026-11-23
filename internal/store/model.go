package store

// KeyEntry 是受管理的 SSH 私钥，供转发配置引用
type KeyEntry struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Content   string `json:"content"`
	CreatedAt int64  `json:"created_at"`
}

// Forward 是一条端口转发配置，等价于:
//
//	ssh -N -L <LocalPort>:<TargetAddr> <User>@<ServerAddr>
//
// 认证方式: Password 与 KeyID 二选一
type Forward struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Tag        string `json:"tag"`
	LocalPort  int    `json:"local_port"`
	TargetAddr string `json:"target_addr"` // 远端目标, 如 localhost:5432
	ServerAddr string `json:"server_addr"` // SSH 服务器, 如 39.99.158.61:22
	User       string `json:"user"`
	Password   string `json:"password"`
	KeyID      string `json:"key_id"`
}

// StoreData 是加密存储到磁盘的完整数据
type StoreData struct {
	Hint     string     `json:"hint"`
	Keys     []KeyEntry `json:"keys"`
	Forwards []Forward  `json:"forwards"`
}

// AuthLabel 返回认证方式的展示文本
func (f Forward) AuthLabel(keyNames map[string]string) string {
	if f.KeyID != "" {
		if n, ok := keyNames[f.KeyID]; ok && n != "" {
			return "密钥: " + n
		}
		return "密钥(已删除)"
	}
	if f.Password != "" {
		return "密码"
	}
	return "未设置"
}
