# SSH 端口转发管理系统

一个简单的 SSH 端口转发管理工具，把 `ssh -N -L` 命令集合到一个 Web 页面里，支持增删改查管理所有转发渠道。

## 特性

- 转发列表：名字 / Tag / 本地端口 / 远程地址端口 / 远程服务器 / 用户 / 密码或密钥（二选一）/ 实时状态，支持增删改查、勾选批量连接/断开、Tag 筛选
- 密钥管理：集中管理 SSH 私钥，转发配置直接引用
- 密码设置：修改密码、修改密码提示
- 无数据库：全部数据（密码提示 + 密钥 + 转发配置）JSON 序列化后用 **AES-256-GCM** 加密保存为二进制文件
- 密码即密钥：登录密码经 PBKDF2 派生加密密钥，密码错误无法解密；忘记密码只能重置数据
- 等价命令示例：`ssh -N -L 5432:localhost:5432 -i key root@192.168.1.55`

## 运行

```bash
go run ./cmd/ssht -addr 127.0.0.1:8080 -data ssht.dat
```

- `-addr`：HTTP 监听地址，默认 `127.0.0.1:8080`
- `-data`：加密数据文件路径，默认当前目录下的 `ssht.dat`

首次打开在登录页设置密码；之后每次打开输入密码解锁。所有转发连接保存在内存中，程序重启后需要重新点击连接。

## 目录结构

```
ssht/
├── cmd/
│   └── ssht/
│       └── main.go              # 入口：解析 -addr/-data，调用 server.Run
├── internal/
│   ├── crypto/
│   │   └── crypto.go            # PBKDF2 密钥派生 + AES-256-GCM 加解密
│   ├── store/
│   │   ├── model.go             # Forward / KeyEntry / StoreData 数据模型
│   │   ├── store.go             # 加密数据文件读写、内存数据 CRUD
│   │   └── store_test.go        # 存储层测试
│   ├── forward/
│   │   └── manager.go           # 端口转发运行时（SSH 拨号、监听、代理、状态）
│   └── server/
│       ├── embed.go             # go:embed 模板与静态资源
│       ├── server.go            # Run：路由、HTTP 服务、优雅关闭
│       ├── app.go               # App 状态、会话、鉴权、模板渲染
│       ├── handlers_auth.go     # 登录/退出/重置
│       ├── handlers_forward.go  # 转发 CRUD/连接/批量
│       ├── handlers_key.go      # 密钥管理
│       ├── handlers_password.go # 密码设置
│       ├── api.go               # /api/status JSON
│       ├── templates/           # 页面模板（登录/转发/密钥/密码）
│       └── static/style.css     # 样式
└── README.md
```

包依赖关系：`cmd/ssht` → `server` → `store` → `crypto`，`server` → `forward` → `store`，单向无循环。

## 数据文件

二进制格式：`魔数(9B) || salt(16B) || nonce(12B) || AES-256-GCM 密文`。
密码修改时会重新生成 salt 并整体重新加密。

## 注意

- 当前 SSH 主机密钥校验使用 `InsecureIgnoreHostKey`（首次连接不校验 known_hosts），如需严格校验可自行扩展
- 本地端口默认只监听 `127.0.0.1`，如需对外提供可修改 `internal/forward/manager.go` 中的监听地址
- 数据文件请自行备份；没有密码无法恢复任何数据
