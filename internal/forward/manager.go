// Package forward 管理端口转发的运行时连接(纯内存, 重启后全部断开)
package forward

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/zngw/ssht/internal/store"
)

// ConnState 是一条转发的运行时状态
type ConnState struct {
	Status string // connecting / connected / disconnected / error
	Err    string
	Conns  int32 // 正在代理的活动连接数
	stop   func()
}

// StatusItem 是返回给前端 JSON 的状态
type StatusItem struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tag    string `json:"tag"`
	Status string `json:"status"`
	Err    string `json:"err"`
	Conns  int32  `json:"conns"`
}

// Manager 管理所有端口转发连接
type Manager struct {
	mu     sync.Mutex
	store  *store.Store
	states map[string]*ConnState
}

// NewManager 绑定数据存储创建转发管理器
func NewManager(s *store.Store) *Manager {
	return &Manager{store: s, states: make(map[string]*ConnState)}
}

// State 返回某条转发的当前状态快照
func (m *Manager) State(id string) ConnState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st, ok := m.states[id]; ok {
		return ConnState{Status: st.Status, Err: st.Err, Conns: atomic.LoadInt32(&st.Conns)}
	}
	return ConnState{Status: "disconnected"}
}

func (m *Manager) setState(id string, status, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st, ok := m.states[id]; ok {
		st.Status = status
		st.Err = errMsg
	}
}

// AllStatus 返回所有转发的状态列表
func (m *Manager) AllStatus() []StatusItem {
	data := m.store.Snapshot()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]StatusItem, 0, len(data.Forwards))
	for _, f := range data.Forwards {
		item := StatusItem{ID: f.ID, Name: f.Name, Tag: f.Tag, Status: "disconnected"}
		if st, ok := m.states[f.ID]; ok {
			item.Status = st.Status
			item.Err = st.Err
			item.Conns = atomic.LoadInt32(&st.Conns)
		}
		out = append(out, item)
	}
	return out
}

// Connect 建立一条端口转发, 等价于 ssh -N -L LocalPort:TargetAddr User@ServerAddr
func (m *Manager) Connect(f store.Forward) error {
	m.mu.Lock()
	if st, ok := m.states[f.ID]; ok && (st.Status == "connected" || st.Status == "connecting") {
		m.mu.Unlock()
		return errors.New("该转发已处于连接状态")
	}
	m.states[f.ID] = &ConnState{Status: "connecting"}
	m.mu.Unlock()

	auth, err := m.authFor(f)
	if err != nil {
		m.setState(f.ID, "error", err.Error())
		return err
	}

	cfg := &ssh.ClientConfig{
		User:            f.User,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 简化处理; 如需校验主机密钥可改为 known_hosts 方案
		Timeout:         15 * time.Second,
	}
	client, err := ssh.Dial("tcp", f.ServerAddr, cfg)
	if err != nil {
		m.setState(f.ID, "error", "SSH 连接失败: "+err.Error())
		return err
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", f.LocalPort))
	if err != nil {
		_ = client.Close()
		m.setState(f.ID, "error", "本地端口监听失败: "+err.Error())
		return err
	}

	m.mu.Lock()
	st, ok := m.states[f.ID]
	if !ok {
		// 连接建立期间该转发被删除或断开
		m.mu.Unlock()
		_ = ln.Close()
		_ = client.Close()
		return errors.New("转发已被删除或断开")
	}
	st.Status = "connected"
	st.Err = ""
	st.stop = func() {
		_ = ln.Close()
		_ = client.Close()
	}
	m.mu.Unlock()

	go m.serve(st, client, ln, f.TargetAddr)
	return nil
}

// serve 接受本地连接并通过 SSH 隧道转发到远端目标
func (m *Manager) serve(st *ConnState, client *ssh.Client, ln net.Listener, target string) {
	defer func() {
		_ = ln.Close()
		_ = client.Close()
		m.mu.Lock()
		st.Status = "disconnected"
		st.Err = ""
		st.stop = nil
		m.mu.Unlock()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			atomic.AddInt32(&st.Conns, 1)
			defer atomic.AddInt32(&st.Conns, -1)
			remote, err := client.Dial("tcp", target)
			if err != nil {
				_ = conn.Close()
				return
			}
			proxy(conn, remote)
		}()
	}
}

// Disconnect 断开一条转发
func (m *Manager) Disconnect(id string) {
	m.mu.Lock()
	st := m.states[id]
	if st != nil {
		if st.stop != nil {
			st.stop()
		}
		delete(m.states, id)
	}
	m.mu.Unlock()
}

// StopAll 断开全部转发(退出登录/重置/关服务时调用)
func (m *Manager) StopAll() {
	m.mu.Lock()
	states := make([]*ConnState, 0, len(m.states))
	for _, st := range m.states {
		states = append(states, st)
	}
	m.mu.Unlock()
	for _, st := range states {
		m.mu.Lock()
		if st.stop != nil {
			st.stop()
		}
		m.mu.Unlock()
	}
}

func (m *Manager) authFor(f store.Forward) (ssh.AuthMethod, error) {
	if f.KeyID != "" {
		k, ok := m.store.GetKey(f.KeyID)
		if !ok {
			return nil, errors.New("所选密钥不存在")
		}
		signer, err := ssh.ParsePrivateKey([]byte(k.Content))
		if err != nil {
			return nil, fmt.Errorf("密钥解析失败: %w", err)
		}
		return ssh.PublicKeys(signer), nil
	}
	if f.Password != "" {
		return ssh.Password(f.Password), nil
	}
	return nil, errors.New("未配置认证方式(密码或密钥二选一)")
}

// proxy 在两个连接之间双向复制数据
func proxy(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		closeWrite(a)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		closeWrite(b)
	}()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

func closeWrite(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
}
