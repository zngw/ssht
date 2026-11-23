// Package store 负责加密数据文件的读写与内存数据管理(密码提示/密钥/转发配置)
package store

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/zngw/ssht/internal/crypto"
)

// 文件布局: 魔数 "SSHTFDAT1" || salt(16) || nonce(12) || AES-GCM 密文
const fileMagic = "SSHTFDAT1"

// ErrWrongPassword 密码错误或数据文件损坏时返回
var ErrWrongPassword = errors.New("密码错误或数据文件已损坏")

// Store 是加密数据文件的内存表示
type Store struct {
	mu       sync.Mutex
	path     string
	password string
	salt     []byte
	Data     StoreData
}

// NewID 生成随机 ID
func NewID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// LoadStore 用密码打开已存在的数据文件, 密码错误时返回 ErrWrongPassword
func LoadStore(path, password string) (*Store, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) < len(fileMagic)+crypto.SaltSize+crypto.NonceSize || string(raw[:len(fileMagic)]) != fileMagic {
		return nil, errors.New("数据文件格式不正确")
	}
	salt := cloneBytes(raw[len(fileMagic) : len(fileMagic)+crypto.SaltSize])
	plain, err := crypto.Decrypt(raw[len(fileMagic)+crypto.SaltSize:], crypto.DeriveKey(password, salt))
	if err != nil {
		return nil, ErrWrongPassword
	}
	var d StoreData
	if err := json.Unmarshal(plain, &d); err != nil {
		return nil, fmt.Errorf("数据解析失败: %w", err)
	}
	return &Store{path: path, password: password, salt: salt, Data: d}, nil
}

// CreateStore 创建全新的数据文件
func CreateStore(path, password string) (*Store, error) {
	salt, err := crypto.NewSalt()
	if err != nil {
		return nil, err
	}
	s := &Store{
		path:     path,
		password: password,
		salt:     salt,
		Data:     StoreData{Keys: []KeyEntry{}, Forwards: []Forward{}},
	}
	if err := s.Save(); err != nil {
		return nil, err
	}
	return s, nil
}

func cloneBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// Save 加密并原子写入数据文件
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

// saveLocked 先写临时文件再原子替换, 避免写入中断导致数据损坏
func (s *Store) saveLocked() error {
	plain, err := json.Marshal(s.Data)
	if err != nil {
		return err
	}
	ct, err := crypto.Encrypt(plain, crypto.DeriveKey(s.password, s.salt))
	if err != nil {
		return err
	}
	out := make([]byte, 0, len(fileMagic)+crypto.SaltSize+len(ct))
	out = append(out, fileMagic...)
	out = append(out, s.salt...)
	out = append(out, ct...)

	dir := filepath.Dir(s.path)
	tmp := filepath.Join(dir, "."+filepath.Base(s.path)+".tmp")
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	_ = os.Remove(s.path) // Windows 下 rename 不能覆盖已存在文件
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// ChangePassword 修改密码(及密码提示), 重新生成盐并整体重新加密
func (s *Store) ChangePassword(newPassword, hint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	salt, err := crypto.NewSalt()
	if err != nil {
		return err
	}
	s.salt = salt
	s.password = newPassword
	s.Data.Hint = hint
	return s.saveLocked()
}

// VerifyPassword 校验密码是否正确
func (s *Store) VerifyPassword(pw string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return subtle.ConstantTimeCompare([]byte(pw), []byte(s.password)) == 1
}

// Hint 返回密码提示
func (s *Store) Hint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Data.Hint
}

// GetKey 按 ID 查找密钥
func (s *Store) GetKey(id string) (KeyEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.Data.Keys {
		if k.ID == id {
			return k, true
		}
	}
	return KeyEntry{}, false
}

// GetForward 按 ID 查找转发配置
func (s *Store) GetForward(id string) (Forward, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.Data.Forwards {
		if f.ID == id {
			return f, true
		}
	}
	return Forward{}, false
}

// UpsertForward 新增或更新转发配置
func (s *Store) UpsertForward(f Forward) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.ID == "" {
		f.ID = NewID()
	}
	for i := range s.Data.Forwards {
		if s.Data.Forwards[i].ID == f.ID {
			s.Data.Forwards[i] = f
			return
		}
	}
	s.Data.Forwards = append(s.Data.Forwards, f)
}

// DeleteForward 删除转发配置
func (s *Store) DeleteForward(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Data.Forwards {
		if s.Data.Forwards[i].ID == id {
			s.Data.Forwards = append(s.Data.Forwards[:i], s.Data.Forwards[i+1:]...)
			return true
		}
	}
	return false
}

// UpsertKey 新增或更新密钥
func (s *Store) UpsertKey(k KeyEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k.ID == "" {
		k.ID = NewID()
		if k.CreatedAt == 0 {
			k.CreatedAt = time.Now().Unix()
		}
	}
	for i := range s.Data.Keys {
		if s.Data.Keys[i].ID == k.ID {
			s.Data.Keys[i] = k
			return
		}
	}
	s.Data.Keys = append(s.Data.Keys, k)
}

// DeleteKey 删除密钥
func (s *Store) DeleteKey(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Data.Keys {
		if s.Data.Keys[i].ID == id {
			s.Data.Keys = append(s.Data.Keys[:i], s.Data.Keys[i+1:]...)
			return true
		}
	}
	return false
}

// KeyUsageCount 统计密钥被多少条转发引用
func (s *Store) KeyUsageCount(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, f := range s.Data.Forwards {
		if f.KeyID == id {
			n++
		}
	}
	return n
}

// Snapshot 返回当前数据的副本, 减少锁持有时间
func (s *Store) Snapshot() StoreData {
	s.mu.Lock()
	defer s.mu.Unlock()
	return StoreData{
		Hint:     s.Data.Hint,
		Keys:     append([]KeyEntry(nil), s.Data.Keys...),
		Forwards: append([]Forward(nil), s.Data.Forwards...),
	}
}
