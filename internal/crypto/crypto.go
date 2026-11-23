// Package crypto 提供数据文件加密: PBKDF2 密钥派生 + AES-256-GCM 加解密
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// SaltSize 盐长度
	SaltSize = 16
	// NonceSize GCM nonce 长度
	NonceSize = 12
	// KeySize AES-256 密钥长度
	KeySize = 32

	pbkdf2Iter = 100000
)

// NewSalt 生成随机盐
func NewSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// DeriveKey 由密码和盐派生 AES-256 密钥
func DeriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, pbkdf2Iter, KeySize, sha256.New)
}

// Encrypt 返回 nonce || ciphertext+tag
func Encrypt(plain []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

// Decrypt 解开 Encrypt 的输出
func Decrypt(data []byte, key []byte) ([]byte, error) {
	if len(data) < NonceSize {
		return nil, errors.New("密文长度不足")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, ct := data[:NonceSize], data[NonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}
