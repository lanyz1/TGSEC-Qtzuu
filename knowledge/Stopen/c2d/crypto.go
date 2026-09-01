package main

// C2 通信加密 —— 与 Python 端 C2Encryption 逐字节兼容
//
// AES-256-CTR: ciphertext = base64(iv(16) || AES-CTR(key, plaintext))，key 为 hex 解码后的 32 字节
// XOR:         ciphertext = base64(plaintext XOR key_ascii[:32])，key 直接按 ASCII 字节循环使用
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	encAES = "aes-256-ctr"
	encXOR = "xor"
)

// validAESKeyLen 与 Python 端一致：128/192/256 位密钥均可用
// （db.create_listener 生成 32 位 hex = AES-128，手动生成器为 64 位 hex = AES-256）
func validAESKey(keyHex string) ([]byte, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("密钥必须是 hex: %v", err)
	}
	switch len(key) {
	case 16, 24, 32:
		return key, nil
	default:
		return nil, fmt.Errorf("密钥长度必须为 16/24/32 字节, got %d", len(key))
	}
}

func Encrypt(plaintext, keyHex, encType string) (string, error) {
	switch encType {
	case encXOR:
		return base64.StdEncoding.EncodeToString(xorCrypt([]byte(plaintext), xorKey(keyHex))), nil
	default: // aes-256-ctr（兼容 128/192 位密钥）
		key, err := validAESKey(keyHex)
		if err != nil {
			return "", err
		}
		iv := make([]byte, 16)
		if _, err := rand.Read(iv); err != nil {
			return "", err
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", err
		}
		ct := make([]byte, len(plaintext))
		cipher.NewCTR(block, iv).XORKeyStream(ct, []byte(plaintext))
		return base64.StdEncoding.EncodeToString(append(iv, ct...)), nil
	}
}

func Decrypt(cipherB64, keyHex, encType string) (string, error) {
	switch encType {
	case encXOR:
		raw, err := base64.StdEncoding.DecodeString(cipherB64)
		if err != nil {
			return "", err
		}
		return string(xorCrypt(raw, xorKey(keyHex))), nil
	default: // aes-256-ctr（兼容 128/192 位密钥）
		key, err := validAESKey(keyHex)
		if err != nil {
			return "", err
		}
		raw, err := base64.StdEncoding.DecodeString(cipherB64)
		if err != nil {
			return "", err
		}
		if len(raw) < 16 {
			return "", errors.New("密文过短（缺少 IV）")
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", err
		}
		pt := make([]byte, len(raw)-16)
		cipher.NewCTR(block, raw[:16]).XORKeyStream(pt, raw[16:])
		return string(pt), nil
	}
}

// xorKey 与 Python 实现一致：key_hex 字符串的 ASCII 字节，循环取前 32 字节
func xorKey(keyHex string) []byte {
	k := []byte(keyHex)
	if len(k) > 32 {
		k = k[:32]
	}
	return k
}

func xorCrypt(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}
