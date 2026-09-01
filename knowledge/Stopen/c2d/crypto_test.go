package main

// 跨语言加密一致性测试 —— 向量由 Python 端 cryptography 库生成
import (
	"bytes"
	"testing"
)

const testKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// Python: AES-256-CTR, key=hex(testKey), iv=000102...0f, plaintext="hello stopen"
const pyAESVector = "AAECAwQFBgcICQoLDA0OD18G1NnPSap2ABIQAg=="

// Python: XOR, key_ascii(testKey[:32]), plaintext="hello stopen"
const pyXORVector = "WFReX1sVRUNXSQQM"

func TestDecryptPythonAESVector(t *testing.T) {
	pt, err := Decrypt(pyAESVector, testKey, encAES)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if pt != "hello stopen" {
		t.Fatalf("AES 向量不匹配: %q", pt)
	}
}

func TestDecryptPythonXORVector(t *testing.T) {
	pt, err := Decrypt(pyXORVector, testKey, encXOR)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if pt != "hello stopen" {
		t.Fatalf("XOR 向量不匹配: %q", pt)
	}
}

func TestAESRoundTrip(t *testing.T) {
	msgs := []string{"{}", `{"type":"exec","command":"whoami"}`, "中文内容", string(bytes.Repeat([]byte("x"), 10000))}
	for _, m := range msgs {
		ct, err := Encrypt(m, testKey, encAES)
		if err != nil {
			t.Fatalf("加密失败: %v", err)
		}
		pt, err := Decrypt(ct, testKey, encAES)
		if err != nil || pt != m {
			t.Fatalf("AES 往返失败: %v", err)
		}
	}
}

func TestXORRoundTrip(t *testing.T) {
	for _, m := range []string{"{}", "heartbeat", "中文"} {
		ct, err := Encrypt(m, testKey, encXOR)
		if err != nil {
			t.Fatalf("加密失败: %v", err)
		}
		pt, err := Decrypt(ct, testKey, encXOR)
		if err != nil || pt != m {
			t.Fatalf("XOR 往返失败: %v", err)
		}
	}
}

func TestEncryptIVIsRandom(t *testing.T) {
	a, _ := Encrypt("same", testKey, encAES)
	b, _ := Encrypt("same", testKey, encAES)
	if a == b {
		t.Fatal("两次加密的 IV 相同，随机性缺失")
	}
}

func TestBadKeyRejected(t *testing.T) {
	if _, err := Encrypt("x", "not-hex", encAES); err == nil {
		t.Fatal("非 hex 密钥应被拒绝")
	}
	if _, err := Decrypt("AAAA", testKey, encAES); err == nil {
		t.Fatal("过短密文应被拒绝")
	}
}
