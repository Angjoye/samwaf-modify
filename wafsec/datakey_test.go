package wafsec

import (
	"path/filepath"
	"testing"
)

// legacyKey 模拟旧的全实例共用通讯密钥（16 字节 AES-128）。
var legacyKey = []byte("7E@u*has$d*@s5YX")

// setupDataKey 在临时目录初始化一把全新的 DEK，供各用例使用。
// 因 InitDataKey 用 sync.Once，测试里直接给 dataKey 赋值绕过 Once。
func setupDataKey(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	key, err := loadOrCreateDataKey(filepath.Join(dir, ".keys", "data_key"))
	if err != nil {
		t.Fatalf("loadOrCreateDataKey: %v", err)
	}
	dataKeyMu.Lock()
	dataKey = key
	dataKeyMu.Unlock()
}

func TestDataEncryptRoundTrip(t *testing.T) {
	setupDataKey(t)
	plain := "s3cr3t-TOTP-KEY-你好"
	enc, err := DataEncrypt(plain)
	if err != nil {
		t.Fatalf("DataEncrypt: %v", err)
	}
	if !IsDataKeyCiphertext(enc) {
		t.Fatalf("密文应带 swk1 前缀: %q", enc)
	}
	got, err := DataDecrypt(enc, legacyKey)
	if err != nil {
		t.Fatalf("DataDecrypt: %v", err)
	}
	if got != plain {
		t.Fatalf("往返不一致: got %q want %q", got, plain)
	}
}

func TestDataEncryptEmpty(t *testing.T) {
	setupDataKey(t)
	if enc, _ := DataEncrypt(""); enc != "" {
		t.Fatalf("空串应原样返回空: %q", enc)
	}
	if dec, _ := DataDecrypt("", legacyKey); dec != "" {
		t.Fatalf("空串应原样返回空: %q", dec)
	}
}

func TestDataEncryptNonceUnique(t *testing.T) {
	setupDataKey(t)
	a, _ := DataEncrypt("same-plaintext")
	b, _ := DataEncrypt("same-plaintext")
	if a == b {
		t.Fatalf("相同明文两次加密应因随机 nonce 得到不同密文")
	}
}

// DataDecrypt 必须能读升级前用旧通讯密钥 CBC 加密的存量密文（无 swk1 前缀）。
func TestDataDecryptLegacyCBC(t *testing.T) {
	setupDataKey(t)
	plain := "legacy-cbc-credential"
	legacyEnc, err := AesEncrypt([]byte(plain), legacyKey)
	if err != nil {
		t.Fatalf("AesEncrypt: %v", err)
	}
	if IsDataKeyCiphertext(legacyEnc) {
		t.Fatalf("旧 CBC 密文不应带 swk1 前缀")
	}
	got, err := DataDecrypt(legacyEnc, legacyKey)
	if err != nil {
		t.Fatalf("DataDecrypt 旧密文失败: %v", err)
	}
	if got != plain {
		t.Fatalf("旧密文解出不一致: got %q want %q", got, plain)
	}
}

// --rekey-legacy 的核心：swk1 → 旧 CBC 后，仍能用旧密钥解回原文（模拟降级到旧版）。
func TestLegacyEncryptRoundTrip(t *testing.T) {
	setupDataKey(t)
	plain := "rollback-me"
	enc, _ := DataEncrypt(plain)
	back, err := LegacyEncrypt(mustDecrypt(t, enc), legacyKey)
	if err != nil {
		t.Fatalf("LegacyEncrypt: %v", err)
	}
	if IsDataKeyCiphertext(back) {
		t.Fatalf("回退产物不应带 swk1 前缀")
	}
	b, err := AesDecrypt(back, legacyKey)
	if err != nil {
		t.Fatalf("旧版应能用旧密钥解回退后的密文: %v", err)
	}
	if string(b) != plain {
		t.Fatalf("回退往返不一致: got %q want %q", string(b), plain)
	}
}

func mustDecrypt(t *testing.T, enc string) string {
	t.Helper()
	s, err := DataDecrypt(enc, legacyKey)
	if err != nil {
		t.Fatalf("DataDecrypt: %v", err)
	}
	return s
}

// 篡改 swk1 密文应被 GCM 完整性校验拒绝（CBC 做不到这一点）。
func TestDataDecryptTamperRejected(t *testing.T) {
	setupDataKey(t)
	enc, _ := DataEncrypt("integrity-protected")
	tampered := enc[:len(enc)-2] + func() string {
		last := enc[len(enc)-2:]
		if last == "AA" {
			return "BB"
		}
		return "AA"
	}()
	if _, err := DataDecrypt(tampered, legacyKey); err == nil {
		t.Fatalf("被篡改的 GCM 密文应解密失败")
	}
}
