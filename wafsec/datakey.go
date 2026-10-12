package wafsec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// 每实例静态数据加密密钥（DEK）。与通讯密钥 GWAF_COMMUNICATION_KEY 彻底分离：
// 通讯密钥全实例共用且随源码公开，只适合做传输层混淆；落库的敏感字段（Access 的
// TOTP/rq 签名密钥、CDN 厂商凭证、管理端 2FA 密钥等）改用本模块的每实例随机密钥，
// 拿到数据库文件不再等于拿到明文。
//
// 落地形态（与 security.ssl_export_allowed_dirs 等同口径）：密钥文件放 data/.keys/
// 下、权限 0600，不进数据库、不经 API 回显；运营方可用 config.yml 的
// security.data_key_file 指定自管位置。
//
// 密文格式：DataEncrypt 产出带 "swk1:" 前缀（AES-256-GCM）；DataDecrypt 见到前缀走
// DEK、无前缀按旧通讯密钥 CBC 解，保证升级前的存量密文仍可读。

const (
	// DataKeyPrefixV1 是 swk1 版密文前缀：AES-256-GCM。
	DataKeyPrefixV1 = "swk1:"
	dataKeyDirName  = ".keys"
	dataKeyFileName = "data_key"
	dataKeyLen      = 32 // AES-256
)

var (
	dataKey     []byte
	dataKeyOnce sync.Once
	dataKeyErr  error
	dataKeyMu   sync.RWMutex
)

// InitDataKey 加载（首次启动则生成）每实例 DEK。dataDir 为安装目录（GetCurrentDir），
// customFile 为 config.yml 中 security.data_key_file 声明的自管路径（可空）。
// 该函数应在数据库初始化之前调用，且全进程只需成功一次。
func InitDataKey(dataDir, customFile string) error {
	dataKeyOnce.Do(func() {
		path := strings.TrimSpace(customFile)
		if path == "" {
			path = filepath.Join(dataDir, "data", dataKeyDirName, dataKeyFileName)
		}
		key, err := loadOrCreateDataKey(path)
		if err != nil {
			dataKeyErr = err
			return
		}
		dataKeyMu.Lock()
		dataKey = key
		dataKeyMu.Unlock()
	})
	return dataKeyErr
}

// DataKeyReady 返回 DEK 是否已成功加载。
func DataKeyReady() bool {
	dataKeyMu.RLock()
	defer dataKeyMu.RUnlock()
	return len(dataKey) == dataKeyLen
}

func loadOrCreateDataKey(path string) ([]byte, error) {
	// 已存在：读取并校验长度。
	if raw, err := os.ReadFile(path); err == nil {
		key, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if decErr != nil {
			return nil, fmt.Errorf("数据密钥文件内容无法解析: %w", decErr)
		}
		if len(key) != dataKeyLen {
			return nil, fmt.Errorf("数据密钥长度非法(期望%d字节,实际%d字节): %s", dataKeyLen, len(key), path)
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("读取数据密钥文件失败: %w", err)
	}

	// 不存在：首次生成，落 0600 文件。
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("创建数据密钥目录失败: %w", err)
	}
	key := make([]byte, dataKeyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("生成数据密钥失败: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	if err := os.WriteFile(path, []byte(encoded), 0600); err != nil {
		return nil, fmt.Errorf("写入数据密钥文件失败: %w", err)
	}
	return key, nil
}

// currentDataKey 取当前 DEK 的副本；未就绪返回错误。
func currentDataKey() ([]byte, error) {
	dataKeyMu.RLock()
	defer dataKeyMu.RUnlock()
	if len(dataKey) != dataKeyLen {
		return nil, errors.New("数据密钥尚未初始化")
	}
	k := make([]byte, dataKeyLen)
	copy(k, dataKey)
	return k, nil
}

// DataEncrypt 用每实例 DEK 加密并返回带 swk1: 前缀的密文（AES-256-GCM）。空串原样返回。
func DataEncrypt(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	key, err := currentDataKey()
	if err != nil {
		return "", err
	}
	ct, err := gcmEncrypt([]byte(plain), key)
	if err != nil {
		return "", err
	}
	return DataKeyPrefixV1 + ct, nil
}

// DataDecrypt 解密 DataEncrypt 的产物。带 swk1: 前缀走 DEK(GCM)；无前缀视为升级前的
// 旧密文，用通讯密钥 CBC 解（兜底，保证存量可读）。空串原样返回。
// legacyKey 传 global.GWAF_COMMUNICATION_KEY（本包不反向依赖 global）。
func DataDecrypt(enc string, legacyKey []byte) (string, error) {
	if enc == "" {
		return "", nil
	}
	if strings.HasPrefix(enc, DataKeyPrefixV1) {
		key, err := currentDataKey()
		if err != nil {
			return "", err
		}
		b, err := gcmDecrypt(strings.TrimPrefix(enc, DataKeyPrefixV1), key)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	// 无前缀：旧通讯密钥 CBC 密文。
	b, err := AesDecrypt(enc, legacyKey)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// IsDataKeyCiphertext 判断是否为 swk1 新格式密文（迁移时用来跳过已迁移行）。
func IsDataKeyCiphertext(enc string) bool {
	return strings.HasPrefix(enc, DataKeyPrefixV1)
}

// LegacyEncrypt 用旧通讯密钥 CBC 加密（回退工具 --rekey-legacy 专用：把 swk1 密文
// 重写回旧格式，供降级到旧版二进制后读取）。空串原样返回。
func LegacyEncrypt(plain string, legacyKey []byte) (string, error) {
	if plain == "" {
		return "", nil
	}
	return AesEncrypt([]byte(plain), legacyKey)
}

// gcmEncrypt: 输出 base64(nonce ‖ ciphertext ‖ tag)。
func gcmEncrypt(plain, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plain, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

func gcmDecrypt(b64 string, key []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}
