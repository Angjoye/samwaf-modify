package wafsec

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

// 管理端传输层的 v2 通道（swt2）。与静态加密的 DEK（datakey.go）彻底分开：DEK 管落库、
// 本模块管一次会话内的报文；两者密钥不同、生命周期不同、算法不同。
//
// 形态：服务端持每实例 X25519 静态密钥对（私钥落 data/.keys/comm_key，0600，不进库不经 API），
// 客户端每标签生成一次性密钥对与之协商出共享密钥，报文用 XSalsa20-Poly1305 加密。
// 选 NaCl 而非 AES-GCM 的原因见计划 §二十：浏览器 crypto.subtle 只在 secure context 可用，
// 而本通道要服务的正是 HTTP 部署；tweetnacl 是纯 JS 且同步的。
//
// 密文格式：swt2:<keyid>:<base64(nonce24 ‖ secretbox)>；无前缀 = 旧 CBC 通道（legacy），
// 由调用方按前缀路由，旧客户端行为逐字节不变。
//
// 边界（如实记录，不做过度承诺）：会话密钥防的是被动抓包与 HAR 离线还原；
// 服务端静态私钥长期有效，故无前向保密；主动中间人仍只有 TLS 能防。

const (
	// TransportPrefixV2 是 swt2 版密文前缀。
	TransportPrefixV2 = "swt2:"
	commKeyFileName   = "comm_key"
	commKeyLen        = 32
	commNonceLen      = 24

	// commSessionTTL 是一个会话密钥的存活时长，每次成功使用后顺延。
	commSessionTTL = 12 * time.Hour
	// commSessionMax 是会话表上限。握手端点在登录前开放，没有上限的话
	// 反复握手就能把内存顶掉；到顶后按最早过期的先淘汰。
	commSessionMax = 4096
)

var (
	commPriv    [commKeyLen]byte
	commPub     [commKeyLen]byte
	commKeyOnce sync.Once
	commKeyErr  error
	commKeyMu   sync.RWMutex
	commKeyOK   bool

	commSessions   = make(map[string]*commSession)
	commSessionsMu sync.Mutex
)

type commSession struct {
	key      [commKeyLen]byte
	expireAt time.Time
}

// InitCommKey 加载（首次启动则生成）每实例传输密钥对。dataDir 为安装目录，
// customFile 为 config.yml 中 security.data_key_file 同级目录下的自管路径（可空）。
func InitCommKey(dataDir, customFile string) error {
	commKeyOnce.Do(func() {
		path := strings.TrimSpace(customFile)
		if path == "" {
			path = filepath.Join(dataDir, "data", dataKeyDirName, commKeyFileName)
		}
		priv, err := loadOrCreateCommKey(path)
		if err != nil {
			commKeyErr = err
			return
		}
		var pub [commKeyLen]byte
		curve25519.ScalarBaseMult(&pub, priv)

		commKeyMu.Lock()
		commPriv = *priv
		commPub = pub
		commKeyOK = true
		commKeyMu.Unlock()
	})
	return commKeyErr
}

// CommKeyReady 返回传输密钥对是否已就绪。
func CommKeyReady() bool {
	commKeyMu.RLock()
	defer commKeyMu.RUnlock()
	return commKeyOK
}

// CommPublicKey 返回服务端静态公钥的 base64（握手端点下发的全部内容）。
func CommPublicKey() (string, error) {
	commKeyMu.RLock()
	defer commKeyMu.RUnlock()
	if !commKeyOK {
		return "", errors.New("传输密钥尚未初始化")
	}
	return base64.StdEncoding.EncodeToString(commPub[:]), nil
}

func loadOrCreateCommKey(path string) (*[commKeyLen]byte, error) {
	var key [commKeyLen]byte

	if raw, err := os.ReadFile(path); err == nil {
		decoded, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if decErr != nil {
			return nil, fmt.Errorf("传输密钥文件内容无法解析: %w", decErr)
		}
		if len(decoded) != commKeyLen {
			return nil, fmt.Errorf("传输密钥长度非法(期望%d字节,实际%d字节): %s", commKeyLen, len(decoded), path)
		}
		copy(key[:], decoded)
		return &key, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("读取传输密钥文件失败: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("创建传输密钥目录失败: %w", err)
	}
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return nil, fmt.Errorf("生成传输密钥失败: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(key[:])
	if err := os.WriteFile(path, []byte(encoded), 0600); err != nil {
		return nil, fmt.Errorf("写入传输密钥文件失败: %w", err)
	}
	return &key, nil
}

// RegisterCommSession 用客户端一次性公钥协商出共享密钥并登记，返回 keyid 与存活秒数。
// clientPubB64 为 base64 的 32 字节 X25519 公钥。
func RegisterCommSession(clientPubB64 string) (string, int, error) {
	commKeyMu.RLock()
	ready, priv := commKeyOK, commPriv
	commKeyMu.RUnlock()
	if !ready {
		return "", 0, errors.New("传输密钥尚未初始化")
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(clientPubB64))
	if err != nil || len(decoded) != commKeyLen {
		return "", 0, errors.New("客户端公钥格式不正确")
	}
	var peer [commKeyLen]byte
	copy(peer[:], decoded)

	var shared [commKeyLen]byte
	box.Precompute(&shared, &peer, &priv)

	keyid, err := randomKeyID()
	if err != nil {
		return "", 0, err
	}

	commSessionsMu.Lock()
	defer commSessionsMu.Unlock()
	pruneCommSessionsLocked()
	commSessions[keyid] = &commSession{key: shared, expireAt: time.Now().Add(commSessionTTL)}
	return keyid, int(commSessionTTL / time.Second), nil
}

// 会话密钥不随登出失效：握手在登录前就开放、与账号无关，它保护的是传输而不是身份。
// 登出即丢会让紧接着的登录请求先吃一次重新握手，白白多一个来回；到期由 TTL 负责。

func lookupCommSession(keyid string) ([commKeyLen]byte, bool) {
	var zero [commKeyLen]byte
	if keyid == "" {
		return zero, false
	}
	commSessionsMu.Lock()
	defer commSessionsMu.Unlock()

	s, ok := commSessions[keyid]
	if !ok {
		return zero, false
	}
	if time.Now().After(s.expireAt) {
		delete(commSessions, keyid)
		return zero, false
	}
	// 活跃会话顺延，避免用户挂着页面工作一整天被中途踢回握手。
	s.expireAt = time.Now().Add(commSessionTTL)
	return s.key, true
}

// pruneCommSessionsLocked 清掉过期项；仍超上限则按最早过期的淘汰。调用方需持有锁。
func pruneCommSessionsLocked() {
	now := time.Now()
	for id, s := range commSessions {
		if now.After(s.expireAt) {
			delete(commSessions, id)
		}
	}
	for len(commSessions) >= commSessionMax {
		var oldestID string
		var oldestAt time.Time
		for id, s := range commSessions {
			if oldestID == "" || s.expireAt.Before(oldestAt) {
				oldestID, oldestAt = id, s.expireAt
			}
		}
		if oldestID == "" {
			return
		}
		delete(commSessions, oldestID)
	}
}

func randomKeyID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("生成会话标识失败: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// IsTransportV2 判断报文是否为 swt2 格式。
func IsTransportV2(s string) bool {
	return strings.HasPrefix(s, TransportPrefixV2)
}

// TransportEncrypt 用 keyid 对应的会话密钥加密，产出 swt2:<keyid>:<base64>。
// keyid 无效（未握手/已过期/服务端重启）时返回错误，由调用方回落 legacy 通道。
func TransportEncrypt(keyid string, plain []byte) (string, error) {
	key, ok := lookupCommSession(keyid)
	if !ok {
		return "", errors.New("会话密钥不存在或已过期")
	}
	var nonce [commNonceLen]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", err
	}
	sealed := secretbox.Seal(nonce[:], plain, &nonce, &key)
	return TransportPrefixV2 + keyid + ":" + base64.StdEncoding.EncodeToString(sealed), nil
}

// TransportDecrypt 解开 swt2 报文，返回明文与其 keyid。
func TransportDecrypt(enc string) ([]byte, string, error) {
	if !IsTransportV2(enc) {
		return nil, "", errors.New("不是 swt2 报文")
	}
	rest := strings.TrimPrefix(enc, TransportPrefixV2)
	sep := strings.Index(rest, ":")
	if sep <= 0 {
		return nil, "", errors.New("swt2 报文格式不正确")
	}
	keyid, payload := rest[:sep], rest[sep+1:]

	key, ok := lookupCommSession(keyid)
	if !ok {
		return nil, keyid, errors.New("会话密钥不存在或已过期")
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, keyid, err
	}
	if len(raw) < commNonceLen {
		return nil, keyid, errors.New("swt2 报文长度不足")
	}
	var nonce [commNonceLen]byte
	copy(nonce[:], raw[:commNonceLen])
	plain, ok := secretbox.Open(nil, raw[commNonceLen:], &nonce, &key)
	if !ok {
		return nil, keyid, errors.New("swt2 报文校验失败")
	}
	return plain, keyid, nil
}
