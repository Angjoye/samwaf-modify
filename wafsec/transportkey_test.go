package wafsec

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

// 测试直接操作包内变量绕开 sync.Once：InitCommKey 全进程只跑一次，
// 而这里需要在多个用例里换密钥/换目录。
func setupCommKey(t *testing.T) {
	t.Helper()

	dir := t.TempDir()
	priv, err := loadOrCreateCommKey(filepath.Join(dir, "data", ".keys", commKeyFileName))
	if err != nil {
		t.Fatalf("生成传输密钥失败: %v", err)
	}
	var pub [commKeyLen]byte
	curve25519.ScalarBaseMult(&pub, priv)

	commKeyMu.Lock()
	commPriv, commPub, commKeyOK = *priv, pub, true
	commKeyMu.Unlock()

	commSessionsMu.Lock()
	commSessions = make(map[string]*commSession)
	commSessionsMu.Unlock()
}

// clientHandshake 模拟前端 tweetnacl 那一侧：生成一次性密钥对并算出共享密钥。
func clientHandshake(t *testing.T) (keyid string, shared [commKeyLen]byte) {
	t.Helper()

	serverPubB64, err := CommPublicKey()
	if err != nil {
		t.Fatalf("取服务端公钥失败: %v", err)
	}
	serverPubRaw, err := base64.StdEncoding.DecodeString(serverPubB64)
	if err != nil || len(serverPubRaw) != commKeyLen {
		t.Fatalf("服务端公钥格式不正确")
	}
	var serverPub [commKeyLen]byte
	copy(serverPub[:], serverPubRaw)

	var esk [commKeyLen]byte
	if _, err := io.ReadFull(rand.Reader, esk[:]); err != nil {
		t.Fatalf("生成临时私钥失败: %v", err)
	}
	var epk [commKeyLen]byte
	curve25519.ScalarBaseMult(&epk, &esk)
	box.Precompute(&shared, &serverPub, &esk)

	keyid, _, err = RegisterCommSession(base64.StdEncoding.EncodeToString(epk[:]))
	if err != nil {
		t.Fatalf("握手失败: %v", err)
	}
	return keyid, shared
}

// 客户端与服务端必须协商出同一把密钥，两个方向都要能解开对方的报文。
func TestCommHandshakeSharedKeyMatches(t *testing.T) {
	setupCommKey(t)
	keyid, shared := clientHandshake(t)

	// 服务端加密 → 客户端用自己算出的共享密钥解
	enc, err := TransportEncrypt(keyid, []byte("从服务端来的数据"))
	if err != nil {
		t.Fatalf("服务端加密失败: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(enc, TransportPrefixV2+keyid+":"))
	if err != nil {
		t.Fatalf("密文 base64 解析失败: %v", err)
	}
	var nonce [commNonceLen]byte
	copy(nonce[:], raw[:commNonceLen])
	plain, ok := secretbox.Open(nil, raw[commNonceLen:], &nonce, &shared)
	if !ok {
		t.Fatal("客户端解不开服务端报文——共享密钥不一致")
	}
	if string(plain) != "从服务端来的数据" {
		t.Fatalf("明文不符: %s", plain)
	}

	// 客户端加密 → 服务端解
	var cnonce [commNonceLen]byte
	if _, err := io.ReadFull(rand.Reader, cnonce[:]); err != nil {
		t.Fatal(err)
	}
	sealed := secretbox.Seal(cnonce[:], []byte("从客户端来的数据"), &cnonce, &shared)
	clientMsg := TransportPrefixV2 + keyid + ":" + base64.StdEncoding.EncodeToString(sealed)

	got, gotKeyid, err := TransportDecrypt(clientMsg)
	if err != nil {
		t.Fatalf("服务端解密失败: %v", err)
	}
	if gotKeyid != keyid {
		t.Fatalf("keyid 不符: 期望 %s 实际 %s", keyid, gotKeyid)
	}
	if string(got) != "从客户端来的数据" {
		t.Fatalf("明文不符: %s", got)
	}
}

// 两次握手必须拿到不同的 keyid 与不同的密钥：一个标签的密钥解不了另一个标签的报文。
func TestCommSessionsAreIsolated(t *testing.T) {
	setupCommKey(t)
	keyidA, _ := clientHandshake(t)
	keyidB, _ := clientHandshake(t)

	if keyidA == keyidB {
		t.Fatal("两次握手拿到了相同的 keyid")
	}

	enc, err := TransportEncrypt(keyidA, []byte("A 的数据"))
	if err != nil {
		t.Fatal(err)
	}
	// 把密文的 keyid 换成 B：B 的密钥不该能解开 A 的报文
	forged := TransportPrefixV2 + keyidB + ":" + strings.TrimPrefix(enc, TransportPrefixV2+keyidA+":")
	if _, _, err := TransportDecrypt(forged); err == nil {
		t.Fatal("B 的会话密钥解开了 A 的报文")
	}
}

// Poly1305 认证标签必须挡住篡改——这正是相对旧 CBC 通道的增益。
func TestTransportRejectsTamper(t *testing.T) {
	setupCommKey(t)
	keyid, _ := clientHandshake(t)

	enc, err := TransportEncrypt(keyid, []byte("原始内容"))
	if err != nil {
		t.Fatal(err)
	}
	payload := strings.TrimPrefix(enc, TransportPrefixV2+keyid+":")
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff // 翻转密文最后一字节
	tampered := TransportPrefixV2 + keyid + ":" + base64.StdEncoding.EncodeToString(raw)

	if _, _, err := TransportDecrypt(tampered); err == nil {
		t.Fatal("被篡改的报文通过了校验")
	}
}

// keyid 不存在（服务端重启丢会话）时必须报错，让调用方回落 legacy 或要求重新握手。
func TestUnknownKeyIDFails(t *testing.T) {
	setupCommKey(t)

	if _, err := TransportEncrypt("不存在的keyid", []byte("x")); err == nil {
		t.Fatal("未知 keyid 竟然加密成功")
	}
	if _, _, err := TransportDecrypt(TransportPrefixV2 + "不存在的keyid:AAAA"); err == nil {
		t.Fatal("未知 keyid 竟然解密成功")
	}
}

// 非 swt2 报文一律不认，避免与 legacy 通道混淆。
func TestIsTransportV2(t *testing.T) {
	if IsTransportV2("U2FtV2Fm") {
		t.Fatal("legacy 密文被误判为 v2")
	}
	if !IsTransportV2(TransportPrefixV2 + "abc:def") {
		t.Fatal("v2 密文没被识别")
	}
	if _, _, err := TransportDecrypt("U2FtV2Fm"); err == nil {
		t.Fatal("legacy 密文不该被 v2 解密接受")
	}
}

// 握手参数非法必须拒绝，不能把任意长度的输入当公钥算。
func TestRegisterRejectsBadClientKey(t *testing.T) {
	setupCommKey(t)

	for _, bad := range []string{"", "不是base64", base64.StdEncoding.EncodeToString([]byte("太短"))} {
		if _, _, err := RegisterCommSession(bad); err == nil {
			t.Fatalf("非法客户端公钥被接受: %q", bad)
		}
	}
}

// 会话表必须有上限，否则登录前开放的握手端点可以被反复调用顶爆内存。
func TestCommSessionsCapped(t *testing.T) {
	setupCommKey(t)

	var epk [commKeyLen]byte
	for i := 0; i < commSessionMax+64; i++ {
		if _, err := io.ReadFull(rand.Reader, epk[:]); err != nil {
			t.Fatal(err)
		}
		if _, _, err := RegisterCommSession(base64.StdEncoding.EncodeToString(epk[:])); err != nil {
			t.Fatalf("第 %d 次握手失败: %v", i, err)
		}
	}

	commSessionsMu.Lock()
	n := len(commSessions)
	commSessionsMu.Unlock()
	if n > commSessionMax {
		t.Fatalf("会话表突破上限: %d > %d", n, commSessionMax)
	}
}

// 密钥文件必须复用而不是每次启动重生成，否则重启后旧客户端全部失联。
func TestCommKeyFilePersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "comm_key")

	first, err := loadOrCreateCommKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateCommKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if *first != *second {
		t.Fatal("同一路径两次加载得到了不同的密钥")
	}

	// 内容损坏时必须报错而不是静默换一把新的（静默换钥=存量客户端全断且无从排查）
	if err := os.WriteFile(path, []byte("这不是合法的密钥"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateCommKey(path); err == nil {
		t.Fatal("损坏的密钥文件没有报错")
	}
}
