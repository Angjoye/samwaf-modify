package response

import (
	"SamWaf/global"
	"SamWaf/wafsec"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/curve25519"
)

// 传输层协商的四种组合：v2 有效、无声明(旧客户端)、v2 失效+legacy 开、v2 失效+legacy 关。
// 重点是第二种——旧客户端行为必须逐字节不变。

func newCtx(t *testing.T, keyid string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/whatever", nil)
	if keyid != "" {
		req.Header.Set(HeaderKeyID, keyid)
		req.Header.Set("X-Sec-Ver", "2")
	}
	c.Request = req
	return c, rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) Response {
	t.Helper()
	var resp Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	return resp
}

// 起一把可用的传输密钥并握手，返回 keyid
func setupSession(t *testing.T) string {
	t.Helper()
	if err := wafsec.InitCommKey(t.TempDir(), filepath.Join(t.TempDir(), "comm_key")); err != nil {
		t.Fatalf("初始化传输密钥失败: %v", err)
	}
	// 客户端那一侧只需要一个合法的 32 字节公钥，本用例不校验共享密钥内容
	keyid, _, err := wafsec.RegisterCommSession(clientPubForTest(t))
	if err != nil {
		t.Fatalf("握手失败: %v", err)
	}
	return keyid
}

// clientPubForTest 造一个合法的 X25519 客户端公钥（32 字节 base64）
func clientPubForTest(t *testing.T) string {
	t.Helper()
	var esk [32]byte
	if _, err := io.ReadFull(rand.Reader, esk[:]); err != nil {
		t.Fatal(err)
	}
	var epk [32]byte
	curve25519.ScalarBaseMult(&epk, &esk)
	return base64.StdEncoding.EncodeToString(epk[:])
}

func TestResultUsesV2WhenSessionValid(t *testing.T) {
	keyid := setupSession(t)
	c, rec := newCtx(t, keyid)

	OkWithData(map[string]string{"hello": "world"}, c)

	resp := decodeBody(t, rec)
	data, _ := resp.Data.(string)
	if !strings.HasPrefix(data, wafsec.TransportPrefixV2) {
		t.Fatalf("有会话密钥时没走 v2，实际: %.20s", data)
	}
	plain, gotKeyid, err := wafsec.TransportDecrypt(data)
	if err != nil {
		t.Fatalf("v2 响应解密失败: %v", err)
	}
	if gotKeyid != keyid {
		t.Fatalf("keyid 不符: %s", gotKeyid)
	}
	if !strings.Contains(string(plain), "world") {
		t.Fatalf("明文内容不符: %s", plain)
	}
}

// 旧客户端（不声明 keyid）必须原样走 legacy——这是"不破坏存量行为"的硬约束
func TestResultFallsBackToLegacyForOldClient(t *testing.T) {
	setupSession(t)
	c, rec := newCtx(t, "")

	OkWithData(map[string]string{"hello": "world"}, c)

	resp := decodeBody(t, rec)
	data, _ := resp.Data.(string)
	if strings.HasPrefix(data, wafsec.TransportPrefixV2) {
		t.Fatal("旧客户端收到了 v2 报文")
	}
	plain, err := wafsec.AesDecrypt(data, global.GWAF_COMMUNICATION_KEY)
	if err != nil {
		t.Fatalf("legacy 响应解密失败: %v", err)
	}
	if !strings.Contains(string(plain), "world") {
		t.Fatalf("明文内容不符: %s", plain)
	}
}

// 会话失效（服务端重启）时，legacy 开着就回落，客户端仍能解开并据此重新握手
func TestResultFallsBackWhenSessionExpired(t *testing.T) {
	setupSession(t)
	global.GCONFIG_COMM_LEGACY_KEY = true
	c, rec := newCtx(t, "早就没了的keyid")

	OkWithData(map[string]string{"hello": "world"}, c)

	resp := decodeBody(t, rec)
	if resp.Code != SUCCESS {
		t.Fatalf("期望回落 legacy 正常返回，实际 code=%d", resp.Code)
	}
	data, _ := resp.Data.(string)
	if _, err := wafsec.AesDecrypt(data, global.GWAF_COMMUNICATION_KEY); err != nil {
		t.Fatalf("回落的 legacy 报文解不开: %v", err)
	}
}

// legacy 被运维关掉后，没有会话密钥的请求要拿到明确的重新握手信号，
// 而不是一段对方解不开的密文
func TestResultSignalsRehandshakeWhenLegacyDisabled(t *testing.T) {
	setupSession(t)
	global.GCONFIG_COMM_LEGACY_KEY = false
	defer func() { global.GCONFIG_COMM_LEGACY_KEY = true }()

	c, rec := newCtx(t, "早就没了的keyid")
	OkWithData(map[string]string{"hello": "world"}, c)

	resp := decodeBody(t, rec)
	if resp.Code != NEED_REHANDSHAKE {
		t.Fatalf("期望 %d，实际 %d", NEED_REHANDSHAKE, resp.Code)
	}
	if resp.Data != "" {
		t.Fatalf("重新握手信号不该带数据: %v", resp.Data)
	}
}

// 握手类接口的响应必须是明文——此时双方还没有共享密钥
func TestPlainHelpersDoNotEncrypt(t *testing.T) {
	c, rec := newCtx(t, "")
	OkWithPlainData(gin.H{"pub": "abc"}, c)

	resp := decodeBody(t, rec)
	m, ok := resp.Data.(map[string]interface{})
	if !ok || m["pub"] != "abc" {
		t.Fatalf("握手响应不是明文对象: %#v", resp.Data)
	}
}
