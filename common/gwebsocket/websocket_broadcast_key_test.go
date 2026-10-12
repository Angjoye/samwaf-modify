package gwebsocket

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	Wssocket "github.com/gorilla/websocket"
)

// 广播的按连接组装回归用例。
//
// v2 通道下每条连接各有各的会话密钥，不能再像以前那样"加密一次发给所有人"。
// BroadcastBuild 把组装交给调用方，并把该连接建连时声明的 KeyID 传进去；
// 下面验证每条连接确实收到用自己 KeyID 组装出来的那一份，且旧客户端（KeyID 为空）
// 仍能收到东西——否则表现就是"部分标签页收不到通知"。

// dialWithKey 建一条带 keyid 的连接，返回客户端侧连接
func dialWithKey(t *testing.T, online *WebSocketOnline, srvURL string, keyID string) *Wssocket.Conn {
	t.Helper()
	conn, _, err := Wssocket.DefaultDialer.Dial(strings.Replace(srvURL, "http://", "ws://", 1)+"?keyid="+keyID, nil)
	if err != nil {
		t.Fatalf("拨号失败(keyid=%q): %v", keyID, err)
	}
	return conn
}

func TestBroadcastBuildUsesPerConnectionKey(t *testing.T) {
	online := InitWafWebSocket()

	upGrader := Wssocket.Upgrader{
		CheckOrigin:     func(r *http.Request) bool { return true },
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	var wg sync.WaitGroup
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upGrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade 失败: %v", err)
			return
		}
		// 复刻 api/waf_websocket.go：keyid 从查询串取（WS 握手带不了自定义头）
		sessionID := online.AddWebSocketWithKey("tenant-user-admin", r.URL.Query().Get("keyid"), ws)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer online.CloseSession(sessionID)
			for {
				if _, _, err := ws.ReadMessage(); err != nil {
					return
				}
			}
		}()
	}))
	defer func() {
		srv.Close()
		wg.Wait()
	}()

	// 三条连接：两条带各自的 keyid，一条模拟旧客户端（无 keyid）
	connA := dialWithKey(t, online, srv.URL, "key-A")
	defer connA.Close()
	connB := dialWithKey(t, online, srv.URL, "key-B")
	defer connB.Close()
	connOld := dialWithKey(t, online, srv.URL, "")
	defer connOld.Close()

	// 等三条都登记完
	deadline := time.Now().Add(3 * time.Second)
	for online.OnlineCount() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if online.OnlineCount() != 3 {
		t.Fatalf("期望 3 条在线连接，实际 %d", online.OnlineCount())
	}

	// build 回调按 KeyID 产出不同内容——真实实现里这就是"用该连接的会话密钥加密"
	var mu sync.Mutex
	seen := map[string]int{}
	sent := online.BroadcastBuild(Wssocket.TextMessage, func(keyID string) ([]byte, error) {
		mu.Lock()
		seen[keyID]++
		mu.Unlock()
		if keyID == "" {
			return []byte("legacy-payload"), nil
		}
		return []byte("payload-for:" + keyID), nil
	})
	if sent != 3 {
		t.Fatalf("期望发给 3 条连接，实际 %d", sent)
	}

	// 每个 KeyID 都应恰好被组装一次
	mu.Lock()
	defer mu.Unlock()
	for _, want := range []string{"key-A", "key-B", ""} {
		if seen[want] != 1 {
			t.Fatalf("KeyID %q 应被组装 1 次，实际 %d 次", want, seen[want])
		}
	}

	// 每条连接收到的必须是给自己那一份
	expect := map[*Wssocket.Conn]string{
		connA:   "payload-for:key-A",
		connB:   "payload-for:key-B",
		connOld: "legacy-payload",
	}
	for conn, want := range expect {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, data, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("读取失败: %v", err)
		}
		if string(data) != want {
			t.Fatalf("期望收到 %q，实际 %q", want, data)
		}
	}
}

// build 返回错误的连接跳过即可，不能影响其它连接——
// 某一条的会话密钥失效时，别人的通知不该跟着丢。
func TestBroadcastBuildSkipsFailedConnection(t *testing.T) {
	online := InitWafWebSocket()

	upGrader := Wssocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	var wg sync.WaitGroup
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upGrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		sessionID := online.AddWebSocketWithKey("u", r.URL.Query().Get("keyid"), ws)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer online.CloseSession(sessionID)
			for {
				if _, _, err := ws.ReadMessage(); err != nil {
					return
				}
			}
		}()
	}))
	defer func() {
		srv.Close()
		wg.Wait()
	}()

	bad := dialWithKey(t, online, srv.URL, "bad")
	defer bad.Close()
	good := dialWithKey(t, online, srv.URL, "good")
	defer good.Close()

	deadline := time.Now().Add(3 * time.Second)
	for online.OnlineCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	sent := online.BroadcastBuild(Wssocket.TextMessage, func(keyID string) ([]byte, error) {
		if keyID == "bad" {
			return nil, errBuild
		}
		return []byte("ok:" + keyID), nil
	})
	if sent != 1 {
		t.Fatalf("期望只发出 1 条（坏的那条被跳过），实际 %d", sent)
	}

	good.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, data, err := good.ReadMessage()
	if err != nil {
		t.Fatalf("正常连接应照常收到消息: %v", err)
	}
	if string(data) != "ok:good" {
		t.Fatalf("期望 ok:good，实际 %q", data)
	}
}

type buildErr struct{}

func (buildErr) Error() string { return "组装失败" }

var errBuild = buildErr{}
