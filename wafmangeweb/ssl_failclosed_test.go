package wafmangeweb

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 「仅允许HTTPS」在拿不到证书时的行为。
//
// 这条是安全语义，不是可用性偏好：运维显式声明过"只走 HTTPS"，而证书过期/损坏又是最常见的
// 失败方式。若此时静默降级成明文，管理端会在运维毫不知情的情况下以明文接受登录、口令明文过网——
// 开关名字承诺的和实际做的就对不上了。这几条用例把这个语义钉住，防止后来被改回"总是降级"。

// fail-closed 时端口照常监听，但管理端路由不挂载：任何路径都只回 503。
func TestHTTPSRequiredHandlerRefusesEverything(t *testing.T) {
	h := httpsRequiredHandler("管理端证书文件不存在")

	// 登录接口、静态页、随便什么路径，一律 503
	for _, path := range []string{"/", "/api/v1/public/login", "/api/v1/hosts/list", "/whatever"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))

			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("%s %s 期望 503，实际 %d", method, path, rec.Code)
			}
			body := rec.Body.String()
			if !strings.Contains(body, "仅允许HTTPS") {
				t.Fatalf("%s %s 的响应没说明原因，运维无从排查: %s", method, path, body)
			}
			// 纯文本 + nosniff：别让浏览器把它当 HTML 渲染，也不给任何可交互的东西
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
				t.Fatalf("%s %s 的 Content-Type 应为 text/plain，实际 %s", method, path, ct)
			}
			if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("%s %s 缺少 nosniff", method, path)
			}
		}
	}
}

// fail-closed 最怕"锁死了还不知道怎么开"：恢复指引必须是照着就能做的
func TestHTTPSRequiredNoticeIsActionable(t *testing.T) {
	notice := httpsRequiredNotice("管理端证书加载失败：x509: 证书与私钥不配对")

	for _, must := range []string{
		"x509: 证书与私钥不配对",  // 具体原因要带出来，不能只说"失败了"
		"conf/config.yml", // 改哪个文件
		"ssl_force_https", // 改哪个开关
		"ssl_enable",      // 另一条退路
		"domain.crt",      // 证书在哪
		"重启",              // 改完要重启，否则改了也不生效
	} {
		if !strings.Contains(notice, must) {
			t.Fatalf("恢复指引里缺少 %q，运维照着做不出来:\n%s", must, notice)
		}
	}
}

// 提示里不能出现任何可被当成入口的东西——它就是一段纯文本
func TestHTTPSRequiredNoticeHasNoMarkupOrLink(t *testing.T) {
	notice := httpsRequiredNotice("管理端证书文件不存在")
	for _, bad := range []string{"<", ">", "http://", "https://"} {
		if strings.Contains(notice, bad) {
			t.Fatalf("提示文案里不该出现 %q：它是明文端口上唯一的响应，应当只是一段纯文本\n%s", bad, notice)
		}
	}
}
