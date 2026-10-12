package wafenginecore

import (
	"net/http"
	"testing"
)

func reqWithHeader(name, val string) *http.Request {
	r, _ := http.NewRequest("GET", "http://x/", nil)
	r.Header.Set(name, val)
	return r
}

// S1-4：自定义头里的注入应被对应 check 命中
func TestHeaderDetect_Hits(t *testing.T) {
	if !headerXSSHit(reqWithHeader("X-Custom", "<script>alert(1)</script>")) {
		t.Error("头位 XSS 应命中")
	}
	if !headerSQLHit(reqWithHeader("X-Api", "1;exec sp_configure 'xp_cmdshell',1;reconfigure;--")) {
		t.Error("头位 SQLi(关键字) 应命中")
	}
	if !headerSQLHit(reqWithHeader("X-Forwarded-Host", "1' or '1'='1")) {
		t.Error("头位 SQLi(libinjection) 应命中")
	}
	if ok, _ := headerRCEHit(reqWithHeader("X-Cmd", "who^ami")); !ok {
		t.Error("头位命令注入(反混淆) 应命中")
	}
	if ok, _ := headerRCEHit(reqWithHeader("X-Debug", ";id")); !ok {
		t.Error("头位命令注入 应命中")
	}
}

// 标准/浏览器头及正常自定义头不应误报
func TestHeaderDetect_NoFP(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://x/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	r.Header.Set("Referer", "https://site.com/search?q=select+all&cat=news")
	r.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	r.Header.Set("Sec-Ch-Ua", `"Chromium";v="120", "Not?A_Brand";v="8"`)
	r.Header.Set("X-Requested-With", "XMLHttpRequest")
	r.Header.Set("X-Custom-Id", "user-12345")
	if headerXSSHit(r) {
		t.Error("正常头不应判 XSS")
	}
	if headerSQLHit(r) {
		t.Error("正常头不应判 SQLi")
	}
	if ok, _ := headerRCEHit(r); ok {
		t.Error("正常头不应判命令注入")
	}
}

func TestSkipDetectHeader(t *testing.T) {
	skip := []string{"Host", "User-Agent", "Referer", "Accept", "Cookie", "Sec-Fetch-Site", "waf_req_uuid"}
	for _, h := range skip {
		if !skipDetectHeader(h) {
			t.Errorf("应跳过标准头: %s", h)
		}
	}
	for _, h := range []string{"X-Custom", "X-Forwarded-Host", "X-Cmd"} {
		if skipDetectHeader(h) {
			t.Errorf("自定义头不应跳过: %s", h)
		}
	}
}
