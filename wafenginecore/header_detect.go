package wafenginecore

import (
	"SamWaf/libinjection-go"
	"SamWaf/wafdefenserce"
	"SamWaf/wafenginecore/wafhttpcore"
	"net/http"
	"strings"
)

// 头位注入检测(S1-4)：自定义/非标准请求头也可能藏 XSS/SQLi/命令注入(如 X-Forwarded-For、
// 各类 X-* 自定义头)。受 body_detect_mode 门控(observe 默认只观察)。为压误报，跳过所有
// 标准/浏览器头——这些头合法值复杂(Referer 带 URL、Accept 带通配、UA 带括号等)，经 blaze
// 33k 白样本实测：跳过下列头 + sec-*/waf_ 前缀后，剩余自定义头值命中检测 = 0 条。

var headerDetectSkip = map[string]struct{}{}

func init() {
	for _, h := range []string{
		"host", "user-agent", "accept", "accept-encoding", "accept-language",
		"accept-charset", "accept-datetime", "referer", "origin", "connection",
		"content-type", "content-length", "content-disposition", "content-encoding",
		"cache-control", "pragma", "upgrade-insecure-requests", "dnt", "cookie",
		"authorization", "proxy-authorization", "if-none-match", "if-modified-since",
		"if-match", "if-unmodified-since", "if-range", "range", "te", "trailer",
		"transfer-encoding", "expect", "date", "keep-alive",
		"x-requested-with", "x-client-data", "x-forwarded-proto",
		"x-forwarded-port", "cf-ray", "cf-ipcountry", "cf-visitor",
		"priority", "purpose", "x-purpose", "save-data", "device-memory",
		"downlink", "ect", "rtt", "viewport-width", "width", "content-md5",
		"max-forwards", "from", "warning", "cookie2", "x-csrf-token", "x-xsrf-token",
	} {
		headerDetectSkip[h] = struct{}{}
	}
}

// skipDetectHeader 报告该头是否跳过注入检测(标准/浏览器头 + sec-*/waf_ 前缀)。
func skipDetectHeader(name string) bool {
	n := strings.ToLower(name)
	if _, ok := headerDetectSkip[n]; ok {
		return true
	}
	return strings.HasPrefix(n, "sec-") || strings.HasPrefix(n, "waf_")
}

// detectableHeaderValues 返回需做注入检测的头的(多轮 URL 解码后)值。UA 已由 D2 扫描器覆盖、
// Cookie 由各 check 单独走 COOKIES，故不在此重复。
func detectableHeaderValues(r *http.Request) []string {
	if r == nil {
		return nil
	}
	var out []string
	for name, vals := range r.Header {
		if skipDetectHeader(name) {
			continue
		}
		for _, v := range vals {
			out = append(out, wafhttpcore.NormalizeForDetection(v))
		}
	}
	return out
}

// headerXSSHit 头值逐个判 XSS(结构化跳过 C + 多信号 D，同请求体口径)
func headerXSSHit(r *http.Request) bool {
	for _, v := range detectableHeaderValues(r) {
		if bodyValueIsXSS(v) {
			return true
		}
	}
	return false
}

// headerSQLHit 头值逐个判 SQLi(高危关键字兜底 + 结构化跳过 + libinjection)
func headerSQLHit(r *http.Request) bool {
	for _, v := range detectableHeaderValues(r) {
		if wafhttpcore.HasHighRiskSQLKeyword(v) {
			return true
		}
		if wafhttpcore.IsStructuredDataValue(v) {
			continue
		}
		if libinjection.IsSQLiNotReturnPrint(v) {
			return true
		}
	}
	return false
}

// headerRCEHit 头值逐个判命令注入(含 D1-6 反混淆)
func headerRCEHit(r *http.Request) (bool, string) {
	for _, v := range detectableHeaderValues(r) {
		if ok, name := wafdefenserce.DetermineRCE(v); ok {
			return true, name
		}
	}
	return false, ""
}
