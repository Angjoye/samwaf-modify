package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"net/http"
	"net/url"
	"testing"
)

func newTestWafForXSS() (*WafEngine, *wafenginmodel.HostSafe) {
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "json")
	waf := &WafEngine{}
	waf.InitRouting()
	global.GWAF_GLOBAL_HOST_NAME = "全局网站"
	waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME] = &wafenginmodel.HostSafe{
		Host: model.Hosts{GUARD_STATUS: 1},
	}
	hostSafe := &wafenginmodel.HostSafe{
		Host: model.Hosts{GUARD_STATUS: 1},
	}
	return waf, hostSafe
}

func TestCheckXss(t *testing.T) {
	waf, hostSafe := newTestWafForXSS()
	globalHost := waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME]
	global.GCONFIG_BODY_DETECT_MODE = "block" // 测请求体拦截逻辑（默认 observe 只记录不拦）
	defer func() { global.GCONFIG_BODY_DETECT_MODE = "observe" }()

	tests := []struct {
		name        string
		rawQuery    string
		postForm    string
		bodyValues  []string
		formValues  url.Values
		expectBlock bool
		desc        string
	}{
		// --- 误报修复 ---
		{
			name:        "误报修复-style参数名在RawQuery中",
			rawQuery:    "style=ptype&ptypeid=000050004500108&orderid=1615",
			expectBlock: false,
			desc:        "参数名 style 不应触发 XSS 拦截",
		},
		{
			name:        "误报修复-filter和class参数名",
			rawQuery:    "filter=name&class=active&id=123",
			expectBlock: false,
			desc:        "参数名 filter/class/id 不应触发 XSS 拦截",
		},
		{
			name:        "误报修复-href和src参数名",
			rawQuery:    "href=home&src=logo&action=submit",
			expectBlock: false,
			desc:        "参数名 href/src/action 不应触发 XSS 拦截",
		},

		// --- 正常请求 ---
		{
			name:        "正常-分页参数",
			rawQuery:    "page=1&size=20&keyword=hello",
			expectBlock: false,
			desc:        "正常分页参数不应被拦截",
		},
		{
			name:        "正常-空查询串",
			rawQuery:    "",
			expectBlock: false,
			desc:        "空查询串不应被拦截",
		},

		// --- 真实 XSS ---
		{
			name:        "真实XSS-script标签在RawQuery值中",
			rawQuery:    "name=<script>alert(1)</script>",
			expectBlock: true,
			desc:        "参数值包含 <script> 应被拦截",
		},
		{
			name:        "真实XSS-img_onerror在RawQuery值中",
			rawQuery:    `q="><img src=x onerror=alert(1)>`,
			expectBlock: true,
			desc:        "参数值包含 img onerror 应被拦截",
		},
		{
			name:        "真实XSS-script标签在POST_FORM中",
			postForm:    "comment=<script>alert(1)</script>&submit=ok",
			expectBlock: true,
			desc:        "POST 表单参数值含 <script> 应被拦截",
		},
		{
			name:     "D3-formValue中的XSS-现已启用检测",
			rawQuery: "page=1",
			formValues: url.Values{
				"input": []string{"<script>alert(1)</script>"},
			},
			expectBlock: true,
			desc:        "formValue 逐值检测已启用，值含 <script> 应被拦截",
		},
		{
			name:     "D3-formValue正常值-不误拦",
			rawQuery: "page=1",
			formValues: url.Values{
				"nickname": []string{"hello world"},
				"remark":   []string{"价格 100 元"},
			},
			expectBlock: false,
			desc:        "普通表单值不应被误拦",
		},
		{
			name:        "D3-JSON请求体值含XSS",
			bodyValues:  []string{"<script>alert(document.cookie)</script>"},
			expectBlock: true,
			desc:        "JSON 请求体字符串值含 <script> 应被拦截（逐值 BodyValues）",
		},
		{
			name:        "D3-JSON请求体正常字符串值-不误拦",
			bodyValues:  []string{"weekly report", "订单已发货"},
			expectBlock: false,
			desc:        "正常 JSON 字符串值不应被误拦",
		},
		{
			name:        "真实XSS-svg在值中",
			rawQuery:    "data=<svg/onload=alert(1)>",
			expectBlock: true,
			desc:        "参数值包含 svg onload 应被拦截",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com/path?"+tt.rawQuery, nil)
			weblog := &innerbean.WebLog{
				RawQuery:   tt.rawQuery,
				POST_FORM:  tt.postForm,
				BodyValues: tt.bodyValues,
			}
			formValues := tt.formValues
			if formValues == nil {
				formValues = url.Values{}
			}

			result := waf.CheckXss(req, weblog, formValues, hostSafe, globalHost)

			if result.IsBlock != tt.expectBlock {
				t.Errorf("[%s] IsBlock = %v, 期望 %v (query=%q, postForm=%q)",
					tt.desc, result.IsBlock, tt.expectBlock, tt.rawQuery, tt.postForm)
			}
			if tt.expectBlock {
				if result.Title != "XSS跨站注入" {
					t.Errorf("期望 Title 为 'XSS跨站注入', 实际为 %q", result.Title)
				}
				if weblog.RISK_LEVEL != 2 {
					t.Errorf("期望 RISK_LEVEL = 2, 实际为 %d", weblog.RISK_LEVEL)
				}
			}
		})
	}
}

// TestCheckXssBodyMode 验证请求体 XSS 的三档模式：observe 只记录不拦、block 拦、off 不检测。
func TestCheckXssBodyMode(t *testing.T) {
	waf, hostSafe := newTestWafForXSS()
	globalHost := waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME]
	defer func() { global.GCONFIG_BODY_DETECT_MODE = "observe" }()

	run := func(mode string, bodyValues []string) detection.Result {
		global.GCONFIG_BODY_DETECT_MODE = mode
		req, _ := http.NewRequest("POST", "http://example.com/api", nil)
		weblog := &innerbean.WebLog{BodyValues: bodyValues}
		return waf.CheckXss(req, weblog, url.Values{}, hostSafe, globalHost)
	}
	xss := []string{"<script>alert(1)</script>"}

	if r := run("observe", xss); r.IsBlock {
		t.Error("observe 模式不应拦截 body XSS")
	}
	if r := run("block", xss); !r.IsBlock {
		t.Error("block 模式应拦截 body XSS")
	}
	if r := run("off", xss); r.IsBlock {
		t.Error("off 模式不应做 body 检测")
	}
	// observe 模式命中要在 RULE 打观察标记(供 abnormal 日志落库复查)
	global.GCONFIG_BODY_DETECT_MODE = "observe"
	req, _ := http.NewRequest("POST", "http://example.com/api", nil)
	wl := &innerbean.WebLog{BodyValues: xss}
	waf.CheckXss(req, wl, url.Values{}, hostSafe, globalHost)
	if wl.RULE == "" {
		t.Error("observe 命中应在 RULE 打观察标记")
	}
}

// TestCheckXssBodyMultiSignal 验证多信号(D)：block 模式下，散文里孤立的 < / 引号(无真标签/事件)
// 不被误拦，而真标签/事件属性的 XSS 仍拦。
func TestCheckXssBodyMultiSignal(t *testing.T) {
	waf, hostSafe := newTestWafForXSS()
	globalHost := waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME]
	global.GCONFIG_BODY_DETECT_MODE = "block"
	defer func() { global.GCONFIG_BODY_DETECT_MODE = "observe" }()

	// 正常散文/表达式：无真标签、无事件 → 不拦
	benign := []string{
		"Uncaught SyntaxError: Unexpected token '<'",
		"a < b && c > d",
		"价格 < 100 元",
	}
	for _, v := range benign {
		req, _ := http.NewRequest("POST", "http://example.com/api", nil)
		wl := &innerbean.WebLog{BodyValues: []string{v}}
		if r := waf.CheckXss(req, wl, url.Values{}, hostSafe, globalHost); r.IsBlock {
			t.Errorf("散文不应被误拦: %q", v)
		}
	}
	// 真 XSS：真标签 / 事件属性 / 伪协议 → 拦
	attacks := []string{
		"<script>alert(1)</script>",
		`"><img src=x onerror=alert(1)>`,
		"<svg/onload=alert(1)>",
	}
	for _, v := range attacks {
		req, _ := http.NewRequest("POST", "http://example.com/api", nil)
		wl := &innerbean.WebLog{BodyValues: []string{v}}
		if r := waf.CheckXss(req, wl, url.Values{}, hostSafe, globalHost); !r.IsBlock {
			t.Errorf("真 XSS 漏拦: %q", v)
		}
	}
}

// TestCheckXssBodyFieldExclude 验证按字段排除(E)：排除的字段(如 html/content)里的 XSS 不拦，
// 非排除字段的 XSS 仍拦；JSON(按父键名)与表单(按字段名)都生效。
func TestCheckXssBodyFieldExclude(t *testing.T) {
	waf, hostSafe := newTestWafForXSS()
	globalHost := waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME]
	global.GCONFIG_BODY_DETECT_MODE = "block"
	SetBodyDetectFieldExclude("html, content") // 大小写不敏感、去空
	defer func() {
		global.GCONFIG_BODY_DETECT_MODE = "observe"
		SetBodyDetectFieldExclude("")
	}()

	xss := "<script>alert(1)</script>"
	check := func(fields, values []string, fv url.Values) bool {
		req, _ := http.NewRequest("POST", "http://example.com/api", nil)
		wl := &innerbean.WebLog{BodyFields: fields, BodyValues: values}
		if fv == nil {
			fv = url.Values{}
		}
		return waf.CheckXss(req, wl, fv, hostSafe, globalHost).IsBlock
	}

	// JSON：排除字段 html → 不拦；非排除字段 comment → 拦
	if check([]string{"html"}, []string{xss}, nil) {
		t.Error("排除字段 html 的 JSON XSS 不应拦")
	}
	if check([]string{"HTML"}, []string{xss}, nil) { // 大小写不敏感
		t.Error("排除字段大小写不敏感应生效")
	}
	if !check([]string{"comment"}, []string{xss}, nil) {
		t.Error("非排除字段 comment 的 JSON XSS 应拦")
	}
	// 表单：排除字段 content → 不拦；非排除字段 msg → 拦
	if check(nil, nil, url.Values{"content": []string{xss}}) {
		t.Error("排除的表单字段 content 的 XSS 不应拦")
	}
	if !check(nil, nil, url.Values{"msg": []string{xss}}) {
		t.Error("非排除的表单字段 msg 的 XSS 应拦")
	}
}
