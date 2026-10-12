package wafhttpcore

import (
	"strings"
	"testing"
)

func TestExtractJSONStringValues(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		want    []string // 期望包含的（子串）值
		wantNil bool
	}{
		{
			name: "普通JSON只取字符串值不取键名",
			body: `{"name":"tom","age":18,"ok":true,"tags":["a","b"]}`,
			want: []string{"tom", "a", "b"}, // age/ok 非字符串跳过；键名不取
		},
		{
			name: "JSON字符串值含script标签",
			body: `{"x":"<script>alert(1)</script>"}`,
			want: []string{"<script>alert(1)</script>"},
		},
		{
			name: "值里的URL编码不再叠解码(避免正常埋点误报)",
			body: `{"x":"%3Cimg%20src=x%20onerror=1%3E"}`,
			want: []string{"%3Cimg%20src=x%20onerror=1%3E"}, // 保持原样，不 URL 解码
		},
		{
			name: "嵌套对象/数组递归取值",
			body: `{"a":{"b":["c",{"d":"e"}]}}`,
			want: []string{"c", "e"},
		},
		{
			name:    "非JSON返回nil(正常表单/文本不参与)",
			body:    `a=1&b=2`,
			wantNil: true,
		},
		{
			name:    "空串返回nil",
			body:    "",
			wantNil: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ExtractJSONStringValues(c.body)
			if c.wantNil {
				if got != nil {
					t.Errorf("期望 nil，得到 %v", got)
				}
				return
			}
			joined := strings.Join(got, "\x00")
			for _, w := range c.want {
				if !strings.Contains(joined, w) {
					t.Errorf("期望包含值 %q，实际提取=%v", w, got)
				}
			}
		})
	}
}

// TestExtractJSONStringValues_UnicodeEscape 验证 JSON \uXXXX 转义会被 json 解析还原，
// 从而覆盖 {"x":"<script>..."} 这类绕过（body 用字节构造反斜杠，避免源码转义歧义）。
func TestExtractJSONStringValues_UnicodeEscape(t *testing.T) {
	bs := string([]byte{0x5c}) // 反斜杠
	body := `{"x":"` + bs + `u003cscript` + bs + `u003ealert(1)` + bs + `u003c/script` + bs + `u003e"}`
	got := ExtractJSONStringValues(body)
	joined := strings.Join(got, "\x00")
	if !strings.Contains(joined, "<script>alert(1)</script>") {
		t.Errorf("期望 JSON 转义被解成 <script>...，实际提取=%v", got)
	}
}

func TestIsJSONBody(t *testing.T) {
	yes := []string{`{"a":1}`, ` [1,2,3] `, `{"x":{"y":"z"}}`}
	no := []string{"", "a=1&b=2", "hello", "123", `{"a":1`}
	for _, s := range yes {
		if !IsJSONBody(s) {
			t.Errorf("IsJSONBody(%q)=false，期望 true", s)
		}
	}
	for _, s := range no {
		if IsJSONBody(s) {
			t.Errorf("IsJSONBody(%q)=true，期望 false", s)
		}
	}
}

func TestIsStructuredDataValue(t *testing.T) {
	// 结构化数据（跳过 SQLi）
	structured := []string{
		`["[Capi Success]",{"body":{}}]`,
		`{"serviceType":"ba"}`,
		"https://rs.fullstory.com/rec/bundle/v2?OrgId=B9193&UserId=4b2b7c84-aa5f",
		"HTTP://Example.com/x",
	}
	// 仍需检测的普通值（不跳过）
	normal := []string{
		"1' or '1'='1",
		"admin",
		"union select password from users",
		"",
	}
	for _, s := range structured {
		if !IsStructuredDataValue(s) {
			t.Errorf("IsStructuredDataValue(%q)=false，期望 true(应跳过SQLi)", s)
		}
	}
	for _, s := range normal {
		if IsStructuredDataValue(s) {
			t.Errorf("IsStructuredDataValue(%q)=true，期望 false(应检测)", s)
		}
	}
}

func TestExtractJSONFieldValues(t *testing.T) {
	fields, values := ExtractJSONFieldValues(`{"html":"<b>hi</b>","n":1,"a":{"content":"x"},"arr":["p","q"]}`)
	if len(fields) != len(values) {
		t.Fatalf("fields/values 长度不一致: %d vs %d", len(fields), len(values))
	}
	got := map[string]string{}
	for i := range values {
		got[values[i]] = fields[i]
	}
	// 值 → 直接父键名
	want := map[string]string{"<b>hi</b>": "html", "x": "content", "p": "arr", "q": "arr"}
	for v, f := range want {
		if got[v] != f {
			t.Errorf("值 %q 的父键=%q，期望 %q", v, got[v], f)
		}
	}
	// 数字值不提取
	if _, ok := got["1"]; ok {
		t.Error("数字值不应被提取")
	}
}

// S1 二期：HTML 实体 + JS unicode 解码
func TestNormalizeForXSSDetection(t *testing.T) {
	cases := []struct{ in, wantContains string }{
		{"&lt;script&gt;alert(1)&lt;/script&gt;", "<script>"},         // htmlent 命名实体
		{"&#60;script&#62;", "<script>"},                              // 十进制实体
		{"&#x3c;svg onload&#x3d;alert(1)&#x3e;", "<svg onload=alert"}, // 十六进制实体
		{`<script>alert(1)</script>`, "<script>"},                     // unicode_js \u00XX
		{`\x3cimg src=x onerror=alert(1)\x3e`, "<img src=x onerror="}, // \xXX
		{"img&#40;1&#41;", "img(1)"},                                  // &#40; &#41; → ( )
	}
	for _, c := range cases {
		got := NormalizeForXSSDetection(c.in)
		if !strings.Contains(got, c.wantContains) {
			t.Errorf("NormalizeForXSSDetection(%q)=%q, 应含 %q", c.in, got, c.wantContains)
		}
	}
	// 正常文本不应被破坏（无实体/转义则原样）
	for _, s := range []string{"hello world", "price 100", "a=1&b=2"} {
		if got := NormalizeForXSSDetection(s); got != s {
			t.Errorf("正常文本被改动: %q -> %q", s, got)
		}
	}
}
