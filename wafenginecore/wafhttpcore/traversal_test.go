package wafhttpcore

import "testing"

// D4+D6：目录穿越/LFI —— 7 条真漏样本(SamWafPoc traversal 语料)必须命中，
// path-css 误报样本及常见正常值必须放行。
func TestHasTraversalOrLFI(t *testing.T) {
	malicious := map[string]string{
		"unix-passwd":   "../../../../etc/passwd",
		"enc-passwd":    "..%2f..%2f..%2fetc%2fpasswd",
		"dotdot-slash":  "....//....//etc/passwd",
		"abs-passwd":    "/etc/passwd", // D6 裸绝对路径
		"win-ini":       "..\\..\\..\\windows\\win.ini",
		"double-enc":    "%252e%252e%252fetc%252fpasswd",
		"utf8-overlong": "..%c0%af..%c0%afetc/passwd",
		// 额外 D6 敏感文件
		"abs-shadow":  "/etc/shadow",
		"abs-environ": "/proc/self/environ",
		"win-abs-ini": "C:\\windows\\win.ini",
		"wp-config":   "/var/www/wp-config.php",
	}
	for name, p := range malicious {
		if !HasTraversalOrLFI(p) {
			t.Errorf("应命中但漏过 [%s]: %q", name, p)
		}
	}

	benign := map[string]string{
		"path-css":     "/assets/theme/../css/app.css", // 站内相对，规范化后不逃根
		"normal-path":  "/api/v1/users/123",
		"version":      "1.2.3",
		"abs-url":      "https://cdn.example.com/a/../b/app.js", // 绝对 URL 内的 .. 不逃根
		"query-normal": "keyword=价格100元",
		"dotfile":      "app.config.js",
		"subdir-etc":   "uploads/etc/report.csv", // 站内 etc 子目录，非系统 /etc
		"env-word":     "/api/environment/list",  // 不应被 .env 之类误伤
	}
	for name, p := range benign {
		if HasTraversalOrLFI(p) {
			t.Errorf("应放行但误拦 [%s]: %q", name, p)
		}
	}
}

func TestEscapesRoot(t *testing.T) {
	esc := []string{"../x", "../../etc/passwd", "a/../../b", "/../etc"}
	for _, p := range esc {
		if !escapesRoot(p) {
			t.Errorf("应判逃根: %q", p)
		}
	}
	stay := []string{"/assets/theme/../css/app.css", "a/b/../c", "/etc/passwd", "foo/bar", ""}
	for _, p := range stay {
		if escapesRoot(p) {
			t.Errorf("应在根内: %q", p)
		}
	}
}

func TestContainsSensitiveToken(t *testing.T) {
	// 边界匹配：命中
	hit := [][2]string{
		{"/etc/passwd", "/etc/passwd"},
		{"/var/www/wp-config.php", "wp-config.php"},
		{"/x/.git/config", ".git/config"},
	}
	for _, c := range hit {
		if !containsSensitiveToken(c[0], c[1]) {
			t.Errorf("应命中 token %q in %q", c[1], c[0])
		}
	}
	// 边界匹配：不命中(前缀/子串误伤)
	miss := [][2]string{
		{"/etc/passwderr", "/etc/passwd"},   // 右边界
		{"/app/etc/passwd", "/etc/passwd"},  // 左边界(子目录 app/etc)
		{"/etc/hostsettings", "/etc/hosts"}, // 若未来加 hosts 也不误伤
	}
	for _, c := range miss {
		if containsSensitiveToken(c[0], c[1]) {
			t.Errorf("不应命中 token %q in %q", c[1], c[0])
		}
	}
}
