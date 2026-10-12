package wafhttpcore

import "strings"

// ── D4/D6：目录穿越 + 敏感文件(LFI)检测 ──
// 先归一化(多轮 URL 解码 → overlong UTF-8 → 反斜杠归一 → ....// 折叠)，再判"是否逃出根"
// 而非见 ../ 就拦：站内相对路径 /assets/theme/../css/app.css 规范化后仍在根内，放行(消除
// path-css 误报)。另叠一张敏感文件表接住"无 ../ 的裸绝对路径 LFI"(/etc/passwd 等，D6)。

// overlong UTF-8 及编码变体 → 规范字符，防 ..%c0%af 之类绕过(URL 解码后是裸字节)。
var traversalOverlong = strings.NewReplacer(
	"\xc0\xaf", "/", "\xe0\x80\xaf", "/", "\xf0\x80\x80\xaf", "/", // '/'
	"\xc0\xae", ".", "\xe0\x80\xae", ".", // '.'
	"\xc1\x9c", "/", "\xe0\x81\x9c", "/", // '\\' → 统一按 '/'
)

// normalizeTraversalPath 归一化用于穿越/LFI 判定的串(输出小写、正斜杠)。
func normalizeTraversalPath(raw string) string {
	if raw == "" {
		return ""
	}
	s := NormalizeForDetection(raw)      // 多轮 URL 解码(含双重编码 %252e)
	s = traversalOverlong.Replace(s)     // overlong UTF-8 → / .
	s = strings.ReplaceAll(s, "\\", "/") // 反斜杠 → 正斜杠
	for strings.Contains(s, "....//") {  // 折叠 ....// → ../("删一次 ../"式绕过)
		s = strings.ReplaceAll(s, "....//", "../")
	}
	return strings.ToLower(s)
}

// escapesRoot 报告归一化后的路径是否"逃出根"(../ 累计深度超过前缀目录深度)。
// /assets/theme/../css/app.css 规范化后仍在根内 → false；../../etc/passwd → true。
func escapesRoot(p string) bool {
	depth := 0
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "", ".":
			// 分隔符 / 当前目录：不改变深度
		case "..":
			depth--
			if depth < 0 {
				return true // 跳出根
			}
		default:
			depth++
		}
	}
	return false
}

// 敏感文件/路径特征(对标 OWASP CRS 930120 lfi-os-files)。均小写。
// absSensitiveFiles 需绝对定位(前导 / 或 // 边界)——避免站内子目录 foo/etc/passwd 误伤。
var absSensitiveFiles = []string{
	"/etc/passwd", "/etc/shadow", "/etc/gshadow",
	"/proc/self/environ", "/proc/self/cmdline", "/proc/version",
	"/root/.bash_history",
	"/.ssh/id_rsa", "/.ssh/id_dsa", "/.ssh/authorized_keys",
	"/windows/win.ini", "/windows/system.ini", "/windows/system32/config/sam",
	"/boot.ini",
}

// nameSensitiveFiles 足够独特的文件名，出现在任意路径段边界即判(前导 / 或串首)。
var nameSensitiveFiles = []string{
	"wp-config.php", ".htpasswd", "web-inf/web.xml", ".git/config", ".svn/entries",
}

// hitSensitiveFile 归一化串是否命中敏感文件表(路径边界匹配，压误报)。
func hitSensitiveFile(normalized string) bool {
	for _, f := range absSensitiveFiles {
		if containsSensitiveToken(normalized, f) {
			return true
		}
	}
	for _, f := range nameSensitiveFiles {
		if containsSensitiveToken(normalized, f) {
			return true
		}
	}
	return false
}

// containsSensitiveToken 在"路径边界"上查子串：左侧为串首或 '/'，右侧为串尾或 / ? # .
// —— 避免 /etc/passwd 命中 /etc/passwderr、/etc/hosts 命中 /etc/hostsettings。
func containsSensitiveToken(s, token string) bool {
	from := 0
	for {
		rel := strings.Index(s[from:], token)
		if rel < 0 {
			return false
		}
		i := from + rel
		leftOK := i == 0 || s[i-1] == '/' || s[i-1] == ':' // ':' 容纳盘符 c:/ 与 scheme
		end := i + len(token)
		rightOK := end == len(s)
		if !rightOK {
			c := s[end]
			rightOK = c == '/' || c == '?' || c == '#' || c == '.'
		}
		if leftOK && rightOK {
			return true
		}
		from = i + 1
	}
}

// HasTraversalOrLFI 归一化后判"逃出根"或命中敏感文件。供 CheckDirTraversal 逐值调用。
func HasTraversalOrLFI(raw string) bool {
	if raw == "" {
		return false
	}
	n := normalizeTraversalPath(raw)
	if escapesRoot(n) {
		return true
	}
	return hitSensitiveFile(n)
}
