package batch

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
)

// 批量任务数据源的边界用例
// 未知执行方式静默不执行。

// allowImportDir 把 config 允许清单指向一个临时目录，用例结束还原
func allowImportDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := global.GCONFIG_BATCH_IMPORT_ALLOWED_DIRS
	global.GCONFIG_BATCH_IMPORT_ALLOWED_DIRS = dir
	t.Cleanup(func() { global.GCONFIG_BATCH_IMPORT_ALLOWED_DIRS = old })
	return dir
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("写文件失败: %v", err)
	}
	return p
}

func localTask(source string) model.BatchTask {
	return model.BatchTask{
		BatchType:          enums.BATCHTASK_IPDENY,
		BatchSourceType:    enums.BATCHTASK_SOURCETYPE_LOCAL,
		BatchSource:        source,
		BatchExecuteMethod: enums.BATCHTASK_EXECUTEMETHODAPPEND,
	}
}

func remoteTask(source string) model.BatchTask {
	return model.BatchTask{
		BatchType:          enums.BATCHTASK_IPDENY,
		BatchSourceType:    enums.BATCHTASK_SOURCETYPE_REMOTE,
		BatchSource:        source,
		BatchExecuteMethod: enums.BATCHTASK_EXECUTEMETHODAPPEND,
	}
}

func TestOpenSource_允许目录内的本地文件可读(t *testing.T) {
	dir := allowImportDir(t)
	p := writeFile(t, dir, "ip.txt", "1.2.3.4\n5.6.7.8\n")

	rc, expectedLen, err := openSource(localTask(p))
	if err != nil {
		t.Fatalf("允许目录内的文件应可读，实际被拒: %v", err)
	}
	defer rc.Close()
	if expectedLen != 16 {
		t.Fatalf("本地来源应返回真实文件大小，实际 %d", expectedLen)
	}
	data, _ := io.ReadAll(rc)
	if !strings.Contains(string(data), "1.2.3.4") {
		t.Fatalf("读到的内容不对: %q", string(data))
	}
}

func TestOpenSource_越界本地路径被拒(t *testing.T) {
	dir := allowImportDir(t)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("root:x:0:0"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{
		outside,
		filepath.Join(dir, "..", filepath.Base(filepath.Dir(outside)), "secret.txt"),
		"/etc/passwd",
		"/proc/self/environ",
		`C:\Windows\win.ini`,
	} {
		rc, _, err := openSource(localTask(name))
		if err == nil {
			rc.Close()
			t.Fatalf("越界路径 %q 必须被拒", name)
		}
		if !strings.Contains(err.Error(), "本地来源被拒绝") {
			t.Fatalf("拒绝原因应指明是来源被拒，实际: %v", err)
		}
	}
}

func TestOpenSource_内网与云元数据地址被拒(t *testing.T) {
	old := global.GCONFIG_OUTBOUND_ALLOWED_HOSTS
	global.GCONFIG_OUTBOUND_ALLOWED_HOSTS = ""
	t.Cleanup(func() { global.GCONFIG_OUTBOUND_ALLOWED_HOSTS = old })

	for _, u := range []string{
		"http://127.0.0.1:26666/api/v1/batch_task/list",
		"http://[::1]/x",
		"http://10.0.0.1/x",
		"http://192.168.0.1/x",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"file:///etc/passwd",
		"gopher://127.0.0.1:6379/_INFO",
	} {
		rc, _, err := openSource(remoteTask(u))
		if err == nil {
			rc.Close()
			t.Fatalf("地址 %q 必须被拒", u)
		}
		if !strings.Contains(err.Error(), "远端来源被拒绝") {
			t.Fatalf("拒绝原因应指明是来源被拒，实际: %v", err)
		}
	}
}

func TestLoadSource_超出上限拒绝整批(t *testing.T) {
	dir := allowImportDir(t)
	p := writeFile(t, dir, "big.txt", strings.Repeat("1.2.3.4\n", 100)) // 800 字节 / 100 行

	// 字节超限
	if _, err := loadSource(localTask(p), BatchProcessorConfig{MaxBytes: 100}); err == nil {
		t.Fatal("超出字节上限必须被拒")
	} else if !strings.Contains(err.Error(), "大小上限") {
		t.Fatalf("错误信息应说明是大小超限，实际: %v", err)
	}

	// 行数超限
	if _, err := loadSource(localTask(p), BatchProcessorConfig{MaxLines: 10}); err == nil {
		t.Fatal("超出行数上限必须被拒")
	} else if !strings.Contains(err.Error(), "行数") {
		t.Fatalf("错误信息应说明是行数超限，实际: %v", err)
	}

	// 恰好在上限内应通过
	if data, err := loadSource(localTask(p), BatchProcessorConfig{MaxBytes: 800, MaxLines: 100}); err != nil {
		t.Fatalf("上限内应通过，实际被拒: %v", err)
	} else if len(data) != 800 {
		t.Fatalf("读到的字节数不对: %d", len(data))
	}
}

func TestLoadSource_超长行被拒(t *testing.T) {
	dir := allowImportDir(t)
	// bufio.Scanner 单行上限 64KB。以前这种行会让扫描在中途报错，
	// 而报错之前的数据已经落库 —— 变成半截导入。现在必须在读取阶段就整批拒绝。
	p := writeFile(t, dir, "long.txt", "1.2.3.4\n"+strings.Repeat("A", 70*1024)+"\n5.6.7.8\n")

	if _, err := loadSource(localTask(p), BatchProcessorConfig{}); err == nil {
		t.Fatal("超长行必须被拒")
	} else if !strings.Contains(err.Error(), "超长行") {
		t.Fatalf("错误信息应说明是超长行，实际: %v", err)
	}
}

func TestLoadSource_声明长度与实际不符被拒(t *testing.T) {
	dir := allowImportDir(t)
	p := writeFile(t, dir, "ip.txt", "1.2.3.4\n2.3.4.5\n")

	// 本地文件正常情况下读到的字节数与 stat 一致
	if _, err := loadSource(localTask(p), BatchProcessorConfig{}); err != nil {
		t.Fatalf("正常文件应通过，实际: %v", err)
	}
	// 字节上限恰好卡在文件大小之下时，读到的是被截断的一半 —— 必须按超限拒绝，
	// 绝不能把半份数据当成完整的源交给覆盖模式去做差集删除
	if _, err := loadSource(localTask(p), BatchProcessorConfig{MaxBytes: 8}); err == nil {
		t.Fatal("被截断的读取必须被拒")
	}
}

func TestMaxLineLen(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"abc", 3},
		{"abc\n", 3},
		{"ab\ncdef", 4},
		{"ab\ncdef\n", 4},
		{"\n\n", 0},
	}
	for _, c := range cases {
		if got := maxLineLen([]byte(c.in)); got != c.want {
			t.Fatalf("maxLineLen(%q)=%d 期望 %d", c.in, got, c.want)
		}
	}
}

func TestProcessBatchTask_非法来源类型被拒(t *testing.T) {
	dir := allowImportDir(t)
	p := writeFile(t, dir, "ip.txt", "1.2.3.4\n")

	task := localTask(p)
	task.BatchSourceType = "file" // 存量库里可能留着的非法值
	err := ProcessBatchTask(task, &IPDenyProcessor{}, BatchProcessorConfig{BatchSize: 10, LogPrefix: "test"})
	if err == nil {
		t.Fatal("非法来源类型必须报错")
	}
	if !strings.Contains(err.Error(), "来源类型非法") {
		t.Fatalf("错误信息应说明来源类型非法，实际: %v", err)
	}
}

func TestCountRawLines(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"a", 1},
		{"a\n", 1},
		{"a\nb", 2},
		{"a\nb\n", 2},
		{"\n\n", 2},
	}
	for _, c := range cases {
		if got := countRawLines([]byte(c.in)); got != c.want {
			t.Fatalf("countRawLines(%q)=%d 期望 %d", c.in, got, c.want)
		}
	}
}

func TestProcessBatchTask_非法执行方式被拒(t *testing.T) {
	dir := allowImportDir(t)
	p := writeFile(t, dir, "ip.txt", "1.2.3.4\n")

	task := localTask(p)
	task.BatchExecuteMethod = "sync" // 存量库里可能留着的非法值
	err := ProcessBatchTask(task, &IPDenyProcessor{}, BatchProcessorConfig{BatchSize: 10, LogPrefix: "test"})
	if err == nil {
		t.Fatal("非法执行方式必须报错，而不是静默什么都不做")
	}
	if !strings.Contains(err.Error(), "执行方式非法") {
		t.Fatalf("错误信息应说明执行方式非法，实际: %v", err)
	}

	// 来源被拒时同样要报错，且必须在碰数据库之前就返回
	bad := localTask(filepath.Join(t.TempDir(), "outside.txt"))
	if err = ProcessBatchTask(bad, &IPDenyProcessor{}, BatchProcessorConfig{BatchSize: 10, LogPrefix: "test"}); err == nil {
		t.Fatal("越界来源必须报错")
	}
}
