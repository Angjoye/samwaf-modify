package waf_service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"SamWaf/enums"
	"SamWaf/global"
)

// 批量任务保存侧的边界用例。

func withAllowedImportDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	oldDirs := global.GCONFIG_BATCH_IMPORT_ALLOWED_DIRS
	oldHosts := global.GCONFIG_OUTBOUND_ALLOWED_HOSTS
	global.GCONFIG_BATCH_IMPORT_ALLOWED_DIRS = dir
	global.GCONFIG_OUTBOUND_ALLOWED_HOSTS = ""
	t.Cleanup(func() {
		global.GCONFIG_BATCH_IMPORT_ALLOWED_DIRS = oldDirs
		global.GCONFIG_OUTBOUND_ALLOWED_HOSTS = oldHosts
	})
	return dir
}

func TestCheckTaskInput_非法枚举被拒(t *testing.T) {
	dir := withAllowedImportDir(t)
	ok := filepath.Join(dir, "ip.txt")
	svc := WafBatchServiceApp

	cases := []struct {
		name                                    string
		bType, srcType, trigger, method, source string
	}{
		{"任务类型为空", "", enums.BATCHTASK_SOURCETYPE_LOCAL, enums.BATCHTASK_TRIGGERTYPE_MANUAL, enums.BATCHTASK_EXECUTEMETHODAPPEND, ok},
		{"任务类型未知", "rule", enums.BATCHTASK_SOURCETYPE_LOCAL, enums.BATCHTASK_TRIGGERTYPE_MANUAL, enums.BATCHTASK_EXECUTEMETHODAPPEND, ok},
		{"来源类型未知", enums.BATCHTASK_IPDENY, "ftp", enums.BATCHTASK_TRIGGERTYPE_MANUAL, enums.BATCHTASK_EXECUTEMETHODAPPEND, ok},
		{"触发类型未知", enums.BATCHTASK_IPDENY, enums.BATCHTASK_SOURCETYPE_LOCAL, "auto", enums.BATCHTASK_EXECUTEMETHODAPPEND, ok},
		{"执行方式未知", enums.BATCHTASK_IPDENY, enums.BATCHTASK_SOURCETYPE_LOCAL, enums.BATCHTASK_TRIGGERTYPE_MANUAL, "sync", ok},
		{"执行方式为空", enums.BATCHTASK_IPDENY, enums.BATCHTASK_SOURCETYPE_LOCAL, enums.BATCHTASK_TRIGGERTYPE_MANUAL, "", ok},
		{"来源为空", enums.BATCHTASK_IPDENY, enums.BATCHTASK_SOURCETYPE_LOCAL, enums.BATCHTASK_TRIGGERTYPE_MANUAL, enums.BATCHTASK_EXECUTEMETHODAPPEND, "  "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := svc.checkTaskInput(c.bType, c.srcType, c.trigger, c.method, c.source); err == nil {
				t.Fatal("非法输入必须被拒")
			}
		})
	}
}

func TestCheckTaskInput_合法输入通过(t *testing.T) {
	dir := withAllowedImportDir(t)
	p := filepath.Join(dir, "ip.txt")
	if err := os.WriteFile(p, []byte("1.2.3.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	svc := WafBatchServiceApp

	if err := svc.checkTaskInput(enums.BATCHTASK_IPDENY, enums.BATCHTASK_SOURCETYPE_LOCAL,
		enums.BATCHTASK_TRIGGERTYPE_CRON, enums.BATCHTASK_EXECUTEMETHODAPPEND, p); err != nil {
		t.Fatalf("允许目录内的本地来源应通过，实际: %v", err)
	}
	if err := svc.checkTaskInput(enums.BATCHTASK_IPDENY, enums.BATCHTASK_SOURCETYPE_REMOTE,
		enums.BATCHTASK_TRIGGERTYPE_CRON, enums.BATCHTASK_EXECUTEMETHODOVERWRITE, "https://8.8.8.8/list.txt"); err != nil {
		t.Fatalf("公网来源地址应通过，实际: %v", err)
	}
}

func TestCheckTaskInput_越界来源与内网地址被拒(t *testing.T) {
	withAllowedImportDir(t)
	svc := WafBatchServiceApp

	// 本地：允许目录之外
	err := svc.checkTaskInput(enums.BATCHTASK_IPDENY, enums.BATCHTASK_SOURCETYPE_LOCAL,
		enums.BATCHTASK_TRIGGERTYPE_MANUAL, enums.BATCHTASK_EXECUTEMETHODAPPEND, filepath.Join(t.TempDir(), "x.txt"))
	if err == nil {
		t.Fatal("允许目录之外的本地来源必须被拒")
	}

	// 远端：回环/内网/云元数据/非 http 协议
	for _, u := range []string{
		"http://127.0.0.1:26666/x",
		"http://10.1.2.3/x",
		"http://169.254.169.254/latest/meta-data/",
		"file:///etc/passwd",
	} {
		if err = svc.checkTaskInput(enums.BATCHTASK_IPDENY, enums.BATCHTASK_SOURCETYPE_REMOTE,
			enums.BATCHTASK_TRIGGERTYPE_MANUAL, enums.BATCHTASK_EXECUTEMETHODAPPEND, u); err == nil {
			t.Fatalf("地址 %q 必须被拒", u)
		} else if !strings.Contains(err.Error(), "不被允许") {
			t.Fatalf("拒绝原因应指明地址不被允许，实际: %v", err)
		}
	}
}

func TestValidateChannelURL_威胁情报订阅同款收口(t *testing.T) {
	oldHosts := global.GCONFIG_OUTBOUND_ALLOWED_HOSTS
	global.GCONFIG_OUTBOUND_ALLOWED_HOSTS = ""
	t.Cleanup(func() { global.GCONFIG_OUTBOUND_ALLOWED_HOSTS = oldHosts })

	for _, u := range []string{"", "  ", "http://127.0.0.1/list", "http://169.254.169.254/x", "file:///etc/passwd"} {
		if err := validateChannelURL(u); err == nil {
			t.Fatalf("订阅地址 %q 必须被拒", u)
		}
	}
	if err := validateChannelURL("https://8.8.8.8/list.txt"); err != nil {
		t.Fatalf("公网订阅地址应通过，实际: %v", err)
	}

	// 带外声明后内网镜像可用
	global.GCONFIG_OUTBOUND_ALLOWED_HOSTS = "10.9.8.7"
	if err := validateChannelURL("http://10.9.8.7/list.txt"); err != nil {
		t.Fatalf("已带外声明的内网镜像应通过，实际: %v", err)
	}
}
