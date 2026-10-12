package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"SamWaf/global"
)

// 批量任务本地来源的路径收口用例。
// 收口后：只能读「内置 data/import + config.yml 声明的目录」，且软链接不能把读取引到目录之外。

// setBatchImportBase 把程序目录指到临时目录，并按需设置 config 允许清单，用例结束还原。
func setBatchImportBase(t *testing.T, base, allowedDirs string) {
	t.Helper()
	oldBase := batchImportBaseDir
	batchImportBaseDir = func() string { return base }
	oldDirs := global.GCONFIG_BATCH_IMPORT_ALLOWED_DIRS
	global.GCONFIG_BATCH_IMPORT_ALLOWED_DIRS = allowedDirs
	t.Cleanup(func() {
		batchImportBaseDir = oldBase
		global.GCONFIG_BATCH_IMPORT_ALLOWED_DIRS = oldDirs
	})
}

// mustWrite 在指定目录下写一个文件并返回其路径
func mustWrite(t *testing.T, dir, name, content string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("建目录失败: %v", err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("写文件失败: %v", err)
	}
	return p
}

func TestValidateBatchLocalPath_允许目录内正常读(t *testing.T) {
	base := filepath.Join(t.TempDir(), "samwaf")
	setBatchImportBase(t, base, "")
	importDir := filepath.Join(base, "data", "import")
	p := mustWrite(t, importDir, "ip.txt", "1.2.3.4\n")

	got, err := ValidateBatchLocalPath(p)
	if err != nil {
		t.Fatalf("内置导入目录内的文件应放行，实际被拒: %v", err)
	}
	if got == "" {
		t.Fatal("返回路径不应为空")
	}

	// 只填文件名时按内置导入目录解析，方便用户使用
	if _, err = ValidateBatchLocalPath("ip.txt"); err != nil {
		t.Fatalf("相对文件名应按内置导入目录解析，实际被拒: %v", err)
	}
	// 子目录同样在允许范围内
	sub := mustWrite(t, filepath.Join(importDir, "sub"), "ip2.txt", "5.6.7.8\n")
	if _, err = ValidateBatchLocalPath(sub); err != nil {
		t.Fatalf("允许目录的子目录应放行，实际被拒: %v", err)
	}
}

func TestValidateBatchLocalPath_越界路径被拒(t *testing.T) {
	tmp := t.TempDir()
	base := filepath.Join(tmp, "samwaf")
	setBatchImportBase(t, base, "")
	importDir := filepath.Join(base, "data", "import")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// 允许目录之外真实存在的一个文件：证明"被拒"不是因为文件不存在
	outside := mustWrite(t, filepath.Join(tmp, "secret"), "shadow.txt", "root:x:0:0")

	cases := []struct {
		name string
		path string
	}{
		{"空字符串", ""},
		{"全是空格", "   "},
		{"含换行", filepath.Join(importDir, "a\nb.txt")},
		{"含NUL", filepath.Join(importDir, "a\x00b.txt")},
		{"以分隔符结尾", importDir + string(filepath.Separator)},
		{"允许目录之外的绝对路径", outside},
		{"相对路径上跳逃逸", filepath.Join("..", "..", "secret", "shadow.txt")},
		{"绝对路径带上跳段", filepath.Join(importDir, "..", "..", "..", "secret", "shadow.txt")},
		{"允许根目录本身", importDir},
		{"目录不是普通文件", filepath.Join(importDir, ".")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, err := ValidateBatchLocalPath(c.path); err == nil {
				t.Fatalf("期望拒绝 %q，实际通过并返回 %q", c.path, got)
			}
		})
	}
}

func TestValidateBatchLocalPath_前缀相同的兄弟目录被拒(t *testing.T) {
	tmp := t.TempDir()
	base := filepath.Join(tmp, "samwaf")
	setBatchImportBase(t, base, "")
	// data/import_evil 与 data/import 共享字符串前缀，只做 HasPrefix 会误放行
	evil := mustWrite(t, filepath.Join(base, "data", "import_evil"), "x.txt", "1.2.3.4")
	if got, err := ValidateBatchLocalPath(evil); err == nil {
		t.Fatalf("同前缀兄弟目录必须被拒，实际通过并返回 %q", got)
	}
}

func TestValidateBatchLocalPath_config声明的目录被放行(t *testing.T) {
	tmp := t.TempDir()
	base := filepath.Join(tmp, "samwaf")
	extra := filepath.Join(tmp, "mirror")
	setBatchImportBase(t, base, extra)
	p := mustWrite(t, extra, "list.txt", "1.2.3.4\n")

	if _, err := ValidateBatchLocalPath(p); err != nil {
		t.Fatalf("config 声明的目录应放行，实际被拒: %v", err)
	}

	// 清单清空后立刻恢复 fail-closed
	global.GCONFIG_BATCH_IMPORT_ALLOWED_DIRS = ""
	if got, err := ValidateBatchLocalPath(p); err == nil {
		t.Fatalf("清空允许清单后必须拒绝，实际通过并返回 %q", got)
	}
}

func TestValidateBatchLocalPath_软链接逃逸被拒(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 建软链接需要额外权限，跳过")
	}
	tmp := t.TempDir()
	base := filepath.Join(tmp, "samwaf")
	setBatchImportBase(t, base, "")
	importDir := filepath.Join(base, "data", "import")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := mustWrite(t, filepath.Join(tmp, "secret"), "shadow.txt", "root:x:0:0")

	// 终点软链接：允许目录内的文件名，指向目录之外
	link := filepath.Join(importDir, "innocent.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("当前环境无法创建软链接: %v", err)
	}
	if got, err := ValidateBatchLocalPath(link); err == nil {
		t.Fatalf("指向允许目录之外的软链接必须被拒，实际通过并返回 %q", got)
	}

	// 中间目录软链接：allowed/linkdir -> /tmp/secret，再读 allowed/linkdir/shadow.txt
	linkDir := filepath.Join(importDir, "linkdir")
	if err := os.Symlink(filepath.Join(tmp, "secret"), linkDir); err != nil {
		t.Skipf("当前环境无法创建软链接: %v", err)
	}
	if got, err := ValidateBatchLocalPath(filepath.Join(linkDir, "shadow.txt")); err == nil {
		t.Fatalf("经软链接目录读到允许目录之外必须被拒，实际通过并返回 %q", got)
	}
}

func TestPrecheckBatchLocalPath_文件未就位也放行但越界仍拒(t *testing.T) {
	tmp := t.TempDir()
	base := filepath.Join(tmp, "samwaf")
	setBatchImportBase(t, base, "")
	importDir := filepath.Join(base, "data", "import")

	// 保存任务时文件还没放上来：路径策略合法即放行
	if err := PrecheckBatchLocalPath(filepath.Join(importDir, "not-yet.txt")); err != nil {
		t.Fatalf("允许目录内的未创建文件在保存阶段应放行，实际被拒: %v", err)
	}
	// 越界路径无论文件在不在都必须拒
	if err := PrecheckBatchLocalPath(filepath.Join(tmp, "elsewhere", "x.txt")); err == nil {
		t.Fatal("越界路径在保存阶段就必须被拒")
	}
}
