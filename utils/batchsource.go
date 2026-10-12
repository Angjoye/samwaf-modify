package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"SamWaf/global"
)

// 批量任务「本地路径」来源的路径收口。

// batchImportDefaultSubDir 内置默认导入目录（相对程序目录），恒允许。
const batchImportDefaultSubDir = "data/import"

// batchImportBaseDir 取 SamWaf 程序所在目录，单测里可替换。
var batchImportBaseDir = GetCurrentDir

// BatchImportDefaultDir 返回内置默认导入目录的绝对路径，供报错文案与前端提示使用。
func BatchImportDefaultDir() string {
	if base := batchImportBaseDir(); base != "" {
		if absBase, err := filepath.Abs(base); err == nil {
			return filepath.Clean(filepath.Join(absBase, batchImportDefaultSubDir))
		}
	}
	return batchImportDefaultSubDir
}

// batchImportAllowedRoots 返回允许的导入根目录（已 Clean 的绝对路径）：
// 内置默认 <程序目录>/data/import（恒允许）+ config.yml security.batch_import_allowed_dirs。
func batchImportAllowedRoots() []string {
	roots := make([]string, 0, 4)
	if d := BatchImportDefaultDir(); d != "" && filepath.IsAbs(d) {
		roots = append(roots, d)
	}
	for _, d := range strings.Split(global.GCONFIG_BATCH_IMPORT_ALLOWED_DIRS, ",") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		cleaned := filepath.Clean(d)
		if !filepath.IsAbs(cleaned) {
			continue // 只接受绝对目录，相对目录基准不可控，忽略
		}
		roots = append(roots, cleaned)
	}
	return roots
}

// underAnyRoot 判断路径是否落在任一根目录之下（等于根目录本身不算，来源必须是文件）。
func underAnyRoot(roots []string, p string) bool {
	for _, root := range roots {
		if pathUnder(root, p) {
			return true
		}
	}
	return false
}

// resolveBatchLocalPath 只做「与文件系统状态无关」的路径判定：规范化 + 允许目录前缀锚定。
// 相对路径按内置默认导入目录解析（用户只填文件名即可），随后与绝对路径走同一套判定。
// `..` 在 filepath.Clean 阶段就已被折叠，所以 data/import/../../etc/passwd 会落在根目录之外被拒。
func resolveBatchLocalPath(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", fmt.Errorf("来源路径为空")
	}
	if strings.ContainsAny(p, "\r\n\x00") {
		return "", fmt.Errorf("来源路径包含非法字符(换行或空字符)")
	}
	// 相对路径统一挂到内置默认目录下再判定，避免基准目录取决于进程工作目录
	if !filepath.IsAbs(filepath.Clean(p)) {
		base := BatchImportDefaultDir()
		if base == "" || !filepath.IsAbs(base) {
			return "", fmt.Errorf("无法确定内置导入目录，请填写绝对路径")
		}
		p = filepath.Join(base, p)
	}

	cleaned, err := cleanAbsFilePath(p)
	if err != nil {
		return "", err
	}
	if !underAnyRoot(batchImportAllowedRoots(), cleaned) {
		return "", fmt.Errorf("来源路径不在允许目录内（请把文件放进内置导入目录 %s，该目录不存在时请手工创建；或在 config.yml 的 security.batch_import_allowed_dirs 声明目标目录）: %s",
			BatchImportDefaultDir(), cleaned)
	}
	return cleaned, nil
}

// checkBatchLocalSymlink 软链接逃逸判定：字面路径在允许目录内，不代表真正读到的文件也在。
// EvalSymlinks 会一路解开中间目录与终点的软链接，拿到真实落点后再判一次。
// 返回解析后的真实路径。
func checkBatchLocalSymlink(cleaned string) (string, error) {
	realPath, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", fmt.Errorf("来源文件不存在或不可访问: %s, %v", cleaned, err)
	}
	realPath = filepath.Clean(realPath)
	roots := batchImportAllowedRoots()
	realRoots := make([]string, 0, len(roots))
	for _, root := range roots {
		if rr, e := filepath.EvalSymlinks(root); e == nil {
			realRoots = append(realRoots, filepath.Clean(rr))
		} else {
			realRoots = append(realRoots, root) // 目录尚未创建时按字面根比对
		}
	}
	if !underAnyRoot(realRoots, realPath) {
		return "", fmt.Errorf("来源路径经软链接指向了允许目录之外，已拒绝: %s", cleaned)
	}
	return realPath, nil
}

// PrecheckBatchLocalPath 保存批量任务时的路径预检：只判路径策略，不要求文件已存在
// （用户完全可能先建任务、再把文件放进去）。文件已存在时顺带查一次软链接逃逸，
// 让明显配错的情况在保存阶段就报出来。真正的读取前判定见 ValidateBatchLocalPath。
func PrecheckBatchLocalPath(raw string) error {
	cleaned, err := resolveBatchLocalPath(raw)
	if err != nil {
		return err
	}
	if _, statErr := os.Lstat(cleaned); statErr != nil {
		return nil // 文件还没放上来，保存阶段不拦
	}
	_, err = checkBatchLocalSymlink(cleaned)
	return err
}

// ValidateBatchLocalPath 校验并规范化批量任务的本地来源路径，返回可直接打开的绝对路径。
// 执行（读取）前调用，是真正的安全边界：
//  1. 基本合法性（非空、无控制字符、不以分隔符结尾、指向具体文件）；
//  2. Clean 后必须落在允许根目录之下（前缀锚定）；
//  3. 解析软链接后的**真实**路径同样必须落在允许根目录之下——只判字面路径的话，
//     在允许目录里放一个指向 /etc/shadow 的软链接就能整个绕过；
//  4. 目标必须是普通文件：目录读不出内容，FIFO/设备会把批量任务永久挂住。
func ValidateBatchLocalPath(raw string) (string, error) {
	cleaned, err := resolveBatchLocalPath(raw)
	if err != nil {
		return "", err
	}
	realPath, err := checkBatchLocalSymlink(cleaned)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(realPath)
	if err != nil {
		return "", fmt.Errorf("来源文件不可访问: %s, %v", cleaned, err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("来源必须是普通文件（目录/管道/设备不允许）: %s", cleaned)
	}
	return realPath, nil
}
