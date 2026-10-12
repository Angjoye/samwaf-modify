package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"strings"
	"sync/atomic"
)

// 请求体深度检测（D3/S1 新增的 formValue/JSON 逐值 XSS/SQLi/RCE）受 GCONFIG_BODY_DETECT_MODE 门控：
//   observe(默认) 命中只在日志标记不拦截；block 命中即拦；off 不做请求体深检。
// 查询串(RawQuery/POST_FORM)等既有检测不受此开关影响，始终拦截。

// bodyDetectEnabled 请求体深检是否启用（off 时整体跳过 body 逐值检测）
func bodyDetectEnabled() bool {
	return global.GCONFIG_BODY_DETECT_MODE != "off"
}

// bodyDetectBlocking 是否为拦截模式（block）；否则为 observe 观察
func bodyDetectBlocking() bool {
	return global.GCONFIG_BODY_DETECT_MODE == "block"
}

// markBodyObserve 观察模式命中：只在日志打观察标记(不置 IsBlock)，abnormal 日志模式下会因
// RULE 非空被落库，便于事后筛查(RULE 以“观察模式:”开头，status 非 403)确认无误后再切 block。
func markBodyObserve(weblogbean *innerbean.WebLog, title string) {
	weblogbean.RULE = "观察模式:疑似" + title
}

// ── 按字段排除(E)：已知携带富文本/HTML/代码的字段名，其请求体值跳过深检 ──

const maxBodyDetectFieldExclude = 200 // 排除项数量上限，防误配超长清单

var bodyFieldExclude atomic.Pointer[map[string]struct{}] // RCU：构建完只读，读侧无锁

// SetBodyDetectFieldExclude 解析逗号分隔的字段名(小写去空、去重、封顶)为排除集并原子发布。
// 由配置加载(task_config)调用。
func SetBodyDetectFieldExclude(csv string) {
	m := make(map[string]struct{})
	for _, f := range strings.Split(csv, ",") {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == "" {
			continue
		}
		m[f] = struct{}{}
		if len(m) >= maxBodyDetectFieldExclude {
			break
		}
	}
	bodyFieldExclude.Store(&m)
}

// fieldAt 安全取 fields[i]，越界(如测试只填了 BodyValues 未填 BodyFields)返回 ""。
func fieldAt(fields []string, i int) string {
	if i >= 0 && i < len(fields) {
		return fields[i]
	}
	return ""
}

// isBodyFieldExcluded 字段名是否在排除集(不区分大小写)。空字段名(顶层数组元素)不排除。
func isBodyFieldExcluded(field string) bool {
	if field == "" {
		return false
	}
	m := bodyFieldExclude.Load()
	if m == nil || len(*m) == 0 {
		return false
	}
	_, ok := (*m)[strings.ToLower(field)]
	return ok
}
