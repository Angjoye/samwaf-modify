package response

import (
	"SamWaf/common/diagstat"
	"SamWaf/wafdiag"
)

// WafDiagnosticDbInfo 数据库占用概览（诊断视角只关心体量，不带连接池细节）。
type WafDiagnosticDbInfo struct {
	Name       string  `json:"name"`
	FileSizeMB float64 `json:"file_size_mb"`
}

// WafDiagnosticSnapshot 运行诊断实时快照。
type WafDiagnosticSnapshot struct {
	Version    string                   `json:"version"`     // 版本号
	VersionTag string                   `json:"version_tag"` // 版本号名称
	OS         string                   `json:"os"`
	Arch       string                   `json:"arch"`
	Process    wafdiag.ProcessStat      `json:"process"`
	Runtime    wafdiag.RuntimeStat      `json:"runtime"`
	Components []diagstat.ComponentStat `json:"components"`
	Databases  []WafDiagnosticDbInfo    `json:"databases"`
	SampledAt  int64                    `json:"sampled_at"`
}

// WafDiagnosticTrend 趋势数据。
type WafDiagnosticTrend struct {
	IntervalSec int                  `json:"interval_sec"`
	Points      []wafdiag.TrendPoint `json:"points"`
}
