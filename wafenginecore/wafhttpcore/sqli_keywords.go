package wafhttpcore

import (
	"regexp"
	"strings"
)

// ── D5-1：MSSQL/DB 高危关键字兜底（对标 OWASP CRS 942 专项规则）──
// libinjection 以低误报为目标，纯 DDL/配置语句缺注入指纹会漏：sp_configure 单独开
// xp_cmdshell 开关、CREATE TABLE + INSERT ... VALUES(0x..) 暂存 hex webshell、bcp
// queryout 导出等。这些词/形态正常输入几乎不出现，命中即判 SQLi（大小写不敏感）。

// 单关键字：均为 MSSQL/DB 特有、非日常英文词。误报核验：逐条跑遍 blaze 33k 白样本命中 0。
// 注意：MySQL 文件原语 into outfile/into dumpfile/load_file 是双刃词——真注入上下文由 libinjection
// 拦，裸关键字会误伤合法 DB 管理流量(blaze 白样本实测 into outfile 命中 20+、load_file 1)，故不入表。
var sqlHighRiskKeywords = []string{
	"xp_cmdshell", "sp_configure", "xp_regwrite", "xp_regread", "xp_regdeletevalue",
	"xp_dirtree", "xp_fileexist", "sp_oacreate", "sp_oamethod",
	"openrowset", "openquery", "opendatasource",
}

// bcp ... queryout（导出/落地 webshell）
var reSqlBcpQueryout = regexp.MustCompile(`(?i)\bbcp\b[^;]*\bqueryout\b`)

// hex blob 写入：VALUES(0x..) 或 INSERT INTO .. 0x..（暂存 hex webshell，libinjection 漏）
var reSqlHexBlob = regexp.MustCompile(`(?i)(values\s*\(\s*0x[0-9a-f]{16,}|insert\s+into\b[^;]{0,300}\b0x[0-9a-f]{16,})`)

// HasHighRiskSQLKeyword 报告串是否含 MSSQL/DB 高危关键字或落地形态。供 CheckSql 逐值调用。
// 先叠一层 URL 解码：JSON 逐值(BodyValues)按 S1 设计不额外解码，url 编码的 VALUES(0x..) 会漏；
// 关键字匹配是精确子串，解码只暴露更多明文、对正常内容不会误命中，故此处安全。
func HasHighRiskSQLKeyword(raw string) bool {
	if raw == "" {
		return false
	}
	s := strings.ToLower(NormalizeForDetection(raw))
	for _, kw := range sqlHighRiskKeywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return reSqlBcpQueryout.MatchString(s) || reSqlHexBlob.MatchString(s)
}
