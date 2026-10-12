package wafhttpcore

import "testing"

// D5-1：MSSQL/DB 高危关键字兜底 —— libinjection 漏的纯 DDL/配置语句必须命中，正常输入不误报。
func TestHasHighRiskSQLKeyword(t *testing.T) {
	hit := map[string]string{
		// SamWafPoc sqli 语料 5 条 MSSQL 提权链（含 libinjection 漏的 spconfig-only / webshell-stage）
		"xpcmdshell":     `1;exec master..xp_cmdshell 'whoami';--`,
		"enable-xp":      `1;exec sp_configure 'show advanced options',1;reconfigure;exec sp_configure 'xp_cmdshell',1;reconfigure;--`,
		"spconfig-only":  `1;exec sp_configure 'xp_cmdshell',1;reconfigure;--`,
		"webshell-stage": `1;CREATE TABLE g3(a varchar(8000));INSERT INTO g3 VALUES(0x3c25402070616765);--`,
		"bcp-export":     `1;exec xp_cmdshell 'bcp "select a from g3" queryout /tmp/probe.txt -c -T';--`,
		// 其它高危形态
		"openrowset":   `select * from openrowset('sqloledb','...')`,
		"bcp-queryout": `bcp "select x" queryout c:\inetpub\x.aspx -c`,
		"insert-hex":   `insert into t select 0x3c25402070616765abcd1234`,
		"case-mixed":   `1;EXEC Xp_CmdShell 'whoami';--`,                     // 大小写变体
		"url-encoded":  `insert%20into%20g%20values%280x3c25402070616765%29`, // url 编码(叠 URL 解码后现形)
	}
	for name, p := range hit {
		if !HasHighRiskSQLKeyword(p) {
			t.Errorf("应命中但漏过 [%s]: %q", name, p)
		}
	}

	miss := map[string]string{
		"normal-name":    "John Smith",
		"normal-query":   "keyword=价格100元&page=2",
		"select-word":    "please select all items",             // select 不在关键字表
		"reconfigure":    "reconfigure your dashboard",          // reconfigure 单独不判(常见英文)
		"bcp-noqueryout": "bcpackage download",                  // bcp 无 queryout 不判
		"short-hex":      "color=0xff0000&file=a.png",           // 短 hex 非 blob
		"open-word":      "openreport&opendashboard",            // 非 openrowset/openquery
		"into-outfile":   "export data into outfile report.csv", // MySQL 文件原语不入表(改前误伤 blaze 白样本 20+)
		"load-file":      "please load_file the template",       // 同上，双刃词不入表
	}
	for name, p := range miss {
		if HasHighRiskSQLKeyword(p) {
			t.Errorf("应放行但误判 [%s]: %q", name, p)
		}
	}
}
