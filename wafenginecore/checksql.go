package wafenginecore

import (
	"SamWaf/innerbean"
	"SamWaf/libinjection-go"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafenginecore/wafhttpcore"
	"net/http"
	"net/url"
)

/*
*
检测sqli
*/
func (waf *WafEngine) CheckSql(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	var sqlFlag = false
	//检测sql注入（RawQuery 已多轮解码）。JSON 体不整块扫，改走下方逐值——整块含大量结构
	//字符会把正常数字/结构 JSON 误判为注入。
	scanBody := !wafhttpcore.IsJSONBody(weblogbean.BODY)
	// D5-1：libinjection 之外补 MSSQL/DB 高危关键字兜底（xp_cmdshell/sp_configure/
	// bcp queryout/INSERT VALUES(0x..) 等，接住纯 DDL/配置语句这类无注入指纹的漏检）
	if libinjection.IsSQLiNotReturnPrint(weblogbean.RawQuery) ||
		(scanBody && libinjection.IsSQLiNotReturnPrint(weblogbean.BODY)) ||
		libinjection.IsSQLiNotReturnPrint(weblogbean.POST_FORM) ||
		wafhttpcore.HasHighRiskSQLKeyword(weblogbean.RawQuery) ||
		(scanBody && wafhttpcore.HasHighRiskSQLKeyword(weblogbean.BODY)) ||
		wafhttpcore.HasHighRiskSQLKeyword(weblogbean.POST_FORM) {
		sqlFlag = true
	}
	if sqlFlag == false {
		for key, value := range formValue {
			if isBodyFieldExcluded(key) { // E：已知富文本字段整体跳过
				continue
			}
			for _, v := range value {
				if wafhttpcore.HasHighRiskSQLKeyword(v) { // 高危关键字：不跳过结构化
					sqlFlag = true
					continue
				}
				// 跳过结构化数据值（嵌套 JSON/回调 URL）：正常埋点/日志会误报，且不构成 SQLi
				if wafhttpcore.IsStructuredDataValue(v) {
					continue
				}
				if libinjection.IsSQLiNotReturnPrint(v) {
					sqlFlag = true
				}
			}
		}
	}
	if sqlFlag == true {
		// 查询串/表单串等既有检测：始终强制拦截
		weblogbean.RISK_LEVEL = 2
		result.IsBlock = true
		result.Title = "SQL注入"
		result.Content = "请正确访问"
		return result
	}
	// JSON 请求体逐值检测（S1 新增）：受 body_detect_mode 门控 + 字段排除(E) + 跳过结构化数据值
	if bodyDetectEnabled() {
		hit := false
		for i, v := range weblogbean.BodyValues {
			if isBodyFieldExcluded(fieldAt(weblogbean.BodyFields, i)) {
				continue
			}
			if wafhttpcore.HasHighRiskSQLKeyword(v) { // 高危关键字：不跳过结构化
				hit = true
				break
			}
			if wafhttpcore.IsStructuredDataValue(v) {
				continue
			}
			if libinjection.IsSQLiNotReturnPrint(v) {
				hit = true
				break
			}
		}
		if !hit { // 头位 SQLi(S1-4)
			hit = headerSQLHit(r)
		}
		if hit {
			if bodyDetectBlocking() {
				weblogbean.RISK_LEVEL = 2
				result.IsBlock = true
				result.Title = "SQL注入"
				result.Content = "请正确访问"
				return result
			}
			markBodyObserve(weblogbean, "SQL注入")
		}
	}
	return result
}
