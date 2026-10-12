package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafenginecore/wafhttpcore"
	"net/http"
	"net/url"
	"testing"
)

func newTestWafForSQL() (*WafEngine, *wafenginmodel.HostSafe, *wafenginmodel.HostSafe) {
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "json")
	waf := &WafEngine{}
	waf.InitRouting()
	global.GWAF_GLOBAL_HOST_NAME = "全局网站"
	waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME] = &wafenginmodel.HostSafe{Host: model.Hosts{GUARD_STATUS: 1}}
	hostSafe := &wafenginmodel.HostSafe{Host: model.Hosts{GUARD_STATUS: 1}}
	return waf, hostSafe, waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME]
}

// TestCheckSqlBodyFalsePositives 用 blaze 全量实测抓到的 7 条正常流量误报样本，
// 确认收敛后（JSON 体走逐值不整块扫 + 跳过结构化数据值 + JSON 值不再叠 URL 解码）不再误拦。
func TestCheckSqlBodyFalsePositives(t *testing.T) {
	waf, hostSafe, globalHost := newTestWafForSQL()
	global.GCONFIG_BODY_DETECT_MODE = "block" // 测请求体拦截逻辑（默认 observe 只记录不拦）
	defer func() { global.GCONFIG_BODY_DETECT_MODE = "observe" }()

	// 均为真实正常业务体（遥测/日志上报/埋点/URL编码JSON），不应被 SQLi 拦
	benignBodies := []struct {
		name string
		body string
	}{
		{"数字遥测JSON", `{"Seq":9,"When":162400,"Evts":[{"Kind":9,"Args":[162417,1573,1553,-20,-20,163,174,11,11,132]}]}`},
		{"日志上报嵌套JSON", `{"level":["2","2"],"msg":["[\"[Capi Success]\",{\"body\":{\"serviceType\":\"ba\",\"regionId\":1}}]"]}`},
		{"埋点含回调URL", `{"Seq":5,"Evts":[{"Kind":63,"Args":["POST","https://rs.fullstory.com/rec/bundle/v2?OrgId=B9193&UserId=4b2b7c84-aa5f-44aa-b927-6f55e6eb3095"]}]}`},
		{"URL编码的JSON数组", `["%7B%22val_nm%22%3A%226%22%2C%22val_act%22%3A%22exposure_yw%22%7D"]`},
	}
	for _, b := range benignBodies {
		t.Run("benign/"+b.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "http://example.com/api", nil)
			weblog := &innerbean.WebLog{
				BODY:       b.body,
				BodyValues: wafhttpcore.ExtractJSONStringValues(b.body),
			}
			res := waf.CheckSql(req, weblog, url.Values{}, hostSafe, globalHost)
			if res.IsBlock {
				t.Errorf("正常体被误拦为 SQLi: %s", b.body)
			}
		})
	}

	// 真实 SQLi 仍必须拦（防止收敛过度）
	attacks := []struct {
		name string
		body string
	}{
		{"JSON值内SQLi", `{"q":"1' UNION SELECT username,password FROM users--"}`},
		{"JSON值内OR注入", `{"user":"admin' or '1'='1"}`},
	}
	for _, a := range attacks {
		t.Run("attack/"+a.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "http://example.com/api", nil)
			weblog := &innerbean.WebLog{
				BODY:       a.body,
				BodyValues: wafhttpcore.ExtractJSONStringValues(a.body),
			}
			res := waf.CheckSql(req, weblog, url.Values{}, hostSafe, globalHost)
			if !res.IsBlock {
				t.Errorf("真实 SQLi 漏拦: %s", a.body)
			}
		})
	}
}
