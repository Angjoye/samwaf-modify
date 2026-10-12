package api

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/utils"
	"SamWaf/utils/localca"
	"strings"

	"github.com/gin-gonic/gin"
)

// 管理端本地证书：用本机长效 CA 给管理端签一张服务器证书。
//
// 面向"没有域名、或有域名但不想走 ACME"的部署。有域名的用户更推荐 DNS-01 + 证书夹绑定
// （不开 80 端口、不公网暴露、自动续期），本接口是那条路走不通时的兜底。
//
// 权限与上传证书同级（系统管理员），因为落地效果一样：都会覆盖管理端的证书文件。

// maxSANItems 单张证书里的访问地址数量上限。放开没有意义，还给了个把证书撑大的口子。
const maxSANItems = 32

// GenerateLocalCertApi 生成（或重新签发）管理端本地证书
func (w *WafVpConfigApi) GenerateLocalCertApi(c *gin.Context) {
	var req struct {
		// SANs 用户实际用来访问管理端的地址，逗号分隔：域名、内网IP、公网IP 可混填。
		// 现代浏览器只认 SAN 不认 CN，漏掉任何一个访问方式，用那个方式访问就会报错。
		SANs string `json:"sans"`
		// ValidDays 留空用默认值；上限由 localca 兜（Apple 平台 825 天硬限制）
		ValidDays int `json:"valid_days"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析请求失败", c)
		return
	}

	items := splitSANInput(req.SANs)
	if len(items) == 0 {
		response.FailWithMessage("请至少填写一个访问地址（域名或IP）", c)
		return
	}
	if len(items) > maxSANItems {
		response.FailWithMessage("访问地址过多，最多支持 32 个", c)
		return
	}

	paths := localca.DefaultPaths(utils.GetCurrentDir())
	summary, err := localca.IssueServerCert(paths, items, req.ValidDays)
	if err != nil {
		response.FailWithMessage("生成本地证书失败: "+err.Error(), c)
		return
	}
	zlog.Info("已生成管理端本地证书", "subject", summary.Subject, "not_after", summary.NotAfter)

	response.OkWithDetailed(gin.H{
		"cert":    summary,
		"ca":      localca.CASummary(paths),
		"sans":    localca.SANsOf(summary),
		"message": "生成成功，需要启用SSL并重启管理端生效；浏览器信任需要导入根证书",
	}, "生成本地证书成功", c)
}

// RotateLocalCaApi 作废当前本地 CA 并用新 CA 重新签发管理端证书。
//
// 自建 CA 没有 CRL/OCSP，"吊销"实际就是两步：服务端换一把 CA（本接口），
// 客户端把旧根证书从信任库里删掉（只能由管理员在自己电脑上做）。
// 这是破坏性操作：所有导入过旧根证书的电脑都会立刻报"不安全"，必须重新导入新的。
func (w *WafVpConfigApi) RotateLocalCaApi(c *gin.Context) {
	var req struct {
		SANs      string `json:"sans"`
		ValidDays int    `json:"valid_days"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析请求失败", c)
		return
	}

	items := splitSANInput(req.SANs)
	if len(items) > maxSANItems {
		response.FailWithMessage("访问地址过多，最多支持 32 个", c)
		return
	}

	paths := localca.DefaultPaths(utils.GetCurrentDir())
	summary, err := localca.RotateCA(paths, items, req.ValidDays)
	if err != nil {
		response.FailWithMessage("重建本地CA失败: "+err.Error(), c)
		return
	}
	zlog.Info("已重建管理端本地CA", "subject", summary.Subject, "not_after", summary.NotAfter)

	response.OkWithDetailed(gin.H{
		"cert":    summary,
		"ca":      localca.CASummary(paths),
		"sans":    localca.SANsOf(summary),
		"message": "已换用新的根证书。旧根证书随即失效，请在所有访问用的电脑上删除旧的并导入新的",
	}, "重建本地CA成功", c)
}

// ClearLocalCertApi 删除本地 CA 与它签发的管理端证书。
//
// SSL 还开着时拒绝执行——证书文件被删掉后管理端重启会加载不到证书，HTTPS 直接起不来，
// 那是个自己把自己锁在门外的操作，宁可让用户先显式关掉 SSL 或换到别的证书来源。
func (w *WafVpConfigApi) ClearLocalCertApi(c *gin.Context) {
	paths := localca.DefaultPaths(utils.GetCurrentDir())

	if global.GWAF_SSL_ENABLE && localca.IsIssuedByLocalCA(paths) {
		response.FailWithMessage("管理端正在使用本地证书，请先关闭SSL或改用其它证书来源，再执行清除", c)
		return
	}
	if err := localca.ClearLocal(paths); err != nil {
		response.FailWithMessage("清除本地证书失败: "+err.Error(), c)
		return
	}
	zlog.Info("已清除管理端本地CA与本地证书")
	response.OkWithMessage("已清除。请记得在导入过根证书的电脑上把它删掉", c)
}

// GetLocalCertStatusApi 查询本地 CA 与当前管理端证书的状态
func (w *WafVpConfigApi) GetLocalCertStatusApi(c *gin.Context) {
	paths := localca.DefaultPaths(utils.GetCurrentDir())
	current := localca.CurrentServerCert(paths)

	// CA 是公钥证书、本身不含秘密，直接随状态回给前端，
	// 前端据此在浏览器本地存成 .crt 文件——省掉一个只为下载而开的路由，
	// 也避开"window.open 带不了鉴权头"这个坑（查询串取令牌只对下载日志那条路径生效）
	caPEM := ""
	if raw, err := localca.ReadCACert(paths); err == nil {
		caPEM = string(raw)
	}

	// 证书能不能真的把 HTTPS 起起来。前端据此在重启前就把问题摆出来，
	// 而不是等重启完打不开才发现——那时候只能上服务器改配置文件
	certProblem := ""
	if err := localca.CheckServerCert(paths); err != nil {
		certProblem = err.Error()
	}

	response.OkWithDetailed(gin.H{
		"has_ca": localca.CASummary(paths) != nil,
		"ca":     localca.CASummary(paths),
		"ca_pem": caPEM,
		// 当前管理端证书是不是本地 CA 签的：手工上传与 ACME 绑定的证书不该被这条路径接管
		"is_local":     localca.IsIssuedByLocalCA(paths),
		"cert":         current,
		"sans":         localca.SANsOf(current),
		"cert_usable":  certProblem == "",
		"cert_problem": certProblem,
	}, "获取本地证书状态成功", c)
}

// splitSANInput 把用户填的一行地址拆开。换行、逗号、分号都当分隔符——
// 用户从别处粘贴过来的多半带换行，不必强求格式。
func splitSANInput(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';' || r == ' ' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if s := strings.TrimSpace(f); s != "" {
			out = append(out, s)
		}
	}
	return out
}
