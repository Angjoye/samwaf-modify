package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafDiagnosticRouter struct {
}

// InitWafDiagnosticRouter 运行诊断路由。挂载在 TokenOnly + 系统管理员组（见 localserver.go），
// 拒绝 API Key 访问：诊断包含进程内部信息，只允许后台登录的系统管理员获取。
func (s *WafDiagnosticRouter) InitWafDiagnosticRouter(group *gin.RouterGroup) {
	wafDiagnosticApi := api.APIGroupAPP.WafDiagnosticApi
	router := group.Group("")
	router.GET("/api/v1/diagnostic/snapshot", wafDiagnosticApi.GetSnapshotApi)              // 实时快照
	router.GET("/api/v1/diagnostic/trend", wafDiagnosticApi.GetTrendApi)                    // 趋势数据
	router.POST("/api/v1/diagnostic/cpuprofile/start", wafDiagnosticApi.StartCpuProfileApi) // 发起CPU采样
	router.GET("/api/v1/diagnostic/cpuprofile/status", wafDiagnosticApi.GetCpuProfileStatusApi)
	router.GET("/api/v1/diagnostic/package", wafDiagnosticApi.DownloadPackageApi) // 诊断包下载
}
