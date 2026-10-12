package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type PluginRouter struct {
}

// InitPluginRouter 插件管理路由。
//
// 【当前状态：故意不注册】wafmangeweb/localserver.go 没有调用本函数，这些接口不可达。
// 原因：add/modify 会把 JSON 里的 binary_path 直接落库并交给 LoadPlugin 执行，
// 在签名与准入控制（L0 路径收口 + L1 验签）完成之前接上等于给管理端开一个任意路径 RCE。
//
// 接上之前必须满足：
//  1. manager.PendingVerification 已置为 false（即 L0+L1 已落地）；
//  2. binary_path 改为只能从 binary_dir 已有文件中选取，不允许前端自由填写路径。
//
// 详见 SamWafTechDoc/Plan/2026-08-23-插件系统暂停加载-清单与恢复计划.md
func (receiver *PluginRouter) InitPluginRouter(group *gin.RouterGroup) {
	apiInstance := api.APIGroupAPP.WafPluginApi
	router := group.Group("")

	// 插件管理
	router.POST("/api/v1/wafplugin/list", apiInstance.GetListApi)
	router.GET("/api/v1/wafplugin/detail", apiInstance.GetDetailApi)
	router.POST("/api/v1/wafplugin/add", apiInstance.AddApi)
	router.POST("/api/v1/wafplugin/modify", apiInstance.ModifyApi)
	router.GET("/api/v1/wafplugin/del", apiInstance.DeleteApi)
	router.POST("/api/v1/wafplugin/toggle", apiInstance.ToggleApi)

	// 系统配置
	router.GET("/api/v1/wafplugin/systemconfig/get", apiInstance.GetSystemConfigApi)
	router.POST("/api/v1/wafplugin/systemconfig/update", apiInstance.UpdateSystemConfigApi)

	// 插件日志
	router.POST("/api/v1/wafplugin/logs", apiInstance.GetPluginLogsApi)
}
