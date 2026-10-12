package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type SecKeyRouter struct {
}

// InitSecKeyRouter 挂在 Public 组，与登录接口同组同中间件
// （IP 白名单 / 域名白名单 / 防重放全部生效）。
func (receiver *SecKeyRouter) InitSecKeyRouter(group *gin.RouterGroup) {
	apiHandler := api.APIGroupAPP.WafSecKeyApi
	router := group.Group("")
	router.POST("/api/v1/public/seckey", apiHandler.SecKeyApi)
}
