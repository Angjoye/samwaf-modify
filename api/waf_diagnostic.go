package api

import (
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/wafdiag"
	"time"

	"github.com/gin-gonic/gin"
)

type WafDiagnosticApi struct {
}

var wafDiagnosticService = waf_service.WafDiagnosticServiceApp

// GetSnapshotApi 获取运行诊断实时快照（进程/Go runtime/内部组件/数据库体量）
// @Summary      获取运行诊断快照
// @Description  本进程视角的资源占用与内部组件计量，毫秒级采集
// @Tags         运行诊断
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /diagnostic/snapshot [get]
func (w *WafDiagnosticApi) GetSnapshotApi(c *gin.Context) {
	response.OkWithDetailed(wafDiagnosticService.GetSnapshot(), "获取成功", c)
}

// GetTrendApi 获取趋势采样数据（10s 间隔，最近 1 小时）
// @Summary      获取运行诊断趋势
// @Tags         运行诊断
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /diagnostic/trend [get]
func (w *WafDiagnosticApi) GetTrendApi(c *gin.Context) {
	response.OkWithDetailed(wafDiagnosticService.GetTrend(), "获取成功", c)
}

// StartCpuProfileApi 发起一次 30 秒 CPU 采样（异步任务，立即返回，前端轮询状态）
// @Summary      发起CPU采样
// @Tags         运行诊断
// @Produce      json
// @Success      200  {object}  response.Response  "已发起"
// @Security     ApiKeyAuth
// @Router       /diagnostic/cpuprofile/start [post]
func (w *WafDiagnosticApi) StartCpuProfileApi(c *gin.Context) {
	if err := wafdiag.StartCPUProfile(); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithMessage("CPU采样已发起，约30秒后完成", c)
}

// GetCpuProfileStatusApi 查询 CPU 采样任务状态（前端轮询）
// @Summary      查询CPU采样状态
// @Tags         运行诊断
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /diagnostic/cpuprofile/status [get]
func (w *WafDiagnosticApi) GetCpuProfileStatusApi(c *gin.Context) {
	response.OkWithDetailed(wafdiag.GetCPUProfileStatus(), "获取成功", c)
}

// DownloadPackageApi 生成并下载诊断包（流式 zip，不落盘）
// @Summary      下载运行诊断包
// @Description  快照/趋势/goroutine dump/heap profile（及已完成的CPU采样）打包下载
// @Tags         运行诊断
// @Produce      application/zip
// @Security     ApiKeyAuth
// @Router       /diagnostic/package [get]
func (w *WafDiagnosticApi) DownloadPackageApi(c *gin.Context) {
	fileName := "samwaf_diag_" + time.Now().Format("20060102_150405") + ".zip"
	// 先在内存组装完再发送：失败时能返回真实错误响应，而不是 200 + 截断的 zip
	data, err := wafDiagnosticService.BuildDiagnosticPackage()

	account, _ := c.Get("loginAccount")
	role, _ := c.Get("userRole")
	accountStr, _ := account.(string)
	roleStr, _ := role.(string)
	result, detail := model.AccessAuditOK, "生成诊断包 "+fileName
	if err != nil {
		result, detail = model.AccessAuditFail, "生成诊断包失败: "+err.Error()
	}
	wafAccessAuditService.Write(waf_service.AuditEntry{
		Event:       model.AuditEventConfigDiagPackage,
		AccountName: accountStr,
		ClientIP:    utils.GetManageClientIP(c),
		Result:      result,
		Message:     "[" + roleStr + "] " + detail,
	})

	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	c.Header("Content-Disposition", "attachment; filename="+fileName)
	c.Data(200, "application/zip", data)
}
