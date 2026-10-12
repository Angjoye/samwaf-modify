package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/model"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/waftask/batch"
	"fmt"
	"strings"
)

var (
	wafBatchTaskService = waf_service.WafBatchServiceApp
)

// sensitiveMaxLines 敏感词单次导入的行数上限
const sensitiveMaxLines = 50000

/*
*
批量任务
*/
func BatchTask() {
	innerLogName := "BatchTask"
	zlog.Info(innerLogName, "准备进行自动执行批量任务")

	batchTaskList, size, err := wafBatchTaskService.GetAllCronListInner()
	if err != nil {
		zlog.Error(innerLogName, "批量任务:", err)
		return
	}
	if size <= 0 {
		zlog.Info(innerLogName, "没有需要批量执行的任务")
		return
	}
	for _, batchTask := range batchTaskList {
		runErr := ExecuteBatchTask(batchTask)
		// 定时执行同样入统一安全审计：这条链路会读宿主机文件/拉远端地址并批量改防护策略，
		// 只有手工执行留痕的话，改成 cron 就能绕开审计。
		AuditBatchTaskRun(batchTask, "system(cron)", "", runErr)
		if runErr != nil {
			zlog.Error(innerLogName, fmt.Sprintf("批量任务[%s]执行失败: %s", batchTask.BatchTaskName, runErr.Error()))
			continue
		}
		zlog.Info(innerLogName, "批量已处理完")
	}
}

// ExecuteBatchTask 按任务类型分发执行，未知类型显式报错。
// 以前分发用的是一个没有 default 分支的 switch：类型写错时什么都不做，
// 而手工执行接口照样返回"成功"，运维完全看不出任务其实从未运行。
func ExecuteBatchTask(task model.BatchTask) error {
	switch task.BatchType {
	case enums.BATCHTASK_IPALLOW:
		return IPAllowBatch(task)
	case enums.BATCHTASK_IPDENY:
		return IPDenyBatch(task)
	case enums.BATCHTASK_IPGROUP:
		return IPGroupBatch(task)
	case enums.BATCHTASK_SENSITIVE:
		return SensitiveBatch(task)
	}
	return fmt.Errorf("任务类型非法(%s)，未执行", task.BatchType)
}

// AuditBatchTaskRun 把一次批量任务执行（成功/被拒）记入统一安全审计（config 类）。
// Message 只写来源类型、来源路径或URL、操作者与结果，绝不写文件内容
func AuditBatchTaskRun(task model.BatchTask, accountName, clientIP string, runErr error) {
	source := utils.RedactURLCredentials(strings.TrimSpace(task.BatchSource))
	if len(source) > 200 {
		source = source[:200] + "..."
	}
	detail := fmt.Sprintf("批量任务[%s] 类型=%s 来源=%s:%s 方式=%s",
		task.BatchTaskName, task.BatchType, task.BatchSourceType, source, task.BatchExecuteMethod)
	result := model.AccessAuditOK
	if runErr != nil {
		result = model.AccessAuditFail
		detail += " 结果=失败/被拒: " + runErr.Error()
	} else {
		detail += " 结果=成功"
	}
	waf_service.WafSecurityAuditServiceApp.Write(waf_service.AuditEntry{
		Event:       model.AuditEventConfigBatchTaskRun,
		AccountName: accountName,
		ClientIP:    clientIP,
		HostCode:    task.BatchHostCode,
		Result:      result,
		Message:     detail,
	})
}

// IPAllowBatch 白名单IP批量处理
func IPAllowBatch(task model.BatchTask) error {
	processor := &batch.IPAllowProcessor{}
	config := batch.BatchProcessorConfig{
		BatchSize: 1000,
		LogPrefix: "BatchTask-IPAllowBatch",
	}
	return batch.ProcessBatchTask(task, processor, config)
}

// IPDenyBatch 黑名单IP批量处理
func IPDenyBatch(task model.BatchTask) error {
	processor := &batch.IPDenyProcessor{}
	config := batch.BatchProcessorConfig{
		BatchSize: 1000,
		LogPrefix: "BatchTask-IPDenyBatch",
	}
	return batch.ProcessBatchTask(task, processor, config)
}

// IPGroupBatch IP组条目批量处理。
// 处理器持有跨批次状态(覆盖模式的差集)，所以每次执行都要新建实例，不能复用。
func IPGroupBatch(task model.BatchTask) error {
	processor := &batch.IPGroupProcessor{}
	config := batch.BatchProcessorConfig{
		BatchSize: 1000,
		LogPrefix: "BatchTask-IPGroupBatch",
	}
	return batch.ProcessBatchTask(task, processor, config)
}

// SensitiveBatch 敏感词批量处理
func SensitiveBatch(task model.BatchTask) error {
	processor := &batch.SensitiveProcessor{}
	config := batch.BatchProcessorConfig{
		BatchSize: 1000,
		LogPrefix: "BatchTask-SensitiveBatch",
		MaxLines:  sensitiveMaxLines,
	}
	return batch.ProcessBatchTask(task, processor, config)
}
