package batch

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/utils"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// BatchProcessor 批量处理器接口
type BatchProcessor interface {
	// ProcessItem 处理单个项目
	ProcessBatch(items []string, task model.BatchTask, progress *BatchProgress) bool
	// GetExistingItems 获取已存在的项目
	GetExistingItems(items []string, task model.BatchTask, config interface{}) map[string]interface{}
	// NotifyEngine 通知引擎更新
	NotifyEngine(task model.BatchTask)
}

// BatchFinalizer 可选接口：所有批次都跑完之后回调一次。
//
// 给「必须看完整份源才能决定」的收尾用（例如覆盖模式下删除源里已经不存在的旧条目）。
// sourceComplete 表示这份源是否被完整读完（扫描无错误）——半截数据绝不能拿去做删除，
// 否则一次网络抖动就能把组清空：被白名单引用时是全站失去豁免，被黑名单引用时是瞬间放行。
// 返回值语义与 ProcessBatch 一致：true 表示数据有变化，需要通知引擎。
type BatchFinalizer interface {
	Finalize(task model.BatchTask, progress *BatchProgress, sourceComplete bool) bool
}

// BatchProcessorConfig 批量处理器配置
type BatchProcessorConfig struct {
	BatchSize int    // 批处理大小
	LogPrefix string // 日志前缀
	// MaxLines 本次导入允许的最大行数，<=0 时取 defaultMaxSourceLines。
	// 敏感词这类"导进来立刻进检测引擎、每个请求都要逐条匹配"的类型需要单独收紧。
	MaxLines int
	// MaxBytes 本次导入允许的最大字节数，<=0 时取 defaultMaxSourceBytes。
	MaxBytes int
}

// 导入上限。批量任务的来源完全由管理端指定
const (
	defaultMaxSourceBytes = 32 * 1024 * 1024 // 单份来源最大字节数
	defaultMaxSourceLines = 500000           // 单份来源最大行数
	fetchTimeout          = 2 * time.Minute  // 远端来源拉取整体超时
)

// BatchProgress 批处理进度
type BatchProgress struct {
	TotalItems     int32 // 总项目数
	ProcessedItems int32 // 已处理项目数
	InsertedItems  int32 // 已插入项目数
	UpdatedItems   int32 // 已更新项目数
}

// AddProcessed 增加已处理数量
func (p *BatchProgress) AddProcessed(count int) {
	atomic.AddInt32(&p.ProcessedItems, int32(count))
}

// AddInserted 增加已插入数量
func (p *BatchProgress) AddInserted(count int) {
	atomic.AddInt32(&p.InsertedItems, int32(count))
}

// AddUpdated 增加已更新数量
func (p *BatchProgress) AddUpdated(count int) {
	atomic.AddInt32(&p.UpdatedItems, int32(count))
}

// GetProgress 获取进度百分比
func (p *BatchProgress) GetProgress() float64 {
	if p.TotalItems == 0 {
		return 100.0
	}
	return float64(p.ProcessedItems) / float64(p.TotalItems) * 100.0
}

// ProcessBatchTask 通用批量处理函数。
//
// 返回 error 而不是像以前那样只打日志静默返回：调用方（手工执行接口 / 定时任务）
// 需要据此给用户明确结果并写安全审计。以前无论来源读不出、执行方式非法还是
// 一条都没导进去，接口都回"手工执行任务成功"，运维完全看不出任务其实没跑。
func ProcessBatchTask(task model.BatchTask, processor BatchProcessor, config BatchProcessorConfig) error {
	innerLogName := config.LogPrefix

	// 枚举在这里再兜一次：保存侧已经拦了，但存量库里可能留着旧的非法值。
	// 执行方式尤其要紧——各 processor 对未知值一律 return false，
	// 表现为"跑完了、什么也没发生"，从外面完全看不出来。
	if !enums.IsValidBatchExecuteMethod(task.BatchExecuteMethod) {
		err := fmt.Errorf("任务执行方式非法(%s)，仅支持 %s/%s",
			task.BatchExecuteMethod, enums.BATCHTASK_EXECUTEMETHODAPPEND, enums.BATCHTASK_EXECUTEMETHODOVERWRITE)
		zlog.Error(innerLogName, err.Error())
		return err
	}
	// 来源类型非法时会落进远端分支（虽然那里也会因为不是合法 URL 而拒），
	// 但报错说"远端来源被拒绝"会把人往错误方向带，不如在这里说清楚。
	if !enums.IsValidBatchSourceType(task.BatchSourceType) {
		err := fmt.Errorf("来源类型非法(%s)，仅支持 %s/%s", task.BatchSourceType,
			enums.BATCHTASK_SOURCETYPE_LOCAL, enums.BATCHTASK_SOURCETYPE_REMOTE)
		zlog.Error(innerLogName, err.Error())
		return err
	}

	// 一次读取、校验并落到内存：既做上限判定，也顺带消灭了"计数一遍 + 处理一遍"
	// 造成的两次拉取（远端源会被请求两次，且两次内容可能不一致）。
	content, err := loadSource(task, config)
	if err != nil {
		zlog.Error(innerLogName, err.Error())
		return err
	}

	// 判断数据库是否已经关闭
	if global.GWAF_LOCAL_DB == nil {
		err = errors.New("数据库已经关闭批量处理终止")
		zlog.Error(innerLogName, err.Error())
		return err
	}

	// 获取对应类型的提取器
	extractor := GetExtractor(task.BatchType)

	// 先整份扫一遍算行数。扫描出错就直接放弃：这一遍还没往库里写任何东西，
	// 拒绝是干净的；硬着头皮往下走的话，正式那一遍会在同一个位置出错，
	// 而此时前半截已经落库了——就成了不该出现的半截导入。
	totalLines, validLines, err := countLinesWithExtractor(content, extractor)
	if err != nil {
		err = fmt.Errorf("来源扫描失败，已拒绝整批导入: %v", err)
		zlog.Error(innerLogName, err.Error())
		return err
	}

	// 创建进度跟踪器
	progress := &BatchProgress{
		TotalItems: int32(validLines),
	}

	zlog.Info(innerLogName, fmt.Sprintf("开始批量处理，总行数: %d，有效行数: %d", totalLines, validLines))

	// 收集有效的项目
	validItems := make([]string, 0, config.BatchSize)
	scanner := bufio.NewScanner(bytes.NewReader(content))
	hasAffectInfo := false

	// 按批次处理
	batchCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" {
			continue // 跳过空行
		}

		// 使用特定类型的提取器
		item := extractor.ExtractItem(line)
		if !extractor.ValidateItem(item) {
			continue
		}

		validItems = append(validItems, item)
		batchCount++

		// 当收集到一批或者是最后一批时，进行批量处理
		if batchCount >= config.BatchSize {
			// 处理当前批次
			if processor.ProcessBatch(validItems, task, progress) {
				hasAffectInfo = true
			}

			// 记录进度
			progress.AddProcessed(len(validItems))
			zlog.Info(innerLogName, fmt.Sprintf("进度: %.2f%% (%d/%d)，已插入: %d，已更新: %d",
				progress.GetProgress(), progress.ProcessedItems, progress.TotalItems,
				progress.InsertedItems, progress.UpdatedItems))

			// 重置批次
			validItems = make([]string, 0, config.BatchSize)
			batchCount = 0
		}
	}

	// 处理最后一批不足BatchSize的项目
	if len(validItems) > 0 {
		if processor.ProcessBatch(validItems, task, progress) {
			hasAffectInfo = true
		}

		// 记录进度
		progress.AddProcessed(len(validItems))
		zlog.Info(innerLogName, fmt.Sprintf("进度: %.2f%% (%d/%d)，已插入: %d，已更新: %d",
			progress.GetProgress(), progress.ProcessedItems, progress.TotalItems,
			progress.InsertedItems, progress.UpdatedItems))
	}

	// 先判定源是否被完整读完，收尾动作（如全量同步的删除）依赖这个信号
	scanErr := scanner.Err()
	if scanErr != nil {
		zlog.Error(innerLogName, fmt.Sprintf("扫描文件时发生错误: %s", scanErr.Error()))
	}

	// 收尾回调（可选实现）
	if finalizer, ok := processor.(BatchFinalizer); ok {
		if finalizer.Finalize(task, progress, scanErr == nil) {
			hasAffectInfo = true
		}
	}

	if hasAffectInfo {
		// 通知引擎进行实时生效
		processor.NotifyEngine(task)
	}

	// 输出最终处理结果
	zlog.Info(innerLogName, fmt.Sprintf("批量处理完成，总计处理: %d，插入: %d，更新: %d",
		progress.ProcessedItems, progress.InsertedItems, progress.UpdatedItems))
	return scanErr
}

// countLinesWithExtractor 使用提取器计算总行数和有效行数
func countLinesWithExtractor(content []byte, extractor ItemExtractor) (int, int, error) {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	totalLines := 0
	validLines := 0

	for scanner.Scan() {
		line := scanner.Text()
		totalLines++

		line = strings.TrimSpace(line)
		if line == "" {
			continue // 跳过空行
		}

		item := extractor.ExtractItem(line)
		if extractor.ValidateItem(item) {
			validLines++
		}
	}

	return totalLines, validLines, scanner.Err()
}

// loadSource 打开、校验并读取数据源，返回全部内容。字节数/行数任一超限即拒绝整批。
func loadSource(task model.BatchTask, config BatchProcessorConfig) ([]byte, error) {
	maxLines := config.MaxLines
	if maxLines <= 0 {
		maxLines = defaultMaxSourceLines
	}
	maxBytes := config.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxSourceBytes
	}

	contentReader, expectedLen, err := openSource(task)
	if err != nil {
		return nil, err
	}
	defer contentReader.Close()

	// 多读 1 字节用于判定"是否超限"，而不是静默截断成半份数据
	data, err := io.ReadAll(io.LimitReader(contentReader, int64(maxBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("读取来源失败: %v", err)
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("来源超过大小上限 %d 字节，已拒绝整批导入", maxBytes)
	}
	// 声明了长度却没读满 = 中途被掐断。这一步很关键：连接关闭式分帧的 HTTP 响应
	// 被截断时 io.ReadAll 是不报错的，半份数据会被当成"完整的源"，
	// 覆盖模式据此把组里"本次没出现"的条目全删掉——一次网络抖动就能清空 IP 组。
	if expectedLen >= 0 && int64(len(data)) != expectedLen {
		return nil, fmt.Errorf("来源读取不完整(已读 %d 字节，声明 %d 字节)，已拒绝整批导入", len(data), expectedLen)
	}
	if lines := countRawLines(data); lines > maxLines {
		return nil, fmt.Errorf("来源行数 %d 超过上限 %d，已拒绝整批导入", lines, maxLines)
	}
	// bufio.Scanner 单行上限 64KB，超了会在扫描中途报错。放到这里判：
	// 此时一条都还没落库，可以干净地拒绝整批；等扫描时才发现的话，
	// 长行之前的数据已经写进去了，就成了半截导入。
	if n := maxLineLen(data); n > bufio.MaxScanTokenSize {
		return nil, fmt.Errorf("来源存在超长行(%d 字节，上限 %d)，已拒绝整批导入", n, bufio.MaxScanTokenSize)
	}
	return data, nil
}

// maxLineLen 返回最长一行的字节数（不含换行符）
func maxLineLen(data []byte) int {
	max, cur := 0, 0
	for _, b := range data {
		if b == '\n' {
			if cur > max {
				max = cur
			}
			cur = 0
			continue
		}
		cur++
	}
	if cur > max {
		max = cur
	}
	return max
}

// countRawLines 统计原始行数（末行无换行也算一行）
func countRawLines(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	n := bytes.Count(data, []byte{'\n'})
	if data[len(data)-1] != '\n' {
		n++
	}
	return n
}

// openSource 打开本地或远程数据源。
//
// 这两条路径的入参 BatchSource 完全由管理端提交，必须先过安全边界：
//   - local：只允许读内置 data/import 目录与 config.yml 带外声明的目录（见 utils.ValidateBatchLocalPath），
//     否则任意绝对路径都能被读出来并逐行落库、再经列表接口读回。
//   - 远端：必须是允许的对外地址（默认仅公网）
//
// 破坏性变更：升级前把来源放在任意路径、或指向内网镜像的任务会开始报错，
// 需要把文件挪进允许目录 / 在 config.yml 的 security.outbound_allowed_hosts 声明该主机。
// 第二个返回值是"声明的字节数"，未知时为 -1，供调用方判定读取是否完整。
func openSource(task model.BatchTask) (io.ReadCloser, int64, error) {
	if enums.IsBatchLocalSource(task.BatchSourceType) {
		realPath, err := utils.ValidateBatchLocalPath(task.BatchSource)
		if err != nil {
			return nil, -1, fmt.Errorf("本地来源被拒绝: %v", err)
		}
		f, err := os.Open(realPath)
		if err != nil {
			return nil, -1, fmt.Errorf("failed to open local file: %v", err)
		}
		size := int64(-1)
		if fi, statErr := f.Stat(); statErr == nil {
			size = fi.Size()
		}
		return f, size, nil
	}
	// remote
	rawURL := strings.TrimSpace(task.BatchSource)
	if ok, reason := utils.IsAllowedOutboundURL(rawURL); !ok {
		return nil, -1, fmt.Errorf("远端来源被拒绝: %s", reason)
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, -1, fmt.Errorf("failed to build request: %v", err)
	}
	req.Header.Set("User-Agent", "SamWaf-BatchTask")
	resp, err := utils.SafeOutboundHTTPClient(fetchTimeout).Do(req)
	if err != nil {
		return nil, -1, fmt.Errorf("failed to fetch remote data: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, -1, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	return resp.Body, resp.ContentLength, nil
}

// extractIPFromLine 使用正则表达式从行中提取IP地址或网段
func extractIPFromLine(line string) string {
	// 匹配IPv4地址或IPv4网段
	ipv4Regex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b`)

	// 匹配IPv6地址或IPv6网段 (简化版本)
	ipv6Regex := regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?:/\d{1,3})?\b`)

	// 先尝试匹配IPv4
	if match := ipv4Regex.FindString(line); match != "" {
		return match
	}

	// 再尝试匹配IPv6
	if match := ipv6Regex.FindString(line); match != "" {
		return match
	}

	return line // 如果没有匹配到，返回原始行
}
