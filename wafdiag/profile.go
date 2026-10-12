package wafdiag

import (
	"bytes"
	"errors"
	"runtime"
	"runtime/pprof"
	"sync"
	"time"
)

// 按需深度采集：只在管理员点击时执行。
// goroutine dump / heap profile 秒级同步返回；
// CPU profile 需持续采样 30s，走异步任务模式（发起→轮询→取结果），
// 任何单个 HTTP 请求都不会长时间挂起。

const (
	cpuProfileDuration = 30 * time.Second
	cpuProfileCooldown = 5 * time.Minute
)

var (
	ErrCPUProfileRunning     = errors.New("已有CPU采集任务在执行中")
	ErrCPUProfileTooFrequent = errors.New("CPU采集触发过于频繁，请稍后再试")
)

// GoroutineDump 返回 goroutine 栈文本。
// debug=1 按调用栈聚合（带数量），debug=2 每个 goroutine 完整栈。
func GoroutineDump(debug int) []byte {
	var buf bytes.Buffer
	profile := pprof.Lookup("goroutine")
	if profile == nil {
		return nil
	}
	_ = profile.WriteTo(&buf, debug)
	return buf.Bytes()
}

// HeapProfile 返回 pprof 堆采样（protobuf gzip 格式，go tool pprof 可直接分析）。
// 先做一次 GC，让"活对象"视图准确（排除待回收垃圾的干扰）。
func HeapProfile() ([]byte, error) {
	runtime.GC()
	var buf bytes.Buffer
	profile := pprof.Lookup("heap")
	if profile == nil {
		return nil, errors.New("heap profile不可用")
	}
	if err := profile.WriteTo(&buf, 0); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CPU profile 异步任务状态机：idle → running → done/failed（结果保留最近一份供诊断包引用）。
type cpuProfileTask struct {
	mu         sync.Mutex
	running    bool
	lastStart  time.Time
	finishedAt time.Time
	data       []byte
	lastErr    string
}

var cpuTask cpuProfileTask

// CPUProfileStatus 任务状态快照。
type CPUProfileStatus struct {
	Running       bool   `json:"running"`
	HasResult     bool   `json:"has_result"`
	ResultSize    int    `json:"result_size"`
	StartedUnix   int64  `json:"started_unix"`
	FinishedUnix  int64  `json:"finished_unix"`
	ElapsedSecond int64  `json:"elapsed_second"`
	DurationSec   int    `json:"duration_sec"`
	LastError     string `json:"last_error"`
	CooldownSec   int64  `json:"cooldown_sec"` // 距离下次允许发起还需等待的秒数，0=可发起
}

// StartCPUProfile 发起一次 30s CPU 采样，立即返回。
// 互斥：同一时刻仅一个任务；频控：5 分钟内只允许发起一次。
func StartCPUProfile() error {
	cpuTask.mu.Lock()
	defer cpuTask.mu.Unlock()
	if cpuTask.running {
		return ErrCPUProfileRunning
	}
	if !cpuTask.lastStart.IsZero() && time.Since(cpuTask.lastStart) < cpuProfileCooldown {
		return ErrCPUProfileTooFrequent
	}
	var buf bytes.Buffer
	if err := pprof.StartCPUProfile(&buf); err != nil {
		return err
	}
	cpuTask.running = true
	cpuTask.lastStart = time.Now()
	cpuTask.lastErr = ""
	go func() {
		time.Sleep(cpuProfileDuration)
		pprof.StopCPUProfile()
		cpuTask.mu.Lock()
		cpuTask.running = false
		cpuTask.finishedAt = time.Now()
		cpuTask.data = buf.Bytes()
		cpuTask.mu.Unlock()
	}()
	return nil
}

// GetCPUProfileStatus 查询任务状态（前端轮询用）。
func GetCPUProfileStatus() CPUProfileStatus {
	cpuTask.mu.Lock()
	defer cpuTask.mu.Unlock()
	status := CPUProfileStatus{
		Running:     cpuTask.running,
		HasResult:   len(cpuTask.data) > 0,
		ResultSize:  len(cpuTask.data),
		DurationSec: int(cpuProfileDuration.Seconds()),
		LastError:   cpuTask.lastErr,
	}
	if !cpuTask.lastStart.IsZero() {
		status.StartedUnix = cpuTask.lastStart.Unix()
		if cpuTask.running {
			status.ElapsedSecond = int64(time.Since(cpuTask.lastStart).Seconds())
		}
		if remain := cpuProfileCooldown - time.Since(cpuTask.lastStart); remain > 0 {
			status.CooldownSec = int64(remain.Seconds())
		}
	}
	if !cpuTask.finishedAt.IsZero() {
		status.FinishedUnix = cpuTask.finishedAt.Unix()
	}
	return status
}

// CPUProfileResult 取最近一次采样结果（诊断包打包用）。第二个返回值为采样完成时间。
func CPUProfileResult() ([]byte, time.Time) {
	cpuTask.mu.Lock()
	defer cpuTask.mu.Unlock()
	return cpuTask.data, cpuTask.finishedAt
}
