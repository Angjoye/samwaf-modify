package wafdiag

import (
	"SamWaf/global"
	"runtime"
	"sync"
	"time"
)

// 低频趋势采样：每 10s 记一个点到内存环形缓冲（360 点 = 1 小时），
// 不落库不落盘，用于回答"占用是什么时候、以什么方式涨上去的"。
// 单点开销：一次 Process.Percent + MemoryInfo + 几个队列 Size，微秒~毫秒级。

const (
	sampleInterval = 10 * time.Second
	ringSize       = 360
)

// TrendPoint 一个采样点。
type TrendPoint struct {
	Ts          int64   `json:"ts"`          // 秒级时间戳
	CPUPercent  float64 `json:"cpu_percent"` // 本进程 CPU%
	RSSBytes    uint64  `json:"rss_bytes"`   // 常驻内存
	Goroutines  int     `json:"goroutines"`  // goroutine 数
	QueueLog    int     `json:"queue_log"`   // 日志写队列长度
	QueueStats  int     `json:"queue_stats"` // 统计写队列长度（含更新队列）
	QueueDb     int     `json:"queue_db"`    // 核心写队列长度（含更新队列）
	QueueMsg    int     `json:"queue_msg"`   // 消息队列长度
	CacheHint   int     `json:"-"`           // 预留
	sampleValid bool
}

var (
	trendMu      sync.RWMutex
	trendRing    [ringSize]TrendPoint
	trendIdx     int
	trendCount   int
	latestCPU    float64
	samplerOnce  sync.Once
	samplerStart time.Time
)

// StartSampler 启动趋势采样 goroutine，进程生命周期内常驻，重复调用只生效一次。
func StartSampler() {
	samplerOnce.Do(func() {
		samplerStart = time.Now()
		if selfProc != nil {
			// 首次 Percent 建立基线，返回值无意义
			_, _ = selfProc.Percent(0)
		}
		go func() {
			ticker := time.NewTicker(sampleInterval)
			defer ticker.Stop()
			for range ticker.C {
				sampleOnce()
			}
		}()
	})
}

func sampleOnce() {
	defer func() { recover() }()
	point := TrendPoint{Ts: time.Now().Unix(), sampleValid: true}
	if selfProc != nil {
		// Percent(0) 返回自上次调用以来的平均 CPU 占用；采样器是唯一调用方
		if cpuPct, err := selfProc.Percent(0); err == nil {
			point.CPUPercent = round2(cpuPct)
		}
		if memInfo, err := selfProc.MemoryInfo(); err == nil && memInfo != nil {
			point.RSSBytes = memInfo.RSS
		}
	}
	point.Goroutines = runtime.NumGoroutine()
	if global.GQEQUE_LOG_DB != nil {
		point.QueueLog = global.GQEQUE_LOG_DB.Size()
	}
	if global.GQEQUE_STATS_DB != nil {
		point.QueueStats = global.GQEQUE_STATS_DB.Size()
	}
	if global.GQEQUE_STATS_UPDATE_DB != nil {
		point.QueueStats += global.GQEQUE_STATS_UPDATE_DB.Size()
	}
	if global.GQEQUE_DB != nil {
		point.QueueDb = global.GQEQUE_DB.Size()
	}
	if global.GQEQUE_UPDATE_DB != nil {
		point.QueueDb += global.GQEQUE_UPDATE_DB.Size()
	}
	if global.GQEQUE_MESSAGE_DB != nil {
		point.QueueMsg = global.GQEQUE_MESSAGE_DB.Size()
	}

	trendMu.Lock()
	trendRing[trendIdx] = point
	trendIdx = (trendIdx + 1) % ringSize
	if trendCount < ringSize {
		trendCount++
	}
	latestCPU = point.CPUPercent
	trendMu.Unlock()
}

// GetTrend 返回按时间升序排列的全部有效采样点。
func GetTrend() []TrendPoint {
	trendMu.RLock()
	defer trendMu.RUnlock()
	points := make([]TrendPoint, 0, trendCount)
	start := trendIdx - trendCount
	if start < 0 {
		start += ringSize
	}
	for i := 0; i < trendCount; i++ {
		p := trendRing[(start+i)%ringSize]
		if p.sampleValid {
			points = append(points, p)
		}
	}
	return points
}

// LatestProcessCPU 趋势采样器缓存的最近一次本进程 CPU%。采样器未启动或尚无样本时返回 0。
func LatestProcessCPU() float64 {
	trendMu.RLock()
	defer trendMu.RUnlock()
	return latestCPU
}

func round2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
}
