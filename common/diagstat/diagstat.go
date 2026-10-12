package diagstat

import (
	"sort"
	"sync"
)

// 运行诊断的组件计量注册表。
// 零依赖：任何模块（引擎/队列/缓存等）都可以安全 import 并注册自己的计量项，
// 诊断侧统一 CollectAll 汇总，避免诊断模块反向 import 业务包形成环。

// Collector 返回该组件当前的计量值集合（key -> 数值）。
// 实现必须廉价（内存读取级别），不允许做 IO / 阻塞操作。
type Collector func() map[string]int64

var (
	mu         sync.RWMutex
	collectors = map[string]Collector{}
)

// Register 注册一个组件计量器，name 重复时覆盖。
func Register(name string, fn Collector) {
	if fn == nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	collectors[name] = fn
}

// ComponentStat 一个组件的计量结果。
type ComponentStat struct {
	Name  string           `json:"name"`
	Items map[string]int64 `json:"items"`
}

// CollectAll 汇总所有已注册组件的计量值，按组件名排序保证输出稳定。
// 单个 collector panic 不影响其他组件。
func CollectAll() []ComponentStat {
	mu.RLock()
	names := make([]string, 0, len(collectors))
	for name := range collectors {
		names = append(names, name)
	}
	mu.RUnlock()
	sort.Strings(names)

	result := make([]ComponentStat, 0, len(names))
	for _, name := range names {
		mu.RLock()
		fn := collectors[name]
		mu.RUnlock()
		if fn == nil {
			continue
		}
		items := safeCollect(fn)
		if items != nil {
			result = append(result, ComponentStat{Name: name, Items: items})
		}
	}
	return result
}

func safeCollect(fn Collector) (items map[string]int64) {
	defer func() {
		if r := recover(); r != nil {
			items = nil
		}
	}()
	return fn()
}
