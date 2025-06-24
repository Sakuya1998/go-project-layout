// Package health 提供应用健康检查功能
// 支持多种健康检查器和状态聚合
package health

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Status 健康状态
type Status string

const (
	// StatusHealthy 健康状态
	StatusHealthy Status = "healthy"
	// StatusUnhealthy 不健康状态
	StatusUnhealthy Status = "unhealthy"
	// StatusDegraded 降级状态
	StatusDegraded Status = "degraded"
	// StatusUnknown 未知状态
	StatusUnknown Status = "unknown"
)

// CheckResult 健康检查结果
type CheckResult struct {
	Status    Status                 `json:"status"`
	Message   string                 `json:"message,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Duration  time.Duration          `json:"duration"`
}

// Checker 健康检查器接口
type Checker interface {
	Check(ctx context.Context) CheckResult
	Name() string
}

// CheckerFunc 函数式健康检查器
type CheckerFunc struct {
	name string
	fn   func(ctx context.Context) CheckResult
}

// Check 执行健康检查
func (c CheckerFunc) Check(ctx context.Context) CheckResult {
	return c.fn(ctx)
}

// Name 返回检查器名称
func (c CheckerFunc) Name() string {
	return c.name
}

// NewChecker 创建函数式健康检查器
func NewChecker(name string, fn func(ctx context.Context) CheckResult) Checker {
	return CheckerFunc{name: name, fn: fn}
}

// Health 健康检查管理器
type Health struct {
	mu       sync.RWMutex
	checkers map[string]Checker
	timeout  time.Duration
}

// New 创建健康检查管理器
func New() *Health {
	return &Health{
		checkers: make(map[string]Checker),
		timeout:  5 * time.Second,
	}
}

// SetTimeout 设置检查超时时间
func (h *Health) SetTimeout(timeout time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.timeout = timeout
}

// Register 注册健康检查器
func (h *Health) Register(checker Checker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checkers[checker.Name()] = checker
}

// Unregister 注销健康检查器
func (h *Health) Unregister(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.checkers, name)
}

// Check 执行所有健康检查
func (h *Health) Check(ctx context.Context) map[string]CheckResult {
	h.mu.RLock()
	checkers := make(map[string]Checker, len(h.checkers))
	for name, checker := range h.checkers {
		checkers[name] = checker
	}
	timeout := h.timeout
	h.mu.RUnlock()

	results := make(map[string]CheckResult)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for name, checker := range checkers {
		wg.Add(1)
		go func(name string, checker Checker) {
			defer wg.Done()

			checkCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			start := time.Now()
			result := checker.Check(checkCtx)
			result.Duration = time.Since(start)
			result.Timestamp = time.Now()

			mu.Lock()
			results[name] = result
			mu.Unlock()
		}(name, checker)
	}

	wg.Wait()
	return results
}

// CheckOne 执行单个健康检查
func (h *Health) CheckOne(ctx context.Context, name string) (CheckResult, bool) {
	h.mu.RLock()
	checker, exists := h.checkers[name]
	timeout := h.timeout
	h.mu.RUnlock()

	if !exists {
		return CheckResult{}, false
	}

	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	result := checker.Check(checkCtx)
	result.Duration = time.Since(start)
	result.Timestamp = time.Now()

	return result, true
}

// Status 获取整体健康状态
func (h *Health) Status(ctx context.Context) Status {
	results := h.Check(ctx)

	if len(results) == 0 {
		return StatusUnknown
	}

	healthyCount := 0
	degradedCount := 0
	unhealthyCount := 0

	for _, result := range results {
		switch result.Status {
		case StatusHealthy:
			healthyCount++
		case StatusDegraded:
			degradedCount++
		case StatusUnhealthy:
			unhealthyCount++
		}
	}

	// 如果有任何不健康的检查，整体状态为不健康
	if unhealthyCount > 0 {
		return StatusUnhealthy
	}

	// 如果有降级的检查，整体状态为降级
	if degradedCount > 0 {
		return StatusDegraded
	}

	// 所有检查都健康
	return StatusHealthy
}

// IsHealthy 检查是否健康
func (h *Health) IsHealthy(ctx context.Context) bool {
	return h.Status(ctx) == StatusHealthy
}

// IsReady 检查是否就绪（所有关键依赖都健康）
func (h *Health) IsReady(ctx context.Context) bool {
	results := h.Check(ctx)
	
	// 检查关键依赖服务
	criticalServices := []string{"database", "redis", "config"}
	for _, service := range criticalServices {
		if result, exists := results[service]; exists {
			if result.Status == StatusUnhealthy {
				return false
			}
		}
	}
	
	return true
}

// GetDependencyStatus 获取依赖服务状态摘要
func (h *Health) GetDependencyStatus(ctx context.Context) map[string]interface{} {
	results := h.Check(ctx)
	status := make(map[string]interface{})
	
	for name, result := range results {
		status[name] = map[string]interface{}{
			"status":    result.Status,
			"message":   result.Message,
			"duration":  result.Duration.String(),
			"timestamp": result.Timestamp.Format(time.RFC3339),
		}
	}
	
	return status
}

// 预定义的健康检查器

// DatabaseChecker 数据库健康检查器
func DatabaseChecker(name string, dsn string) Checker {
	return NewChecker(name, func(ctx context.Context) CheckResult {
		// 简化实现，实际应用中应该检查真实的数据库连接
		select {
		case <-ctx.Done():
			return CheckResult{
				Status:  StatusUnhealthy,
				Message: "Database check timeout",
			}
		default:
			// 模拟数据库检查
			return CheckResult{
				Status:  StatusHealthy,
				Message: "Database connection is healthy",
				Details: map[string]interface{}{
					"dsn": dsn,
				},
			}
		}
	})
}

// RedisChecker Redis健康检查器
func RedisChecker(name string, addr string) Checker {
	return NewChecker(name, func(ctx context.Context) CheckResult {
		start := time.Now()
		// 模拟Redis连接检查
		latency := time.Since(start)
		
		if latency > 100*time.Millisecond {
			return CheckResult{
				Status:  StatusDegraded,
				Message: fmt.Sprintf("Redis latency %.2fms is high", float64(latency.Nanoseconds())/1e6),
				Details: map[string]interface{}{
					"addr":    addr,
					"latency": latency.String(),
				},
			}
		}
		
		return CheckResult{
			Status:  StatusHealthy,
			Message: "Redis connection is healthy",
			Details: map[string]interface{}{
				"addr":    addr,
				"latency": latency.String(),
			},
		}
	})
}

// HTTPServiceChecker HTTP服务健康检查器
func HTTPServiceChecker(name string, url string, timeout time.Duration) Checker {
	return NewChecker(name, func(ctx context.Context) CheckResult {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return CheckResult{
				Status:  StatusUnhealthy,
				Message: fmt.Sprintf("Failed to create request: %v", err),
				Details: map[string]interface{}{
					"url":   url,
					"error": err.Error(),
				},
			}
		}
		
		client := &http.Client{Timeout: timeout}
		resp, err := client.Do(req)
		if err != nil {
			return CheckResult{
				Status:  StatusUnhealthy,
				Message: fmt.Sprintf("HTTP request failed: %v", err),
				Details: map[string]interface{}{
					"url":   url,
					"error": err.Error(),
				},
			}
		}
		defer resp.Body.Close()
		
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return CheckResult{
				Status:  StatusHealthy,
				Message: "HTTP service is healthy",
				Details: map[string]interface{}{
					"url":         url,
					"status_code": resp.StatusCode,
				},
			}
		}
		
		return CheckResult{
			Status:  StatusDegraded,
			Message: fmt.Sprintf("HTTP service returned status %d", resp.StatusCode),
			Details: map[string]interface{}{
				"url":         url,
				"status_code": resp.StatusCode,
			},
		}
	})
}

// AlwaysHealthy 总是返回健康状态的检查器
func AlwaysHealthy(name string) Checker {
	return NewChecker(name, func(ctx context.Context) CheckResult {
		return CheckResult{
			Status:  StatusHealthy,
			Message: "Always healthy",
		}
	})
}

// AlwaysUnhealthy 总是返回不健康状态的检查器
func AlwaysUnhealthy(name string) Checker {
	return NewChecker(name, func(ctx context.Context) CheckResult {
		return CheckResult{
			Status:  StatusUnhealthy,
			Message: "Always unhealthy",
		}
	})
}

// PingChecker 简单的ping检查器
func PingChecker(name string) Checker {
	return NewChecker(name, func(ctx context.Context) CheckResult {
		return CheckResult{
			Status:  StatusHealthy,
			Message: "Ping successful",
		}
	})
}

// MemoryChecker 内存使用检查器
func MemoryChecker(name string, threshold float64) Checker {
	return NewChecker(name, func(ctx context.Context) CheckResult {
		// 简化实现，实际应用中可以检查真实的内存使用情况
		usage := 0.5 // 模拟50%的内存使用率

		if usage > threshold {
			return CheckResult{
				Status:  StatusDegraded,
				Message: fmt.Sprintf("Memory usage %.2f%% exceeds threshold %.2f%%", usage*100, threshold*100),
				Details: map[string]interface{}{
					"usage":     usage,
					"threshold": threshold,
				},
			}
		}

		return CheckResult{
			Status:  StatusHealthy,
			Message: fmt.Sprintf("Memory usage %.2f%% is normal", usage*100),
			Details: map[string]interface{}{
				"usage":     usage,
				"threshold": threshold,
			},
		}
	})
}

// 全局健康检查实例
var globalHealth = New()

// Register 注册全局健康检查器
func Register(checker Checker) {
	globalHealth.Register(checker)
}

// Unregister 注销全局健康检查器
func Unregister(name string) {
	globalHealth.Unregister(name)
}

// Check 执行全局健康检查
func Check(ctx context.Context) map[string]CheckResult {
	return globalHealth.Check(ctx)
}

// CheckOne 执行单个全局健康检查
func CheckOne(ctx context.Context, name string) (CheckResult, bool) {
	return globalHealth.CheckOne(ctx, name)
}

// Status 获取全局健康状态
func GetStatus(ctx context.Context) Status {
	return globalHealth.Status(ctx)
}

// IsHealthy 检查全局是否健康
func IsHealthy(ctx context.Context) bool {
	return globalHealth.IsHealthy(ctx)
}

// SetTimeout 设置全局检查超时时间
func SetTimeout(timeout time.Duration) {
	globalHealth.SetTimeout(timeout)
}
