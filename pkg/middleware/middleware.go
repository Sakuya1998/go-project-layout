// Package middleware 提供常用的HTTP中间件
// 包含日志、指标、限流、CORS、恢复、认证、超时等功能
package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Sakuya1998/go-project-layout/pkg/config"
	"github.com/Sakuya1998/go-project-layout/pkg/logger"
	"github.com/Sakuya1998/go-project-layout/pkg/metrics"
)

// MiddlewareManager 中间件管理器
type MiddlewareManager struct {
	metrics metrics.Metrics
	config  *config.Config
}

// NewMiddlewareManager 创建中间件管理器
func NewMiddlewareManager(cfg *config.Config, m metrics.Metrics) *MiddlewareManager {
	return &MiddlewareManager{
		metrics: m,
		config:  cfg,
	}
}

// Logger 结构化日志中间件
func (m *MiddlewareManager) Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery
		requestID := c.GetString("request_id")
		
		// 记录请求开始日志
		logger.InfoContextKV(c.Request.Context(), "HTTP请求开始",
			"request_id", requestID,
			"method", c.Request.Method,
			"path", path,
			"query", raw,
			"client_ip", c.ClientIP(),
			"user_agent", c.Request.UserAgent(),
			"referer", c.Request.Referer(),
			"content_length", c.Request.ContentLength,
			"proto", c.Request.Proto,
			"timestamp", start,
		)

		c.Next()

		// 计算请求处理时间
		latency := time.Since(start)
		status := c.Writer.Status()
		responseSize := c.Writer.Size()
		
		// 构建基础日志参数
		baseLogArgs := []interface{}{
			"request_id", requestID,
			"method", c.Request.Method,
			"path", path,
			"query", raw,
			"status", status,
			"latency", latency,
			"client_ip", c.ClientIP(),
			"user_agent", c.Request.UserAgent(),
			"response_size", responseSize,
			"proto", c.Request.Proto,
		}

		// 添加错误信息（如果有）
		if len(c.Errors) > 0 {
			errorMsgs := make([]string, len(c.Errors))
			for i, err := range c.Errors {
				errorMsgs[i] = err.Error()
			}
			baseLogArgs = append(baseLogArgs, "errors", errorMsgs)
		}

		// 根据状态码选择日志级别和消息
		ctx := c.Request.Context()
		switch {
		case status >= 500:
			logger.ErrorContextKV(ctx, "HTTP请求完成 - 服务器错误", baseLogArgs...)
		case status >= 400:
			logger.WarnContextKV(ctx, "HTTP请求完成 - 客户端错误", baseLogArgs...)
		case status >= 300:
			logger.InfoContextKV(ctx, "HTTP请求完成 - 重定向", baseLogArgs...)
		default:
			logger.InfoContextKV(ctx, "HTTP请求完成 - 成功", baseLogArgs...)
		}

		// 性能警告
		if latency > 5*time.Second {
			logger.WarnContextKV(ctx, "慢请求检测",
				"request_id", requestID,
				"latency", latency,
				"path", path,
				"method", c.Request.Method,
			)
		}
	}
}

// Recovery 恢复中间件
func (m *MiddlewareManager) Recovery() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		requestID := c.GetString("request_id")
		ctx := c.Request.Context()
		
		// 记录panic详细信息
		logger.ErrorContextKV(ctx, "系统发生Panic异常",
			"request_id", requestID,
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"client_ip", c.ClientIP(),
			"panic_value", recovered,
		)
		
		// 记录堆栈信息
		if err, ok := recovered.(error); ok {
			logger.ErrorContextKV(ctx, "Panic堆栈信息",
				"request_id", requestID,
				"error", err.Error(),
				"stack", "panic_stack",
			)
		} else if errStr, ok := recovered.(string); ok {
			logger.ErrorContextKV(ctx, "Panic堆栈信息",
				"request_id", requestID,
				"error", errStr,
				"stack", "panic_stack",
			)
		}
		
		c.AbortWithStatus(http.StatusInternalServerError)
	})
}

// CORS 跨域中间件
func (m *MiddlewareManager) CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Header("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// Metrics 指标中间件
func (m *MiddlewareManager) Metrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		duration := time.Since(start)
		status := strconv.Itoa(c.Writer.Status())
		method := c.Request.Method
		path := c.FullPath()

		// 记录HTTP请求指标
		m.metrics.RecordHTTPRequest(method, path, status, duration)
	}
}

// SecurityHeaders 安全头中间件
func (m *MiddlewareManager) SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Content Security Policy
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self'; frame-ancestors 'none';")
		
		// HTTP Strict Transport Security
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		
		// X-Frame-Options
		c.Header("X-Frame-Options", "DENY")
		
		// X-Content-Type-Options
		c.Header("X-Content-Type-Options", "nosniff")
		
		// X-XSS-Protection
		c.Header("X-XSS-Protection", "1; mode=block")
		
		// Referrer Policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		
		// Permissions Policy
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		
		c.Next()
	}
}

// APIRateLimit 高级API限流中间件
func (m *MiddlewareManager) APIRateLimit(config RateLimitConfig) gin.HandlerFunc {
	limiter := NewTokenBucketLimiter(config)
	
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		userID := c.GetString("user_id")
		apiKey := c.GetHeader("X-API-Key")
		
		// 构建限流键
		limitKey := buildLimitKey(clientIP, userID, apiKey, c.FullPath())
		
		// 检查限流
		allowed, remaining, resetTime := limiter.Allow(limitKey)
		if !allowed {
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", resetTime.Unix()))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
				"retry_after": resetTime.Sub(time.Now()).Seconds(),
			})
			c.Abort()
			return
		}
		
		// 设置限流响应头
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", resetTime.Unix()))
		
		c.Next()
	}
}

// RateLimit 限流中间件（简单实现）
func (m *MiddlewareManager) RateLimit(maxRequests int, window time.Duration) gin.HandlerFunc {
	type client struct {
		requests int
		lastReset time.Time
	}

	clients := make(map[string]*client)

	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		now := time.Now()
		requestID := c.GetString("request_id")
		ctx := c.Request.Context()

		if cl, exists := clients[clientIP]; exists {
			if now.Sub(cl.lastReset) > window {
				// 记录窗口重置
				logger.DebugContextKV(ctx, "限流窗口重置",
					"request_id", requestID,
					"client_ip", clientIP,
					"previous_requests", cl.requests,
					"window_duration", window,
				)
				cl.requests = 0
				cl.lastReset = now
			}
			cl.requests++
			
			// 记录当前请求计数
			logger.DebugContextKV(ctx, "限流检查",
				"request_id", requestID,
				"client_ip", clientIP,
				"current_requests", cl.requests,
				"max_requests", maxRequests,
				"path", c.Request.URL.Path,
			)
			
			if cl.requests > maxRequests {
				// 记录限流触发
				logger.WarnContextKV(ctx, "触发限流保护",
					"request_id", requestID,
					"client_ip", clientIP,
					"requests_count", cl.requests,
					"max_requests", maxRequests,
					"window_duration", window,
					"path", c.Request.URL.Path,
					"method", c.Request.Method,
					"user_agent", c.Request.UserAgent(),
				)
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
				c.Abort()
				return
			}
		} else {
			// 记录新客户端
			logger.DebugContextKV(ctx, "新客户端限流初始化",
				"request_id", requestID,
				"client_ip", clientIP,
				"max_requests", maxRequests,
				"window_duration", window,
			)
			clients[clientIP] = &client{
				requests: 1,
				lastReset: now,
			}
		}

		c.Next()
	}
}

// Timeout 超时中间件
func (m *MiddlewareManager) Timeout(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetString("request_id")
		start := time.Now()
		
		// 记录超时设置
		logger.DebugContextKV(c.Request.Context(), "设置请求超时",
			"request_id", requestID,
			"timeout", timeout,
			"path", c.Request.URL.Path,
			"method", c.Request.Method,
		)
		
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)
		
		// 监控超时情况
		done := make(chan struct{})
		go func() {
			c.Next()
			close(done)
		}()
		
		select {
		case <-done:
			// 请求正常完成
			duration := time.Since(start)
			if duration > timeout/2 {
				// 请求时间超过超时时间的一半，记录警告
				logger.WarnContextKV(ctx, "请求接近超时阈值",
					"request_id", requestID,
					"duration", duration,
					"timeout", timeout,
					"path", c.Request.URL.Path,
				)
			}
		case <-ctx.Done():
			// 请求超时
			logger.ErrorContextKV(ctx, "请求处理超时",
				"request_id", requestID,
				"timeout", timeout,
				"path", c.Request.URL.Path,
				"method", c.Request.Method,
				"client_ip", c.ClientIP(),
			)
			c.JSON(http.StatusRequestTimeout, gin.H{"error": "Request timeout"})
			c.Abort()
		}
	}
}

// Auth 认证中间件（简单JWT验证）
func (m *MiddlewareManager) Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetString("request_id")
		ctx := c.Request.Context()
		token := c.GetHeader("Authorization")
		
		// 记录认证开始
		logger.DebugContextKV(ctx, "开始JWT认证",
			"request_id", requestID,
			"path", c.Request.URL.Path,
			"method", c.Request.Method,
			"client_ip", c.ClientIP(),
			"has_auth_header", token != "",
		)
		
		if token == "" {
			logger.WarnContextKV(ctx, "认证失败 - 缺少Authorization头",
				"request_id", requestID,
				"path", c.Request.URL.Path,
				"client_ip", c.ClientIP(),
			)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing authorization header"})
			c.Abort()
			return
		}

		// 移除 "Bearer " 前缀
		originalToken := token
		if strings.HasPrefix(token, "Bearer ") {
			token = token[7:]
		}

		// 这里应该验证JWT token，简化实现
		if token == "" {
			logger.WarnContextKV(ctx, "认证失败 - Token为空",
				"request_id", requestID,
				"path", c.Request.URL.Path,
				"client_ip", c.ClientIP(),
				"auth_header", originalToken,
			)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// 记录认证成功
		logger.InfoContextKV(ctx, "JWT认证成功",
			"request_id", requestID,
			"path", c.Request.URL.Path,
			"client_ip", c.ClientIP(),
			"token_length", len(token),
		)

		c.Next()
	}
}

// RequestID 请求ID中间件
func (m *MiddlewareManager) RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		generated := false
		
		if requestID == "" {
			// 生成简单的请求ID
			requestID = fmt.Sprintf("%d", time.Now().UnixNano())
			generated = true
		}

		c.Header("X-Request-ID", requestID)
		c.Set("request_id", requestID)
		
		// 记录请求ID信息
		logger.DebugContextKV(c.Request.Context(), "请求ID处理",
			"request_id", requestID,
			"generated", generated,
			"path", c.Request.URL.Path,
			"method", c.Request.Method,
			"client_ip", c.ClientIP(),
		)
		
		c.Next()
	}
}

// Security 安全头中间件
func (m *MiddlewareManager) Security() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Next()
	}
}

// SetupMiddlewares 设置所有中间件
func (m *MiddlewareManager) SetupMiddlewares(r *gin.Engine) {
	// 基础中间件
	r.Use(m.RequestID())
	r.Use(m.Logger())
	r.Use(m.Recovery())
	r.Use(m.Security())

	// CORS中间件
	if m.config.CORS.Enabled {
		r.Use(m.CORS())
	}

	// 指标中间件
	if m.config.Metrics.Enabled {
		r.Use(m.Metrics())
	}

	// 限流中间件
	if m.config.RateLimit.Enabled {
		r.Use(m.RateLimit(m.config.RateLimit.MaxRequests, time.Duration(m.config.RateLimit.WindowSeconds)*time.Second))
	}

	// 超时中间件
	if m.config.App.Timeout > 0 {
		r.Use(m.Timeout(time.Duration(m.config.App.Timeout) * time.Second))
	}
}

// 便捷函数

// DefaultLogger 默认日志中间件
func DefaultLogger() gin.HandlerFunc {
	return gin.Logger()
}

// DefaultRecovery 默认恢复中间件
func DefaultRecovery() gin.HandlerFunc {
	return gin.Recovery()
}

// SimpleCORS 简单CORS中间件
func SimpleCORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}