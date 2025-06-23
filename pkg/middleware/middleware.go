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
	"go.uber.org/zap"

	"github.com/your-org/your-project/pkg/config"
	"github.com/your-org/your-project/pkg/logger"
	"github.com/your-org/your-project/pkg/metrics"
)

// MiddlewareManager 中间件管理器
type MiddlewareManager struct {
	logger  *zap.Logger
	metrics metrics.Metrics
	config  *config.Config
}

// NewMiddlewareManager 创建中间件管理器
func NewMiddlewareManager(cfg *config.Config, log *zap.Logger, m metrics.Metrics) *MiddlewareManager {
	return &MiddlewareManager{
		logger:  log,
		metrics: m,
		config:  cfg,
	}
}

// Logger 日志中间件
func (m *MiddlewareManager) Logger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\
",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	})
}

// Recovery 恢复中间件
func (m *MiddlewareManager) Recovery() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		if err, ok := recovered.(string); ok {
			m.logger.Error("Panic recovered", zap.String("error", err))
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
		m.metrics.IncHTTPRequests(method, path, status)
		m.metrics.ObserveHTTPDuration(method, path, status, duration.Seconds())
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

		if cl, exists := clients[clientIP]; exists {
			if now.Sub(cl.lastReset) > window {
				cl.requests = 0
				cl.lastReset = now
			}
			cl.requests++
			if cl.requests > maxRequests {
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
				c.Abort()
				return
			}
		} else {
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
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// Auth 认证中间件（简单JWT验证）
func (m *MiddlewareManager) Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing authorization header"})
			c.Abort()
			return
		}

		// 移除 "Bearer " 前缀
		if strings.HasPrefix(token, "Bearer ") {
			token = token[7:]
		}

		// 这里应该验证JWT token，简化实现
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequestID 请求ID中间件
func (m *MiddlewareManager) RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			// 生成简单的请求ID
			requestID = fmt.Sprintf("%d", time.Now().UnixNano())
		}

		c.Header("X-Request-ID", requestID)
		c.Set("request_id", requestID)
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
	if m.config.Server.CORS.Enabled {
		r.Use(m.CORS())
	}

	// 指标中间件
	if m.config.Metrics.Enabled {
		r.Use(m.Metrics())
	}

	// 限流中间件
	if m.config.Server.RateLimit.Enabled {
		r.Use(m.RateLimit(m.config.Server.RateLimit.MaxRequests, time.Duration(m.config.Server.RateLimit.WindowSeconds)*time.Second))
	}

	// 超时中间件
	if m.config.Server.Timeout > 0 {
		r.Use(m.Timeout(time.Duration(m.config.Server.Timeout) * time.Second))
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