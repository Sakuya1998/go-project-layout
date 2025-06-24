package middleware

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/Sakuya1998/go-project-layout/pkg/logger"
)

// SQLInjectionPattern SQL注入攻击模式
var SQLInjectionPattern = regexp.MustCompile(`(?i)(\b(select|update|insert|delete|drop|alter|create|rename|truncate|desc|describe|union|into|load_file|outfile)\b|["'\-#;]|/\*|\*/|\-\-)`)

// XSSPattern XSS攻击模式
var XSSPattern = regexp.MustCompile(`(?i)(<script|javascript:|on\w+\s*=|alert\s*\(|eval\s*\(|document\.cookie|document\.location|<iframe|<object|<embed|<img[^>]+\bonerror\b)`)

// SecurityConfig 安全配置
type SecurityConfig struct {
	EnableSQLInjectionProtection bool
	EnableXSSProtection         bool
	EnableContentTypeValidation bool
	BlockedIPs                  []string
	BlockedUserAgents           []string
}

// SQLInjectionProtection SQL注入防护中间件
func (m *MiddlewareManager) SQLInjectionProtection() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 检查URL参数
		for param, values := range c.Request.URL.Query() {
			for _, value := range values {
				if SQLInjectionPattern.MatchString(value) {
					logger.WarnContextKV(c.Request.Context(), "检测到SQL注入攻击尝试",
						"client_ip", c.ClientIP(),
						"path", c.Request.URL.Path,
						"param", param,
						"value", value,
					)
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "请求被拒绝"})
					return
				}
			}
		}

		// 检查表单数据
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			if err := c.Request.ParseForm(); err == nil {
				for param, values := range c.Request.PostForm {
					for _, value := range values {
						if SQLInjectionPattern.MatchString(value) {
						logger.WarnContextKV(c.Request.Context(), "检测到SQL注入攻击尝试",
							"client_ip", c.ClientIP(),
							"path", c.Request.URL.Path,
							"param", param,
							"value", value,
						)
							c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "请求被拒绝"})
							return
						}
					}
				}
			}
		}

		c.Next()
	}
}

// XSSProtection XSS防护中间件
func (m *MiddlewareManager) XSSProtection() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 检查URL参数
		for param, values := range c.Request.URL.Query() {
			for _, value := range values {
				if XSSPattern.MatchString(value) {
					logger.WarnContextKV(c.Request.Context(), "检测到XSS攻击尝试",
						"client_ip", c.ClientIP(),
						"path", c.Request.URL.Path,
						"param", param,
						"value", value,
					)
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "请求被拒绝"})
					return
				}
			}
		}

		// 检查表单数据
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			if err := c.Request.ParseForm(); err == nil {
				for param, values := range c.Request.PostForm {
					for _, value := range values {
						if XSSPattern.MatchString(value) {
						logger.WarnContextKV(c.Request.Context(), "检测到XSS攻击尝试",
							"client_ip", c.ClientIP(),
							"path", c.Request.URL.Path,
							"param", param,
							"value", value,
						)
							c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "请求被拒绝"})
							return
						}
					}
				}
			}
		}

		c.Next()
	}
}

// IPFilter IP过滤中间件
func (m *MiddlewareManager) IPFilter(blockedIPs []string) gin.HandlerFunc {
	// 转换为map以便快速查找
	blockedIPMap := make(map[string]bool)
	for _, ip := range blockedIPs {
		blockedIPMap[ip] = true
	}

	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		if blockedIPMap[clientIP] {
			logger.WarnContextKV(c.Request.Context(), "检测到来自黑名单IP的请求",
				"client_ip", clientIP,
				"path", c.Request.URL.Path,
			)
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		c.Next()
	}
}

// UserAgentFilter User-Agent过滤中间件
func (m *MiddlewareManager) UserAgentFilter(blockedUserAgents []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userAgent := c.Request.UserAgent()

		for _, blockedUA := range blockedUserAgents {
			if strings.Contains(strings.ToLower(userAgent), strings.ToLower(blockedUA)) {
				logger.WarnContextKV(c.Request.Context(), "检测到来自黑名单User-Agent的请求",
					"client_ip", c.ClientIP(),
					"user_agent", userAgent,
					"path", c.Request.URL.Path,
				)
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		}

		c.Next()
	}
}

// ContentTypeValidation 内容类型验证中间件
func (m *MiddlewareManager) ContentTypeValidation() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 只检查POST、PUT和PATCH请求
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			contentType := c.GetHeader("Content-Type")

			// 检查是否为空
			if contentType == "" {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Content-Type header is required"})
				return
			}

			// 检查是否为允许的类型
			allowedTypes := []string{"application/json", "application/x-www-form-urlencoded", "multipart/form-data"}
			valid := false

			for _, allowedType := range allowedTypes {
				if strings.Contains(contentType, allowedType) {
					valid = true
					break
				}
			}

			if !valid {
				c.AbortWithStatusJSON(http.StatusUnsupportedMediaType, gin.H{"error": "Unsupported Content-Type"})
				return
			}
		}

		c.Next()
	}
}