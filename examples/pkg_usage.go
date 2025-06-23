// Package examples 展示如何使用pkg包中的各种组件
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Sakuya1998/go-project-layout/pkg/config"
	"github.com/Sakuya1998/go-project-layout/pkg/errors"
	"github.com/Sakuya1998/go-project-layout/pkg/health"
	"github.com/Sakuya1998/go-project-layout/pkg/logger"
	"github.com/Sakuya1998/go-project-layout/pkg/metrics"
	"github.com/Sakuya1998/go-project-layout/pkg/middleware"
	"github.com/Sakuya1998/go-project-layout/pkg/tracing"
	"github.com/Sakuya1998/go-project-layout/pkg/utils"
)

func main() {
	// 1. 配置管理示例
	fmt.Println("=== 配置管理示例 ===")
	cfg, err := config.Load("config.yaml")
	if err != nil {
		// 使用默认配置
		cfg = config.Default()
		fmt.Println("使用默认配置")
	}
	fmt.Printf("服务端口: %d\n", cfg.Server.Port)
	fmt.Printf("日志级别: %s\n", cfg.Logger.Level)

	// 2. 日志系统示例
	fmt.Println("\n=== 日志系统示例 ===")
	logger := logger.New(cfg.Logger)
	logger.Info("应用启动", "version", "1.0.0")
	logger.Debug("调试信息", "module", "example")
	logger.Error("错误信息", "error", "示例错误")

	// 设置全局日志
	logger.Init(logger)
	logger.GetGlobal().Info("全局日志已初始化")

	// 3. 错误处理示例
	fmt.Println("\n=== 错误处理示例 ===")
	// 创建各种类型的错误
	validationErr := errors.NewValidationError("用户名不能为空")
	notFoundErr := errors.NewNotFoundError("用户")
	unauthorizedErr := errors.NewUnauthorizedError("")

	fmt.Printf("验证错误: %s (HTTP状态码: %d)\n", validationErr.Error(), validationErr.HTTPStatus())
	fmt.Printf("未找到错误: %s (HTTP状态码: %d)\n", notFoundErr.Error(), notFoundErr.HTTPStatus())
	fmt.Printf("未授权错误: %s (HTTP状态码: %d)\n", unauthorizedErr.Error(), unauthorizedErr.HTTPStatus())

	// 错误包装
	originalErr := fmt.Errorf("数据库连接失败")
	wrappedErr := errors.Wrap(originalErr, errors.ErrorTypeInternal, "DB_ERROR", "数据库操作失败")
	fmt.Printf("包装错误: %s\n", wrappedErr.Error())

	// 4. 健康检查示例
	fmt.Println("\n=== 健康检查示例 ===")
	// 注册健康检查器
	health.Register(health.PingChecker("ping"))
	health.Register(health.MemoryChecker("memory", 0.8)) // 80%阈值
	health.Register(health.AlwaysHealthy("service"))

	ctx := context.Background()
	results := health.Check(ctx)
	for name, result := range results {
		fmt.Printf("检查器 %s: %s - %s (耗时: %v)\n",
			name, result.Status, result.Message, result.Duration)
	}

	overallStatus := health.Status(ctx)
	fmt.Printf("整体健康状态: %s\n", overallStatus)

	// 5. 指标收集示例
	fmt.Println("\n=== 指标收集示例 ===")
	metricsCollector := metrics.New(cfg.Metrics)
	if metricsCollector != nil {
		// 记录各种指标
		metricsCollector.IncrementCounter("http_requests_total", map[string]string{
			"method": "GET",
			"path":   "/api/users",
		})

		metricsCollector.RecordHistogram("http_request_duration_seconds", 0.123, map[string]string{
			"method": "GET",
			"path":   "/api/users",
		})

		metricsCollector.SetGauge("active_connections", 42, nil)

		fmt.Println("指标已记录")
	}

	// 6. 链路追踪示例
	fmt.Println("\n=== 链路追踪示例 ===")
	tracer := tracing.New(cfg.Tracing)
	if tracer != nil {
		ctx, span := tracer.StartSpan(ctx, "example_operation")
		span.SetAttribute("user_id", "12345")
		span.SetAttribute("operation", "get_user")

		// 模拟一些工作
		time.Sleep(10 * time.Millisecond)

		span.End()
		fmt.Println("链路追踪span已创建")
	}

	// 7. 工具函数示例
	fmt.Println("\n=== 工具函数示例 ===")
	// 字符串工具
	originalStr := "hello world"
	camelCase := utils.ToCamelCase(originalStr)
	snakeCase := utils.ToSnakeCase(originalStr)
	fmt.Printf("原始: %s, 驼峰: %s, 蛇形: %s\n", originalStr, camelCase, snakeCase)

	// 验证工具
	email := "test@example.com"
	if utils.IsEmail(email) {
		fmt.Printf("%s 是有效的邮箱地址\n", email)
	}

	// 时间工具
	now := time.Now()
	formatted := utils.FormatTime(now, "2006-01-02 15:04:05")
	fmt.Printf("格式化时间: %s\n", formatted)

	// 加密工具
	password := "mypassword"
	hashed := utils.HashPassword(password)
	fmt.Printf("密码哈希: %s\n", hashed)

	// 8. Web服务器示例
	fmt.Println("\n=== Web服务器示例 ===")
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	// 设置中间件
	middlewareManager := middleware.NewManager(cfg)
	middlewareManager.SetupMiddlewares(r)

	// 或者使用便捷函数
	r.Use(middleware.DefaultLogger())
	r.Use(middleware.DefaultRecovery())
	r.Use(middleware.SimpleCORS())

	// API路由
	api := r.Group("/api/v1")
	{
		api.GET("/health", func(c *gin.Context) {
			results := health.Check(c.Request.Context())
			status := health.Status(c.Request.Context())

			response := gin.H{
				"status":    status,
				"checks":    results,
				"timestamp": time.Now(),
			}

			if status == health.StatusHealthy {
				c.JSON(http.StatusOK, response)
			} else {
				c.JSON(http.StatusServiceUnavailable, response)
			}
		})

		api.GET("/users/:id", func(c *gin.Context) {
			userID := c.Param("id")

			// 模拟业务逻辑
			if userID == "" {
				err := errors.NewValidationError("用户ID不能为空")
				c.JSON(err.HTTPStatus(), errors.ToErrorResponse(err))
				return
			}

			if userID == "999" {
				err := errors.NewNotFoundError("用户")
				c.JSON(err.HTTPStatus(), errors.ToErrorResponse(err))
				return
			}

			// 记录指标
			if metricsCollector != nil {
				metricsCollector.IncrementCounter("api_requests_total", map[string]string{
					"endpoint": "get_user",
					"status":   "success",
				})
			}

			c.JSON(http.StatusOK, gin.H{
				"id":    userID,
				"name":  "示例用户",
				"email": "user@example.com",
			})
		})
	}

	// 指标端点
	if cfg.Metrics.Enabled {
		r.GET(cfg.Metrics.Path, gin.WrapH(metrics.Handler()))
	}

	fmt.Printf("服务器启动在端口 %d\n", cfg.Server.Port)
	fmt.Println("可用端点:")
	fmt.Println("  GET /api/v1/health - 健康检查")
	fmt.Println("  GET /api/v1/users/:id - 获取用户信息")
	if cfg.Metrics.Enabled {
		fmt.Printf("  GET %s - Prometheus指标\n", cfg.Metrics.Path)
	}

	// 启动服务器
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.Port),
		Handler: r,
	}

	log.Printf("服务器启动失败: %v", server.ListenAndServe())
}
