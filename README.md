# Go项目标准布局 - 优化版

这是一个经过优化的Go项目标准布局，专注于云原生时代的高性能、高并发分布式系统开发。

## 🚀 项目特色

- **简洁高效**: 移除冗余代码，保留核心功能
- **云原生**: 支持容器化部署和微服务架构
- **可观测性**: 集成日志、指标、链路追踪
- **标准化**: 遵循Go社区最佳实践
- **生产就绪**: 包含健康检查、错误处理、中间件等

## 📁 项目结构

```
├── cmd/                    # 应用程序入口
│   └── server/            # 服务器应用
│       └── main.go
├── internal/              # 私有应用代码
│   ├── api/              # API层
│   │   ├── handlers/     # HTTP处理器
│   │   └── routes.go     # 路由定义
│   ├── application/      # 应用层
│   │   ├── services/     # 业务服务
│   │   └── tasks/        # 后台任务
│   ├── domain/           # 领域层
│   │   ├── model/        # 领域模型
│   │   └── repository/   # 仓储接口
│   └── infrastructure/   # 基础设施层
│       ├── cache/        # 缓存实现
│       ├── database/     # 数据库实现
│       ├── providers/    # 外部服务提供者
│       └── security/     # 安全相关
├── pkg/                  # 可复用的库代码
│   ├── config/          # 配置管理
│   ├── errors/          # 错误处理
│   ├── health/          # 健康检查
│   ├── logger/          # 日志系统
│   ├── metrics/         # 指标收集
│   ├── middleware/      # HTTP中间件
│   ├── tracing/         # 链路追踪
│   └── utils/           # 工具函数
├── configs/             # 配置文件
├── deploy/              # 部署相关文件
├── doc/                 # 文档
├── examples/            # 示例代码
├── test/                # 测试文件
│   ├── integration/     # 集成测试
│   └── unit/           # 单元测试
├── go.mod              # Go模块定义
├── go.sum              # 依赖校验和
└── README.md           # 项目说明
```

## 🛠️ 核心组件

### 配置管理 (`pkg/config`)

统一的配置管理系统，支持YAML文件和环境变量：

```go
// 加载配置
cfg, err := config.Load("config.yaml")
if err != nil {
    cfg = config.Default() // 使用默认配置
}

// 验证配置
if err := cfg.Validate(); err != nil {
    log.Fatal("配置验证失败:", err)
}
```

### 日志系统 (`pkg/logger`)

基于Zap的高性能日志系统：

```go
// 创建日志器
logger := logger.New(cfg.Logger)
logger.Info("应用启动", "version", "1.0.0")
logger.Error("错误信息", "error", err)

// 使用全局日志器
logger.Init(logger)
logger.GetGlobal().Info("全局日志")
```

### 错误处理 (`pkg/errors`)

统一的错误处理机制，支持错误分类和HTTP状态码映射：

```go
// 创建不同类型的错误
validationErr := errors.NewValidationError("用户名不能为空")
notFoundErr := errors.NewNotFoundError("用户")
unauthorizedErr := errors.NewUnauthorizedError("")

// 错误包装
wrappedErr := errors.Wrap(originalErr, errors.ErrorTypeInternal, "DB_ERROR", "数据库操作失败")

// 获取HTTP状态码
status := errors.GetHTTPStatus(err)

// 转换为HTTP响应
response := errors.ToErrorResponse(err)
```

### 健康检查 (`pkg/health`)

灵活的健康检查系统，支持多种检查器：

```go
// 注册健康检查器
health.Register(health.PingChecker("ping"))
health.Register(health.MemoryChecker("memory", 0.8))

// 执行健康检查
ctx := context.Background()
results := health.Check(ctx)
status := health.Status(ctx)
```

### 指标收集 (`pkg/metrics`)

基于Prometheus的指标收集系统：

```go
// 创建指标收集器
metrics := metrics.New(cfg.Metrics)

// 记录指标
metrics.IncrementCounter("http_requests_total", map[string]string{
    "method": "GET",
    "path":   "/api/users",
})

metrics.RecordHistogram("http_request_duration_seconds", 0.123, nil)
metrics.SetGauge("active_connections", 42, nil)
```

### 链路追踪 (`pkg/tracing`)

基于OpenTelemetry的分布式链路追踪：

```go
// 创建追踪器
tracer := tracing.New(cfg.Tracing)

// 创建span
ctx, span := tracer.StartSpan(ctx, "operation_name")
span.SetAttribute("user_id", "12345")
defer span.End()
```

### 中间件 (`pkg/middleware`)

常用的HTTP中间件集合：

```go
// 使用中间件管理器
manager := middleware.NewManager(cfg)
manager.SetupMiddlewares(router)

// 或使用便捷函数
router.Use(middleware.DefaultLogger())
router.Use(middleware.DefaultRecovery())
router.Use(middleware.SimpleCORS())
```

### 工具函数 (`pkg/utils`)

常用的工具函数集合：

```go
// 字符串工具
camelCase := utils.ToCamelCase("hello world")
snakeCase := utils.ToSnakeCase("HelloWorld")

// 验证工具
if utils.IsEmail("test@example.com") {
    // 有效邮箱
}

// 时间工具
formatted := utils.FormatTime(time.Now(), "2006-01-02 15:04:05")

// 加密工具
hashed := utils.HashPassword("password")
```

## 🚀 快速开始

### 1. 克隆项目

```bash
git clone <repository-url>
cd go-project-layout
```

### 2. 安装依赖

```bash
go mod download
```

### 3. 配置文件

复制并修改配置文件：

```bash
cp configs/config.yaml.example configs/config.yaml
```

### 4. 运行示例

```bash
# 运行包使用示例
go run examples/pkg_usage.go

# 运行服务器
go run cmd/server/main.go
```

### 5. 访问服务

- 健康检查: `GET http://localhost:8080/api/v1/health`
- 用户API: `GET http://localhost:8080/api/v1/users/123`
- Prometheus指标: `GET http://localhost:8080/metrics`

## 📊 可观测性

### 日志

- 结构化日志输出
- 支持多种日志级别
- 可配置输出格式和目标

### 指标

- HTTP请求计数器
- 请求延迟直方图
- 活跃连接数量表
- 自定义业务指标

### 链路追踪

- 分布式请求追踪
- 服务间调用关系
- 性能瓶颈分析

### 健康检查

- 应用存活性检查
- 服务就绪性检查
- 依赖服务状态检查

## 🔧 配置说明

### 服务器配置

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "60s"
```

### 日志配置

```yaml
logger:
  enabled: true
  level: "info"
  format: "json"
  output: "stdout"
```

### 指标配置

```yaml
metrics:
  enabled: true
  path: "/metrics"
  port: 9090
  namespace: "myapp"
```

### 追踪配置

```yaml
tracing:
  enabled: true
  service_name: "my-service"
  service_version: "1.0.0"
  environment: "production"
  exporter_type: "jaeger"
  endpoint: "http://localhost:14268/api/traces"
  sample_ratio: 0.1
```

## 🧪 测试

```bash
# 运行单元测试
go test ./...

# 运行集成测试
go test -tags=integration ./test/integration/...

# 生成测试覆盖率报告
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## 📦 构建和部署

### 本地构建

```bash
# 构建二进制文件
go build -o bin/server cmd/server/main.go

# 运行
./bin/server
```

### Docker构建

```bash
# 构建镜像
docker build -t my-app:latest .

# 运行容器
docker run -p 8080:8080 my-app:latest
```

### Kubernetes部署

```bash
# 应用部署文件
kubectl apply -f deploy/k8s/
```

## 🤝 贡献指南

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 打开 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🔗 相关资源

- [Go官方文档](https://golang.org/doc/)
- [Gin Web框架](https://gin-gonic.com/)
- [Zap日志库](https://github.com/uber-go/zap)
- [Prometheus](https://prometheus.io/)
- [OpenTelemetry](https://opentelemetry.io/)
- [Go项目布局标准](https://github.com/golang-standards/project-layout)

## 📞 支持

如果您有任何问题或建议，请通过以下方式联系：

- 提交 [Issue](https://github.com/your-repo/issues)
- 发送邮件到 your-email@example.com
- 加入我们的 [Discord](https://discord.gg/your-invite)

---

**注意**: 这是一个模板项目，请根据您的具体需求进行调整和扩展。