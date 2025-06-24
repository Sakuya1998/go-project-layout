package config

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/Sakuya1998/go-project-layout/pkg/errors"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

type Config struct {
	App       ApplicationConfig `mapstructure:"app"`
	Log       LogConfig         `mapstructure:"log"`
	Database  DatabaseConfig    `mapstructure:"database"`
	Redis     RedisConfig       `mapstructure:"redis"`
	Providers []ProviderConfig  `mapstructure:"providers"`
	JWT       JWTConfig         `mapstructure:"jwt"`
	CORS      CORSConfig        `mapstructure:"cors"`
	Metrics   MetricsConfig     `mapstructure:"metrics"`
	Tracing   TracingConfig     `mapstructure:"tracing"`
	RateLimit RateLimitConfig   `mapstructure:"rate_limit"`
}
type ApplicationConfig struct {
	Env     string `mapstructure:"env"`
	Name    string `mapstructure:"name"`
	Version string `mapstructure:"version"`
	Port    int    `mapstructure:"port"`
	Timeout int    `mapstructure:"timeout"`
}

type RateLimitConfig struct {
	Enabled        bool          `mapstructure:"enabled"`
	MaxRequests    int           `mapstructure:"max_requests"`
	WindowSeconds  int           `mapstructure:"window_seconds"`
	BurstSize      int           `mapstructure:"burst_size"`
	CleanupInterval int          `mapstructure:"cleanup_interval"`
	Strategy       string        `mapstructure:"strategy"`
	RedisEnabled   bool          `mapstructure:"redis_enabled"`
	RedisKeyPrefix string        `mapstructure:"redis_key_prefix"`
	Whitelist      []string      `mapstructure:"whitelist"`
	Blacklist      []string      `mapstructure:"blacklist"`
	Headers        HeadersConfig `mapstructure:"headers"`
}

type HeadersConfig struct {
	RateLimitHeader     string `mapstructure:"rate_limit_header"`
	RemainingHeader     string `mapstructure:"remaining_header"`
	ResetHeader         string `mapstructure:"reset_header"`
	RetryAfterHeader    string `mapstructure:"retry_after_header"`
}

type LogConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	Output     string `mapstructure:"output"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxAge     int    `mapstructure:"max_age"`
	MaxBackups int    `mapstructure:"max_backups"`
	Compress   bool   `mapstructure:"compress"`
	Caller     bool   `mapstructure:"caller"`
	Stacktrace bool   `mapstructure:"stacktrace"`
}

type DatabaseConfig struct {
	Driver   string `mapstructure:"driver"`
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	DBName   string `mapstructure:"db_name"`
}

type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

type ProviderConfig struct {
	Provider string `mapstructure:"provider"`
	Key      string `mapstructure:"key"`
	Secret   string `mapstructure:"secret"`
}

type JWTConfig struct {
	Secret    string `mapstructure:"secret"`
	ExpiresIn int    `mapstructure:"expires_in"`
}

type CORSConfig struct {
	Enabled      bool     `mapstructure:"enabled"`
	AllowOrigins []string `mapstructure:"allow_origins"`
	AllowMethods []string `mapstructure:"allow_methods"`
	AllowHeaders []string `mapstructure:"allow_headers"`
}

type MetricsConfig struct {
	Enabled              bool   `mapstructure:"enabled"`
	Path                 string `mapstructure:"path"`
	Port                 int    `mapstructure:"port"`
	Namespace            string `mapstructure:"namespace"`
	EnableGoMetrics      bool   `mapstructure:"enable_go_metrics"`
	EnableProcessMetrics bool   `mapstructure:"enable_process_metrics"`
}

type TracingConfig struct {
	Enabled        bool    `mapstructure:"enabled"`
	ServiceName    string  `mapstructure:"service_name"`
	ServiceVersion string  `mapstructure:"service_version"`
	Environment    string  `mapstructure:"environment"`
	ExporterType   string  `mapstructure:"exporter_type"`
	Endpoint       string  `mapstructure:"endpoint"`
	SampleRatio    float64 `mapstructure:"sample_ratio"`
}

// Load 加载配置文件并返回配置实例
func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/app/")

	// 环境变量支持
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	setDefaults()

	// 读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return nil, errors.NewNotFoundError("配置文件未找到,请检查配置文件路径")
		}
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "CONFIG_LOAD_ERROR", "配置文件读取失败")
	}

	// 解析配置文件
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "CONFIG_PARSE_ERROR", "配置文件解析失败")
	}

	// 配置验证
	if err := config.Validate(); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "CONFIG_VALIDATE_ERROR", "配置文件验证失败")
	}

	return &config, nil
}

// setDefaults 设置配置默认值
func setDefaults() {
	// 应用配置默认值
	viper.SetDefault("app.env", "dev")
	viper.SetDefault("app.name", "go-project-layout")
	viper.SetDefault("app.version", "1.0.0")
	viper.SetDefault("app.port", 8080)

	// 日志配置默认值
	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.format", "json")
	viper.SetDefault("log.path", "./logs")
	viper.SetDefault("log.max_size", 100)
	viper.SetDefault("log.max_age", 7)
	viper.SetDefault("log.max_backups", 3)
	viper.SetDefault("log.compress", true)

	// 数据库配置默认值
	viper.SetDefault("database.driver", "mysql")
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 3306)
	viper.SetDefault("database.user", "root")
	viper.SetDefault("database.password", "")
	viper.SetDefault("database.db_name", "app")

	// Redis 配置默认值
	viper.SetDefault("redis.host", "localhost")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.password", "")
	viper.SetDefault("redis.db", 0)

	// JWT 配置默认值
	viper.SetDefault("jwt.secret", "your-256-bit-secret-key-here-change-in-production")
	viper.SetDefault("jwt.expires_in", 86400)

	// CORS 配置默认值
	viper.SetDefault("cors.allow_origins", []string{"http://localhost:3000"})
	viper.SetDefault("cors.allow_methods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	viper.SetDefault("cors.allow_headers", []string{"Content-Type", "Authorization"})

	// Metrics 配置默认值
	viper.SetDefault("metrics.enabled", true)
	viper.SetDefault("metrics.path", "/metrics")
	viper.SetDefault("metrics.port", 9090)
	viper.SetDefault("metrics.namespace", "app")
	viper.SetDefault("metrics.enable_go_metrics", true)
	viper.SetDefault("metrics.enable_process_metrics", true)

	// Tracing 配置默认值
	// 注意：已移除 Jaeger 支持，推荐使用 OTLP
	viper.SetDefault("tracing.enabled", true)
	viper.SetDefault("tracing.service_name", "go-project-layout")
	viper.SetDefault("tracing.service_version", "1.0.0")
	viper.SetDefault("tracing.environment", "development")
	viper.SetDefault("tracing.exporter_type", "otlp")
	viper.SetDefault("tracing.endpoint", "http://localhost:4318/v1/traces")
	viper.SetDefault("tracing.sample_ratio", 1.0)

	// 限流配置默认值
	viper.SetDefault("rate_limit.enabled", false)
	viper.SetDefault("rate_limit.max_requests", 100)
	viper.SetDefault("rate_limit.window_seconds", 60)
	viper.SetDefault("rate_limit.burst_size", 10)
	viper.SetDefault("rate_limit.cleanup_interval", 300)
	viper.SetDefault("rate_limit.strategy", "fixed_window")
	viper.SetDefault("rate_limit.redis_enabled", false)
	viper.SetDefault("rate_limit.redis_key_prefix", "rate_limit:")
	viper.SetDefault("rate_limit.whitelist", []string{})
	viper.SetDefault("rate_limit.blacklist", []string{})

	// 限流响应头默认值
	viper.SetDefault("rate_limit.headers.rate_limit_header", "X-RateLimit-Limit")
	viper.SetDefault("rate_limit.headers.remaining_header", "X-RateLimit-Remaining")
	viper.SetDefault("rate_limit.headers.reset_header", "X-RateLimit-Reset")
	viper.SetDefault("rate_limit.headers.retry_after_header", "Retry-After")
}

// Validate 验证配置的有效性
func (c *Config) Validate() error {
	// 应用配置验证
	if err := c.validateApp(); err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, "CONFIG_VALIDATION_ERROR", "应用配置验证失败")
	}

	// 数据库配置验证
	if err := c.validateDatabase(); err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, "CONFIG_VALIDATION_ERROR", "数据库配置验证失败")
	}

	// Redis 配置验证
	if err := c.validateRedis(); err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, "CONFIG_VALIDATION_ERROR", "Redis 配置验证失败")
	}

	// JWT 配置验证
	if err := c.validateJWT(); err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, "CONFIG_VALIDATION_ERROR", "JWT 配置验证失败")
	}

	// 日志配置验证
	if err := c.validateLog(); err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, "CONFIG_VALIDATION_ERROR", "日志配置验证失败")
	}

	// CORS 配置验证
	if err := c.validateCORS(); err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, "CONFIG_VALIDATION_ERROR", "CORS 配置验证失败")
	}

	// Metrics 配置验证
	if err := c.validateMetrics(); err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, "CONFIG_VALIDATION_ERROR", "Metrics 配置验证失败")
	}

	// Tracing 配置验证
	if err := c.validateTracing(); err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, "CONFIG_VALIDATION_ERROR", "Tracing 配置验证失败")
	}

	// 限流配置验证
	if err := c.validateRateLimit(); err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, "CONFIG_VALIDATION_ERROR", "限流配置验证失败")
	}

	return nil
}

// validateApp 验证应用配置
func (c *Config) validateApp() error {
	if c.App.Name == "" {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "app.name: 应用名称不能为空")
	}

	if c.App.Env == "" {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "app.env: 环境配置不能为空")
	}

	validEnvs := []string{"dev", "development", "test", "staging", "prod", "production"}
	if !contains(validEnvs, c.App.Env) {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "app.env: 环境配置必须是 dev, test, staging, prod 之一")
	}

	if c.App.Port <= 0 || c.App.Port > 65535 {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "app.port: 端口号必须在 1-65535 范围内")
	}

	if c.App.Version == "" {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "app.version: 应用版本不能为空")
	}

	return nil
}

// validateDatabase 验证数据库配置
func (c *Config) validateDatabase() error {
	if c.Database.Host == "" {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "database.host: 数据库主机地址不能为空")
	}

	if c.Database.Port <= 0 || c.Database.Port > 65535 {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "database.port: 数据库端口号必须在 1-65535 范围内")
	}

	if c.Database.User == "" {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "database.user: 数据库用户名不能为空")
	}

	if c.Database.DBName == "" {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "database.db_name: 数据库名称不能为空")
	}

	validDrivers := []string{"mysql", "postgres", "sqlite"}
	if !contains(validDrivers, c.Database.Driver) {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "database.driver: 数据库驱动只支持 mysql, postgres, sqlite")
	}

	return nil
}

// validateRedis 验证 Redis 配置
func (c *Config) validateRedis() error {
	if c.Redis.Host == "" {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "redis.host: Redis 主机地址不能为空")
	}

	if c.Redis.Port <= 0 || c.Redis.Port > 65535 {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "redis.port: Redis 端口号必须在 1-65535 范围内")
	}

	if c.Redis.DB < 0 || c.Redis.DB > 15 {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "redis.db: Redis 数据库索引必须在 0-15 范围内")
	}

	return nil
}

// validateJWT 验证 JWT 配置
func (c *Config) validateJWT() error {
	if c.JWT.Secret == "" {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "jwt.secret: JWT 密钥不能为空")
	}

	if len(c.JWT.Secret) < 32 {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "jwt.secret: JWT 密钥长度不能少于 32 位")
	}

	if c.JWT.ExpiresIn <= 0 {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "jwt.expires_in: JWT 过期时间必须大于 0")
	}

	// 生产环境下检查是否使用默认密钥
	if c.App.IsProduction() && strings.Contains(c.JWT.Secret, "your-256-bit-secret") {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "jwt.secret: 生产环境不能使用默认 JWT 密钥")
	}

	return nil
}

// validateLog 验证日志配置
func (c *Config) validateLog() error {
	validLogLevels := []string{"debug", "info", "warn", "error", "fatal", "panic"}
	if !contains(validLogLevels, c.Log.Level) {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "log.level: 日志级别必须是 debug, info, warn, error, fatal, panic 之一")
	}

	validLogFormats := []string{"json", "text"}
	if !contains(validLogFormats, c.Log.Format) {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "log.format: 日志格式必须是 json 或 text")
	}

	if c.Log.MaxSize <= 0 {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "log.max_size: 日志文件最大大小必须大于 0")
	}

	if c.Log.MaxAge <= 0 {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "log.max_age: 日志文件保留天数必须大于 0")
	}

	if c.Log.MaxBackups < 0 {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "log.max_backups: 日志备份文件数量不能小于 0")
	}

	return nil
}

// validateCORS 验证 CORS 配置
func (c *Config) validateCORS() error {
	if len(c.CORS.AllowOrigins) == 0 {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "cors.allow_origins: CORS 允许的源不能为空")
	}

	if len(c.CORS.AllowMethods) == 0 {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "cors.allow_methods: CORS 允许的方法不能为空")
	}

	validMethods := []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"}
	for _, method := range c.CORS.AllowMethods {
		if !contains(validMethods, method) {
			return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", fmt.Sprintf("cors.allow_methods: 不支持的 HTTP 方法: %s", method))
		}
	}

	// 生产环境下检查是否使用通配符
	if c.App.IsProduction() {
		for _, origin := range c.CORS.AllowOrigins {
			if origin == "*" {
				return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "cors.allow_origins: 生产环境不建议使用通配符 '*' 作为允许的源")
			}
		}
	}

	return nil
}

// contains 检查字符串切片是否包含指定值
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// GetDSN 根据数据库驱动类型返回相应的数据源名称
func (c *DatabaseConfig) GetDSN() string {
	switch c.Driver {
	case "postgres":
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable TimeZone=UTC",
			c.Host, c.Port, c.User, c.Password, c.DBName)
	case "mysql":
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local&timeout=10s&readTimeout=30s&writeTimeout=30s",
			c.User, c.Password, c.Host, c.Port, c.DBName)
	case "sqlite":
		return fmt.Sprintf("file:%s?cache=shared&mode=rwc&_journal_mode=WAL", c.DBName)
	default:
		return ""
	}
}

// GetAddr 返回数据库地址
func (c *DatabaseConfig) GetAddr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// GetRedisAddr 返回 Redis 地址
func (c *RedisConfig) GetAddr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// GetServerAddr 返回服务器监听地址
func (c *ApplicationConfig) GetServerAddr() string {
	return fmt.Sprintf(":%d", c.Port)
}

// IsDevelopment 判断是否为开发环境
func (c *ApplicationConfig) IsDevelopment() bool {
	return c.Env == "dev" || c.Env == "development"
}

// IsProduction 判断是否为生产环境
func (c *ApplicationConfig) IsProduction() bool {
	return c.Env == "prod" || c.Env == "production"
}

// GetLogFilePath 返回日志文件路径
func (c *LogConfig) GetLogFilePath() string {
	if c.Output == "" {

		return "./logs/app.log"
	}
	return fmt.Sprintf("%s/app.log", c.Output)
}

// validateMetrics 验证指标配置
func (c *Config) validateMetrics() error {
	if !c.Metrics.Enabled {
		return nil
	}

	if c.Metrics.Port <= 0 || c.Metrics.Port > 65535 {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "metrics.port: 指标服务端口号必须在 1-65535 范围内")
	}

	if c.Metrics.Path == "" {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "metrics.path: 指标路径不能为空")
	}

	if c.Metrics.Namespace == "" {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "metrics.namespace: 指标命名空间不能为空")
	}

	return nil
}

// validateTracing 验证追踪配置
func (c *Config) validateTracing() error {
	if !c.Tracing.Enabled {
		return nil
	}

	if c.Tracing.ServiceName == "" {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "tracing.service_name: 服务名称不能为空")
	}

	if c.Tracing.ServiceVersion == "" {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "tracing.service_version: 服务版本不能为空")
	}

	validExporters := []string{"jaeger", "zipkin", "otlp"}
	if !contains(validExporters, c.Tracing.ExporterType) {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "tracing.exporter_type: 追踪导出器类型必须是 jaeger, zipkin, otlp 之一")
	}

	if c.Tracing.SampleRatio < 0 || c.Tracing.SampleRatio > 1 {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "tracing.sample_ratio: 采样比例必须在 0-1 范围内")
	}

	return nil
}

// validateRateLimit 验证限流配置
func (c *Config) validateRateLimit() error {
	if !c.RateLimit.Enabled {
		return nil
	}

	// 验证基本参数
	if c.RateLimit.MaxRequests <= 0 {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "rate_limit.max_requests: 最大请求数必须大于 0")
	}

	if c.RateLimit.WindowSeconds <= 0 {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "rate_limit.window_seconds: 时间窗口必须大于 0 秒")
	}

	// 验证突发大小
	if c.RateLimit.BurstSize < 0 {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "rate_limit.burst_size: 突发大小不能为负数")
	}

	// 验证清理间隔
	if c.RateLimit.CleanupInterval <= 0 {
		c.RateLimit.CleanupInterval = 300 // 默认5分钟
	}

	// 验证策略
	validStrategies := []string{"fixed_window", "sliding_window", "token_bucket", "leaky_bucket"}
	if c.RateLimit.Strategy != "" && !contains(validStrategies, c.RateLimit.Strategy) {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "rate_limit.strategy: 限流策略必须是 fixed_window, sliding_window, token_bucket, leaky_bucket 之一")
	}

	// Redis 配置验证
	if c.RateLimit.RedisEnabled {
		if c.RateLimit.RedisKeyPrefix == "" {
			c.RateLimit.RedisKeyPrefix = "rate_limit:" // 设置默认前缀
		}
		// 检查 Redis 连接配置是否存在
		if c.Redis.Host == "" {
			return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "rate_limit.redis_enabled: 启用 Redis 限流时必须配置 Redis 连接")
		}
	}

	// 验证白名单和黑名单格式
	for _, ip := range c.RateLimit.Whitelist {
		if ip == "" {
			return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "rate_limit.whitelist: 白名单IP不能为空")
		}
	}

	for _, ip := range c.RateLimit.Blacklist {
		if ip == "" {
			return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_VALIDATION_ERROR", "配置验证失败", "rate_limit.blacklist: 黑名单IP不能为空")
		}
	}

	// 验证响应头配置
	if c.RateLimit.Headers.RateLimitHeader == "" {
		c.RateLimit.Headers.RateLimitHeader = "X-RateLimit-Limit"
	}
	if c.RateLimit.Headers.RemainingHeader == "" {
		c.RateLimit.Headers.RemainingHeader = "X-RateLimit-Remaining"
	}
	if c.RateLimit.Headers.ResetHeader == "" {
		c.RateLimit.Headers.ResetHeader = "X-RateLimit-Reset"
	}
	if c.RateLimit.Headers.RetryAfterHeader == "" {
		c.RateLimit.Headers.RetryAfterHeader = "Retry-After"
	}

	return nil
}

// Watch 监听配置文件变化并执行回调函数
// [高危操作] 生产环境使用需谨慎，建议配合熔断机制
func (c *Config) Watch(callback func(*Config, error)) error {
	if callback == nil {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_WATCH_ERROR", "配置监听失败", "callback: 回调函数不能为空")
	}

	// 设置配置文件监听
	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		// 重新加载配置
		newConfig, err := Load()
		if err != nil {
			// 配置加载失败，传递错误给回调
			callback(nil, errors.Wrap(err, errors.ErrorTypeInternal, "CONFIG_RELOAD_ERROR", "配置重新加载失败"))
			return
		}

		// 配置验证通过，执行回调
		callback(newConfig, nil)
	})

	return nil
}

// WatchWithContext 带上下文的配置监听，支持优雅停止
func (c *Config) WatchWithContext(ctx context.Context, callback func(*Config, error)) error {
	if callback == nil {
		return errors.NewWithDetails(errors.ErrorTypeValidation, "CONFIG_WATCH_ERROR", "配置监听失败", "callback: 回调函数不能为空")
	}

	// 使用原子操作标志位控制监听状态
	var stopped int32

	// 包装回调函数，支持上下文取消
	wrappedCallback := func(config *Config, err error) {
		// 检查是否已停止
		if atomic.LoadInt32(&stopped) == 1 {
			return
		}

		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			// 上下文已取消，设置停止标志并返回取消错误
			atomic.StoreInt32(&stopped, 1)
			callback(nil, errors.NewWithDetails(
				errors.ErrorTypeInternal,
				"CONFIG_WATCH_CANCELLED",
				"配置监听已取消",
				fmt.Sprintf("context cancelled: %v", ctx.Err()),
			))
			return
		default:
			// 上下文未取消，执行原始回调
			callback(config, err)
		}
	}

	// 启动配置监听
	if err := c.Watch(wrappedCallback); err != nil {
		return err
	}

	// 监听上下文取消信号
	go func() {
		<-ctx.Done()
		// 设置停止标志，阻止后续回调执行
		atomic.StoreInt32(&stopped, 1)

		// 执行最后一次回调，通知监听已停止
		wrappedCallback(nil, errors.NewWithDetails(
			errors.ErrorTypeInternal,
			"CONFIG_WATCH_STOPPED",
			"配置监听已停止",
			fmt.Sprintf("context done: %v", ctx.Err()),
		))
	}()

	return nil
}
