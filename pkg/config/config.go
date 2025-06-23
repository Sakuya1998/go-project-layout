package config

import (
	"fmt"
	"strings"

	"github.com/Sakuya1998/go-project-layout/pkg/errors"
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
}
type ApplicationConfig struct {
	Env     string `mapstructure:"env"`
	Name    string `mapstructure:"name"`
	Version string `mapstructure:"version"`
	Port    int    `mapstructure:"port"`
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
			return nil, errors.NewConfigNotFoundError("配置文件未找到: config.yaml")
		}
		return nil, errors.NewSystemError(errors.ErrCodeConfigLoad, "配置文件读取失败").WithCause(err)
	}

	// 解析配置文件
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, errors.NewSystemError(errors.ErrCodeConfigLoad, "配置文件解析失败").WithCause(err)
	}

	// 配置验证
	if err := config.Validate(); err != nil {
		return nil, err
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
	viper.SetDefault("tracing.enabled", true)
	viper.SetDefault("tracing.service_name", "go-project-layout")
	viper.SetDefault("tracing.service_version", "1.0.0")
	viper.SetDefault("tracing.environment", "development")
	viper.SetDefault("tracing.exporter_type", "jaeger")
	viper.SetDefault("tracing.endpoint", "http://localhost:14268/api/traces")
	viper.SetDefault("tracing.sample_ratio", 1.0)
}

// Validate 验证配置的有效性
func (c *Config) Validate() error {
	// 应用配置验证
	if err := c.validateApp(); err != nil {
		return err
	}

	// 数据库配置验证
	if err := c.validateDatabase(); err != nil {
		return err
	}

	// Redis 配置验证
	if err := c.validateRedis(); err != nil {
		return err
	}

	// JWT 配置验证
	if err := c.validateJWT(); err != nil {
		return err
	}

	// 日志配置验证
	if err := c.validateLog(); err != nil {
		return err
	}

	// CORS 配置验证
	if err := c.validateCORS(); err != nil {
		return err
	}

	// Metrics 配置验证
	if err := c.validateMetrics(); err != nil {
		return err
	}

	// Tracing 配置验证
	if err := c.validateTracing(); err != nil {
		return err
	}

	return nil
}

// validateApp 验证应用配置
func (c *Config) validateApp() error {
	if c.App.Name == "" {
		return errors.NewConfigValidationError("app.name", "应用名称不能为空")
	}

	if c.App.Env == "" {
		return errors.NewConfigValidationError("app.env", "环境配置不能为空")
	}

	validEnvs := []string{"dev", "development", "test", "staging", "prod", "production"}
	if !contains(validEnvs, c.App.Env) {
		return errors.NewConfigValidationError("app.env", "环境配置必须是 dev, test, staging, prod 之一")
	}

	if c.App.Port <= 0 || c.App.Port > 65535 {
		return errors.NewConfigValidationError("app.port", "端口号必须在 1-65535 范围内")
	}

	if c.App.Version == "" {
		return errors.NewConfigValidationError("app.version", "应用版本不能为空")
	}

	return nil
}

// validateDatabase 验证数据库配置
func (c *Config) validateDatabase() error {
	if c.Database.Host == "" {
		return errors.NewConfigValidationError("database.host", "数据库主机地址不能为空")
	}

	if c.Database.Port <= 0 || c.Database.Port > 65535 {
		return errors.NewConfigValidationError("database.port", "数据库端口号必须在 1-65535 范围内")
	}

	if c.Database.User == "" {
		return errors.NewConfigValidationError("database.user", "数据库用户名不能为空")
	}

	if c.Database.DBName == "" {
		return errors.NewConfigValidationError("database.db_name", "数据库名称不能为空")
	}

	validDrivers := []string{"mysql", "postgres", "sqlite"}
	if !contains(validDrivers, c.Database.Driver) {
		return errors.NewConfigValidationError("database.driver", "数据库驱动只支持 mysql, postgres, sqlite")
	}

	return nil
}

// validateRedis 验证 Redis 配置
func (c *Config) validateRedis() error {
	if c.Redis.Host == "" {
		return errors.NewConfigValidationError("redis.host", "Redis 主机地址不能为空")
	}

	if c.Redis.Port <= 0 || c.Redis.Port > 65535 {
		return errors.NewConfigValidationError("redis.port", "Redis 端口号必须在 1-65535 范围内")
	}

	if c.Redis.DB < 0 || c.Redis.DB > 15 {
		return errors.NewConfigValidationError("redis.db", "Redis 数据库索引必须在 0-15 范围内")
	}

	return nil
}

// validateJWT 验证 JWT 配置
func (c *Config) validateJWT() error {
	if c.JWT.Secret == "" {
		return errors.NewConfigValidationError("jwt.secret", "JWT 密钥不能为空")
	}

	if len(c.JWT.Secret) < 32 {
		return errors.NewConfigValidationError("jwt.secret", "JWT 密钥长度不能少于 32 位")
	}

	if c.JWT.ExpiresIn <= 0 {
		return errors.NewConfigValidationError("jwt.expires_in", "JWT 过期时间必须大于 0")
	}

	// 生产环境下检查是否使用默认密钥
	if c.App.IsProduction() && strings.Contains(c.JWT.Secret, "your-256-bit-secret") {
		return errors.NewConfigValidationError("jwt.secret", "生产环境不能使用默认 JWT 密钥")
	}

	return nil
}

// validateLog 验证日志配置
func (c *Config) validateLog() error {
	validLogLevels := []string{"debug", "info", "warn", "error", "fatal", "panic"}
	if !contains(validLogLevels, c.Log.Level) {
		return errors.NewConfigValidationError("log.level", "日志级别必须是 debug, info, warn, error, fatal, panic 之一")
	}

	validLogFormats := []string{"json", "text"}
	if !contains(validLogFormats, c.Log.Format) {
		return errors.NewConfigValidationError("log.format", "日志格式必须是 json 或 text")
	}

	if c.Log.MaxSize <= 0 {
		return errors.NewConfigValidationError("log.max_size", "日志文件最大大小必须大于 0")
	}

	if c.Log.MaxAge <= 0 {
		return errors.NewConfigValidationError("log.max_age", "日志文件保留天数必须大于 0")
	}

	if c.Log.MaxBackups < 0 {
		return errors.NewConfigValidationError("log.max_backups", "日志备份文件数量不能小于 0")
	}

	return nil
}

// validateCORS 验证 CORS 配置
func (c *Config) validateCORS() error {
	if len(c.CORS.AllowOrigins) == 0 {
		return errors.NewConfigValidationError("cors.allow_origins", "CORS 允许的源不能为空")
	}

	if len(c.CORS.AllowMethods) == 0 {
		return errors.NewConfigValidationError("cors.allow_methods", "CORS 允许的方法不能为空")
	}

	validMethods := []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"}
	for _, method := range c.CORS.AllowMethods {
		if !contains(validMethods, method) {
			return errors.NewConfigValidationError("cors.allow_methods", fmt.Sprintf("不支持的 HTTP 方法: %s", method))
		}
	}

	// 生产环境下检查是否使用通配符
	if c.App.IsProduction() {
		for _, origin := range c.CORS.AllowOrigins {
			if origin == "*" {
				return errors.NewConfigValidationError("cors.allow_origins", "生产环境不建议使用通配符 '*' 作为允许的源")
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
		return errors.NewConfigValidationError("metrics.port", "指标服务端口号必须在 1-65535 范围内")
	}

	if c.Metrics.Path == "" {
		return errors.NewConfigValidationError("metrics.path", "指标路径不能为空")
	}

	if c.Metrics.Namespace == "" {
		return errors.NewConfigValidationError("metrics.namespace", "指标命名空间不能为空")
	}

	return nil
}

// validateTracing 验证追踪配置
func (c *Config) validateTracing() error {
	if !c.Tracing.Enabled {
		return nil
	}

	if c.Tracing.ServiceName == "" {
		return errors.NewConfigValidationError("tracing.service_name", "服务名称不能为空")
	}

	if c.Tracing.ServiceVersion == "" {
		return errors.NewConfigValidationError("tracing.service_version", "服务版本不能为空")
	}

	validExporters := []string{"jaeger", "zipkin", "otlp"}
	if !contains(validExporters, c.Tracing.ExporterType) {
		return errors.NewConfigValidationError("tracing.exporter_type", "追踪导出器类型必须是 jaeger, zipkin, otlp 之一")
	}

	if c.Tracing.SampleRatio < 0 || c.Tracing.SampleRatio > 1 {
		return errors.NewConfigValidationError("tracing.sample_ratio", "采样比例必须在 0-1 范围内")
	}

	return nil
}
