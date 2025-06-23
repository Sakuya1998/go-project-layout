// Package logger 提供结构化日志功能
// 基于zap实现高性能日志记录
package logger

import (
	"context"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/your-org/your-project/pkg/config"
)

// Logger 日志接口
type Logger interface {
	Debug(msg string, fields ...zap.Field)
	Info(msg string, fields ...zap.Field)
	Warn(msg string, fields ...zap.Field)
	Error(msg string, fields ...zap.Field)
	Fatal(msg string, fields ...zap.Field)
	With(fields ...zap.Field) Logger
	Sync() error
}

// zapLogger zap日志实现
type zapLogger struct {
	zap *zap.Logger
}

// New 创建新的日志实例
func New(cfg *config.LoggerConfig) (Logger, error) {
	if !cfg.Enabled {
		return &noopLogger{}, nil
	}

	// 配置日志级别
	level := zapcore.InfoLevel
	switch cfg.Level {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	case "fatal":
		level = zapcore.FatalLevel
	}

	// 配置编码器
	var encoderConfig zapcore.EncoderConfig
	if cfg.Format == "json" {
		encoderConfig = zap.NewProductionEncoderConfig()
	} else {
		encoderConfig = zap.NewDevelopmentEncoderConfig()
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	// 配置输出
	var encoder zapcore.Encoder
	if cfg.Format == "json" {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	// 配置输出目标
	var writeSyncer zapcore.WriteSyncer
	if cfg.Output == "stdout" {
		writeSyncer = zapcore.AddSync(os.Stdout)
	} else if cfg.Output == "stderr" {
		writeSyncer = zapcore.AddSync(os.Stderr)
	} else {
		// 文件输出
		file, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, err
		}
		writeSyncer = zapcore.AddSync(file)
	}

	// 创建核心
	core := zapcore.NewCore(encoder, writeSyncer, level)

	// 创建logger
	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	return &zapLogger{zap: logger}, nil
}

// Debug 记录调试日志
func (l *zapLogger) Debug(msg string, fields ...zap.Field) {
	l.zap.Debug(msg, fields...)
}

// Info 记录信息日志
func (l *zapLogger) Info(msg string, fields ...zap.Field) {
	l.zap.Info(msg, fields...)
}

// Warn 记录警告日志
func (l *zapLogger) Warn(msg string, fields ...zap.Field) {
	l.zap.Warn(msg, fields...)
}

// Error 记录错误日志
func (l *zapLogger) Error(msg string, fields ...zap.Field) {
	l.zap.Error(msg, fields...)
}

// Fatal 记录致命错误日志
func (l *zapLogger) Fatal(msg string, fields ...zap.Field) {
	l.zap.Fatal(msg, fields...)
}

// With 添加字段
func (l *zapLogger) With(fields ...zap.Field) Logger {
	return &zapLogger{zap: l.zap.With(fields...)}
}

// Sync 同步日志
func (l *zapLogger) Sync() error {
	return l.zap.Sync()
}

// noopLogger 空操作日志实现
type noopLogger struct{}

func (n *noopLogger) Debug(msg string, fields ...zap.Field) {}
func (n *noopLogger) Info(msg string, fields ...zap.Field)  {}
func (n *noopLogger) Warn(msg string, fields ...zap.Field)  {}
func (n *noopLogger) Error(msg string, fields ...zap.Field) {}
func (n *noopLogger) Fatal(msg string, fields ...zap.Field) {}
func (n *noopLogger) With(fields ...zap.Field) Logger       { return n }
func (n *noopLogger) Sync() error                          { return nil }

// 全局日志实例
var globalLogger Logger

// Init 初始化全局日志
func Init(cfg *config.LoggerConfig) error {
	logger, err := New(cfg)
	if err != nil {
		return err
	}
	globalLogger = logger
	return nil
}

// GetGlobal 获取全局日志实例
func GetGlobal() Logger {
	if globalLogger == nil {
		// 返回默认的noop logger
		return &noopLogger{}
	}
	return globalLogger
}

// 便捷方法

// Debug 记录调试日志
func Debug(msg string, fields ...zap.Field) {
	GetGlobal().Debug(msg, fields...)
}

// Info 记录信息日志
func Info(msg string, fields ...zap.Field) {
	GetGlobal().Info(msg, fields...)
}

// Warn 记录警告日志
func Warn(msg string, fields ...zap.Field) {
	GetGlobal().Warn(msg, fields...)
}

// Error 记录错误日志
func Error(msg string, fields ...zap.Field) {
	GetGlobal().Error(msg, fields...)
}

// Fatal 记录致命错误日志
func Fatal(msg string, fields ...zap.Field) {
	GetGlobal().Fatal(msg, fields...)
}

// With 添加字段
func With(fields ...zap.Field) Logger {
	return GetGlobal().With(fields...)
}

// Sync 同步日志
func Sync() error {
	return GetGlobal().Sync()
}

// 上下文相关的便捷方法

type contextKey string

const (
	requestIDKey contextKey = "request_id"
	userIDKey    contextKey = "user_id"
)

// WithRequestID 添加请求ID到上下文
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// WithUserID 添加用户ID到上下文
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// FromContext 从上下文获取日志字段
func FromContext(ctx context.Context) []zap.Field {
	var fields []zap.Field

	if requestID, ok := ctx.Value(requestIDKey).(string); ok {
		fields = append(fields, zap.String("request_id", requestID))
	}

	if userID, ok := ctx.Value(userIDKey).(string); ok {
		fields = append(fields, zap.String("user_id", userID))
	}

	return fields
}

// DebugContext 带上下文的调试日志
func DebugContext(ctx context.Context, msg string, fields ...zap.Field) {
	fields = append(fields, FromContext(ctx)...)
	GetGlobal().Debug(msg, fields...)
}

// InfoContext 带上下文的信息日志
func InfoContext(ctx context.Context, msg string, fields ...zap.Field) {
	fields = append(fields, FromContext(ctx)...)
	GetGlobal().Info(msg, fields...)
}

// WarnContext 带上下文的警告日志
func WarnContext(ctx context.Context, msg string, fields ...zap.Field) {
	fields = append(fields, FromContext(ctx)...)
	GetGlobal().Warn(msg, fields...)
}

// ErrorContext 带上下文的错误日志
func ErrorContext(ctx context.Context, msg string, fields ...zap.Field) {
	fields = append(fields, FromContext(ctx)...)
	GetGlobal().Error(msg, fields...)
}

// FatalContext 带上下文的致命错误日志
func FatalContext(ctx context.Context, msg string, fields ...zap.Field) {
	fields = append(fields, FromContext(ctx)...)
	GetGlobal().Fatal(msg, fields...)
}
