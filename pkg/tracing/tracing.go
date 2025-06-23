// Package tracing 提供基于 OpenTelemetry 的分布式追踪功能
// 支持 Jaeger 导出器和多种采样策略
package tracing

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Sakuya1998/go-project-layout/pkg/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/semconv/v1.17.0"
	trace2 "go.opentelemetry.io/otel/trace"
)

// Tracer 追踪器接口
type Tracer interface {
	// StartSpan 开始一个新的 span
	StartSpan(ctx context.Context, name string, opts ...trace2.SpanStartOption) (context.Context, trace2.Span)

	// GetTracer 获取原始追踪器
	GetTracer() trace2.Tracer

	// Shutdown 关闭追踪器
	Shutdown(ctx context.Context) error

	// HealthCheck 健康检查
	HealthCheck() error
}

// tracingManager 追踪管理器实现
type tracingManager struct {
	config   *config.TracingConfig
	tracer   trace2.Tracer
	provider *trace.TracerProvider
}

// New 创建新的追踪管理器
func New(cfg *config.TracingConfig) (Tracer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("tracing config cannot be nil")
	}

	if !cfg.Enabled {
		return &noopTracer{}, nil
	}

	// 创建资源
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
			semconv.DeploymentEnvironment(cfg.Environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// 创建导出器
	exporter, err := createExporter(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create exporter: %w", err)
	}

	// 创建采样器
	sampler := createSampler(cfg)

	// 创建追踪提供者
	provider := trace.NewTracerProvider(
		trace.WithBatcher(exporter),
		trace.WithResource(res),
		trace.WithSampler(sampler),
	)

	// 设置全局追踪提供者
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// 创建追踪器
	tracer := provider.Tracer(cfg.ServiceName)

	return &tracingManager{
		config:   cfg,
		tracer:   tracer,
		provider: provider,
	}, nil
}

// createExporter 创建导出器
func createExporter(cfg *config.TracingConfig) (trace.SpanExporter, error) {
	switch cfg.Exporter.Type {
	case "jaeger":
		return jaeger.New(jaeger.WithCollectorEndpoint(
			jaeger.WithEndpoint(cfg.Exporter.Endpoint),
		))
	default:
		return nil, fmt.Errorf("unsupported exporter type: %s", cfg.Exporter.Type)
	}
}

// createSampler 创建采样器
func createSampler(cfg *config.TracingConfig) trace.Sampler {
	switch cfg.Sampler.Type {
	case "always":
		return trace.AlwaysSample()
	case "never":
		return trace.NeverSample()
	case "ratio":
		return trace.TraceIDRatioBased(cfg.Sampler.Ratio)
	default:
		return trace.TraceIDRatioBased(0.1) // 默认 10% 采样
	}
}

// StartSpan 开始一个新的 span
func (t *tracingManager) StartSpan(ctx context.Context, name string, opts ...trace2.SpanStartOption) (context.Context, trace2.Span) {
	return t.tracer.Start(ctx, name, opts...)
}

// GetTracer 获取原始追踪器
func (t *tracingManager) GetTracer() trace2.Tracer {
	return t.tracer
}

// Shutdown 关闭追踪器
func (t *tracingManager) Shutdown(ctx context.Context) error {
	if t.provider == nil {
		return nil
	}

	// 设置超时
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return t.provider.Shutdown(ctx)
}

// HealthCheck 健康检查
func (t *tracingManager) HealthCheck() error {
	if t.provider == nil {
		return fmt.Errorf("tracer provider is nil")
	}
	return nil
}

// noopTracer 空操作追踪器实现（当追踪被禁用时使用）
type noopTracer struct{}

func (n *noopTracer) StartSpan(ctx context.Context, name string, opts ...trace2.SpanStartOption) (context.Context, trace2.Span) {
	return ctx, trace2.SpanFromContext(ctx)
}

func (n *noopTracer) GetTracer() trace2.Tracer {
	return otel.Tracer("noop")
}

func (n *noopTracer) Shutdown(ctx context.Context) error {
	return nil
}

func (n *noopTracer) HealthCheck() error {
	return nil
}

// 全局追踪管理器
var (
	globalTracer Tracer
	once         sync.Once
)

// Init 初始化全局追踪管理器
func Init(cfg *config.TracingConfig) error {
	var err error
	once.Do(func() {
		globalTracer, err = New(cfg)
	})
	return err
}

// GetGlobal 获取全局追踪管理器
func GetGlobal() Tracer {
	if globalTracer == nil {
		return &noopTracer{}
	}
	return globalTracer
}

// 便捷方法
func StartSpan(ctx context.Context, name string, opts ...trace2.SpanStartOption) (context.Context, trace2.Span) {
	return GetGlobal().StartSpan(ctx, name, opts...)
}

func GetTracer() trace2.Tracer {
	return GetGlobal().GetTracer()
}

// SpanFromContext 从上下文中获取 span
func SpanFromContext(ctx context.Context) trace2.Span {
	return trace2.SpanFromContext(ctx)
}

// ContextWithSpan 将 span 添加到上下文中
func ContextWithSpan(ctx context.Context, span trace2.Span) context.Context {
	return trace2.ContextWithSpan(ctx, span)
}

// AddEvent 向当前 span 添加事件
func AddEvent(ctx context.Context, name string, attrs ...trace2.EventOption) {
	span := trace2.SpanFromContext(ctx)
	span.AddEvent(name, attrs...)
}

// SetStatus 设置当前 span 的状态
func SetStatus(ctx context.Context, code trace2.StatusCode, description string) {
	span := trace2.SpanFromContext(ctx)
	span.SetStatus(code, description)
}

// RecordError 记录错误到当前 span
func RecordError(ctx context.Context, err error, opts ...trace2.EventOption) {
	span := trace2.SpanFromContext(ctx)
	span.RecordError(err, opts...)
}

// SetAttributes 设置当前 span 的属性
func SetAttributes(ctx context.Context, attrs ...trace2.KeyValue) {
	span := trace2.SpanFromContext(ctx)
	span.SetAttributes(attrs...)
}