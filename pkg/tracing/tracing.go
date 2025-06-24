// Package tracing 提供基于 OpenTelemetry 的分布式追踪功能
// 支持 Jaeger 导出器和多种采样策略，包含中间件、性能监控等生产级功能
package tracing

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Sakuya1998/go-project-layout/pkg/config"
	"github.com/Sakuya1998/go-project-layout/pkg/logger"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	trace2 "go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
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

	// Middleware 获取 Gin 中间件
	Middleware() gin.HandlerFunc

	// HTTPMiddleware 获取标准 HTTP 中间件
	HTTPMiddleware(next http.Handler) http.Handler

	// InstrumentHTTPClient 为 HTTP 客户端添加追踪
	InstrumentHTTPClient(client *http.Client) *http.Client

	// GetStats 获取追踪统计信息
	GetStats() TracingStats
}

// TracingStats 追踪统计信息
type TracingStats struct {
	SpansCreated   int64     `json:"spans_created"`
	SpansCompleted int64     `json:"spans_completed"`
	SpansErrored   int64     `json:"spans_errored"`
	LastActivity   time.Time `json:"last_activity"`
	ActiveSpans    int64     `json:"active_spans"`
	ExportErrors   int64     `json:"export_errors"`
}

// tracingManager 追踪管理器实现
type tracingManager struct {
	config   *config.TracingConfig
	tracer   trace2.Tracer
	provider *trace.TracerProvider
	stats    *TracingStats
	mu       sync.RWMutex
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

	m := &tracingManager{
		config:   cfg,
		tracer:   tracer,
		provider: provider,
		stats:    &TracingStats{},
	}

	// 启动统计信息收集
	go m.collectStats()

	return m, nil
}

// createExporter 创建导出器
// 注意：Jaeger 导出器已被弃用，推荐使用 OTLP 导出器
func createExporter(cfg *config.TracingConfig) (trace.SpanExporter, error) {
	switch cfg.ExporterType {
	case "otlp":
		return otlptracehttp.New(context.Background(),
			otlptracehttp.WithEndpoint(cfg.Endpoint),
			otlptracehttp.WithInsecure(), // 生产环境应该使用 TLS
		)
	case "console":
		// 控制台导出器，用于开发调试
		return &consoleExporter{}, nil
	default:
		return nil, fmt.Errorf("unsupported exporter type: %s (supported: otlp, console)", cfg.ExporterType)
	}
}

// createSampler 创建采样器
func createSampler(cfg *config.TracingConfig) trace.Sampler {
	// 根据配置的采样率创建采样器
	if cfg.SampleRatio <= 0 {
		return trace.NeverSample()
	} else if cfg.SampleRatio >= 1.0 {
		return trace.AlwaysSample()
	} else {
		return trace.TraceIDRatioBased(cfg.SampleRatio)
	}
}

// StartSpan 开始一个新的 span
func (t *tracingManager) StartSpan(ctx context.Context, name string, opts ...trace2.SpanStartOption) (context.Context, trace2.Span) {
	ctx, span := t.tracer.Start(ctx, name, opts...)

	// 更新统计信息
	t.mu.Lock()
	t.stats.SpansCreated++
	t.stats.ActiveSpans++
	t.stats.LastActivity = time.Now()
	t.mu.Unlock()

	// 包装 span 以便在结束时更新统计信息
	wrappedSpan := &instrumentedSpan{
		Span:    span,
		manager: t,
	}

	return ctx, wrappedSpan
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
func SetStatus(ctx context.Context, code codes.Code, description string) {
	span := trace2.SpanFromContext(ctx)
	span.SetStatus(code, description)
}

// RecordError 记录错误到当前 span
func RecordError(ctx context.Context, err error, opts ...trace2.EventOption) {
	span := trace2.SpanFromContext(ctx)
	span.RecordError(err, opts...)
}

// SetAttributes 设置当前 span 的属性
func SetAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	span := trace2.SpanFromContext(ctx)
	span.SetAttributes(attrs...)
}

// instrumentedSpan 包装的 span，用于统计信息收集
type instrumentedSpan struct {
	trace2.Span
	manager *tracingManager
}

func (s *instrumentedSpan) End(options ...trace2.SpanEndOption) {
	s.Span.End(options...)

	// 更新统计信息
	s.manager.mu.Lock()
	s.manager.stats.SpansCompleted++
	s.manager.stats.ActiveSpans--
	if s.Span.SpanContext().IsSampled() {
		if status := s.Span.(interface{ Status() (codes.Code, string) }); status != nil {
			if code, _ := status.Status(); code == codes.Error {
				s.manager.stats.SpansErrored++
			}
		}
	}
	s.manager.mu.Unlock()
}

// collectStats 收集统计信息
func (t *tracingManager) collectStats() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		t.mu.RLock()
		stats := *t.stats
		t.mu.RUnlock()

		logger.Debug("追踪统计信息",
			zap.Int64("spans_created", stats.SpansCreated),
			zap.Int64("spans_completed", stats.SpansCompleted),
			zap.Int64("spans_errored", stats.SpansErrored),
			zap.Int64("active_spans", stats.ActiveSpans),
			zap.Int64("export_errors", stats.ExportErrors),
		)
	}
}

// GetStats 获取追踪统计信息
func (t *tracingManager) GetStats() TracingStats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return *t.stats
}

// Middleware 获取 Gin 中间件
func (t *tracingManager) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从请求头中提取追踪上下文
		ctx := otel.GetTextMapPropagator().Extract(c.Request.Context(), propagation.HeaderCarrier(c.Request.Header))

		// 创建 span
		spanName := fmt.Sprintf("%s %s", c.Request.Method, c.FullPath())
		ctx, span := t.StartSpan(ctx, spanName,
			trace2.WithSpanKind(trace2.SpanKindServer),
			trace2.WithAttributes(
				semconv.HTTPMethod(c.Request.Method),
				semconv.HTTPTarget(c.Request.URL.Path),
				semconv.HTTPScheme(c.Request.URL.Scheme),
				semconv.NetHostName(c.Request.Host),
				semconv.HTTPUserAgent(c.Request.UserAgent()),
				semconv.HTTPClientIP(c.ClientIP()),
				attribute.String("request_id", c.GetString("request_id")),
			),
		)
		defer span.End()

		// 将上下文传递给请求
		c.Request = c.Request.WithContext(ctx)

		// 处理请求
		c.Next()

		// 设置响应状态
		status := c.Writer.Status()
		span.SetAttributes(
			semconv.HTTPStatusCode(status),
			semconv.HTTPResponseContentLengthKey.Int64(int64(c.Writer.Size())),
		)

		// 设置 span 状态
		if status >= 400 {
			span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", status))
			if len(c.Errors) > 0 {
				span.RecordError(c.Errors.Last())
			}
		} else {
			span.SetStatus(codes.Ok, "")
		}

		// 将追踪 ID 添加到响应头
		if span.SpanContext().HasTraceID() {
			c.Header("X-Trace-ID", span.SpanContext().TraceID().String())
		}
	}
}

// HTTPMiddleware 获取标准 HTTP 中间件
func (t *tracingManager) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 从请求头中提取追踪上下文
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))

		// 创建 span
		spanName := fmt.Sprintf("%s %s", r.Method, r.URL.Path)
		ctx, span := t.StartSpan(ctx, spanName,
			trace2.WithSpanKind(trace2.SpanKindServer),
			trace2.WithAttributes(
				semconv.HTTPMethod(r.Method),
				semconv.HTTPTarget(r.URL.Path),
				semconv.HTTPScheme(r.URL.Scheme),
				semconv.NetHostName(r.Host),
				semconv.HTTPUserAgent(r.UserAgent()),
			),
		)
		defer span.End()

		// 包装响应写入器以捕获状态码
		wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}

		// 将追踪 ID 添加到响应头
		if span.SpanContext().HasTraceID() {
			w.Header().Set("X-Trace-ID", span.SpanContext().TraceID().String())
		}

		// 处理请求
		next.ServeHTTP(wrapped, r.WithContext(ctx))

		// 设置响应状态
		span.SetAttributes(
			semconv.HTTPStatusCode(wrapped.statusCode),
		)

		// 设置 span 状态
		if wrapped.statusCode >= 400 {
			span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", wrapped.statusCode))
		} else {
			span.SetStatus(codes.Ok, "")
		}
	})
}

// responseWriter 包装 http.ResponseWriter 以捕获状态码
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// InstrumentHTTPClient 为 HTTP 客户端添加追踪
func (t *tracingManager) InstrumentHTTPClient(client *http.Client) *http.Client {
	originalTransport := client.Transport
	if originalTransport == nil {
		originalTransport = http.DefaultTransport
	}

	client.Transport = &tracingTransport{
		base:   originalTransport,
		tracer: t.tracer,
	}

	return client
}

// tracingTransport HTTP 传输层追踪包装器
type tracingTransport struct {
	base   http.RoundTripper
	tracer trace2.Tracer
}

func (t *tracingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// 创建客户端 span
	spanName := fmt.Sprintf("%s %s", req.Method, req.URL.Host)
	ctx, span := t.tracer.Start(req.Context(), spanName,
		trace2.WithSpanKind(trace2.SpanKindClient),
		trace2.WithAttributes(
			semconv.HTTPMethod(req.Method),
			semconv.HTTPTarget(req.URL.Path),
			semconv.HTTPScheme(req.URL.Scheme),
			semconv.NetHostName(req.URL.Host),
		),
	)
	defer span.End()

	// 注入追踪上下文到请求头
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	// 执行请求
	resp, err := t.base.RoundTrip(req.WithContext(ctx))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return resp, err
	}

	// 设置响应属性
	span.SetAttributes(
		semconv.HTTPStatusCode(resp.StatusCode),
	)

	// 设置状态
	if resp.StatusCode >= 400 {
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", resp.StatusCode))
	} else {
		span.SetStatus(codes.Ok, "")
	}

	return resp, nil
}

// consoleExporter 控制台导出器，用于开发调试
type consoleExporter struct{}

func (e *consoleExporter) ExportSpans(ctx context.Context, spans []trace.ReadOnlySpan) error {
	for _, span := range spans {
		logger.Debug("追踪 Span",
			zap.String("trace_id", span.SpanContext().TraceID().String()),
			zap.String("span_id", span.SpanContext().SpanID().String()),
			zap.String("name", span.Name()),
			zap.String("kind", span.SpanKind().String()),
			zap.Time("start_time", span.StartTime()),
			zap.Time("end_time", span.EndTime()),
			zap.Duration("duration", span.EndTime().Sub(span.StartTime())),
			zap.Any("attributes", span.Attributes()),
		)
	}
	return nil
}

func (e *consoleExporter) Shutdown(ctx context.Context) error {
	return nil
}

// 为 noopTracer 添加新方法的空实现
func (n *noopTracer) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}

func (n *noopTracer) HTTPMiddleware(next http.Handler) http.Handler {
	return next
}

func (n *noopTracer) InstrumentHTTPClient(client *http.Client) *http.Client {
	return client
}

func (n *noopTracer) GetStats() TracingStats {
	return TracingStats{}
}

// 高级追踪工具函数

// TraceFunction 追踪函数执行
func TraceFunction(ctx context.Context, name string, fn func(context.Context) error) error {
	ctx, span := StartSpan(ctx, name)
	defer span.End()

	err := fn(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	return err
}

// TraceAsyncFunction 追踪异步函数执行
func TraceAsyncFunction(ctx context.Context, name string, fn func(context.Context)) {
	ctx, span := StartSpan(ctx, name)

	go func() {
		defer span.End()
		defer func() {
			if r := recover(); r != nil {
				span.RecordError(fmt.Errorf("panic: %v", r))
				span.SetStatus(codes.Error, "panic occurred")
			}
		}()

		fn(ctx)
	}()
}

// AddCustomAttributes 添加自定义属性到当前 span
func AddCustomAttributes(ctx context.Context, attrs map[string]interface{}) {
	span := trace2.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}

	var otelAttrs []attribute.KeyValue
	for k, v := range attrs {
		switch val := v.(type) {
		case string:
			otelAttrs = append(otelAttrs, attribute.String(k, val))
		case int:
			otelAttrs = append(otelAttrs, attribute.Int(k, val))
		case int64:
			otelAttrs = append(otelAttrs, attribute.Int64(k, val))
		case float64:
			otelAttrs = append(otelAttrs, attribute.Float64(k, val))
		case bool:
			otelAttrs = append(otelAttrs, attribute.Bool(k, val))
		default:
			otelAttrs = append(otelAttrs, attribute.String(k, fmt.Sprintf("%v", val)))
		}
	}

	span.SetAttributes(otelAttrs...)
}

// GetTraceID 获取当前追踪 ID
func GetTraceID(ctx context.Context) string {
	span := trace2.SpanFromContext(ctx)
	if span.SpanContext().HasTraceID() {
		return span.SpanContext().TraceID().String()
	}
	return ""
}

// GetSpanID 获取当前 Span ID
func GetSpanID(ctx context.Context) string {
	span := trace2.SpanFromContext(ctx)
	if span.SpanContext().HasSpanID() {
		return span.SpanContext().SpanID().String()
	}
	return ""
}
