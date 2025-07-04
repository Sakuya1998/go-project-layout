// Package metrics 提供基于 Prometheus 的指标收集功能
// 支持计数器、直方图、仪表盘等多种指标类型
package metrics

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Sakuya1998/go-project-layout/pkg/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// SLIMetrics SLI指标定义
type SLIMetrics struct {
	AvailabilityTarget float64       // 可用性目标 99.9%
	LatencyTarget      time.Duration // 延迟目标 P99 < 100ms
	ErrorRateTarget    float64       // 错误率目标 < 0.1%
	ThroughputTarget   float64       // 吞吐量目标 RPS
}

// AlertRule 告警规则
type AlertRule struct {
	Name        string            `json:"name"`
	Expr        string            `json:"expr"`
	For         string            `json:"for"`
	Severity    string            `json:"severity"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

// Metrics 指标管理器接口
type Metrics interface {
	// Counter 计数器相关方法
	IncCounter(name string, labels ...string)
	AddCounter(name string, value float64, labels ...string)

	// Histogram 直方图相关方法
	ObserveHistogram(name string, value float64, labels ...string)

	// Gauge 仪表盘相关方法
	SetGauge(name string, value float64, labels ...string)
	IncGauge(name string, labels ...string)
	DecGauge(name string, labels ...string)

	// HTTP 指标
	RecordHTTPRequest(method, path, status string, duration time.Duration)

	// 业务指标
	RecordDatabaseOperation(operation, table string, duration time.Duration, success bool)
	RecordCacheOperation(operation string, hit bool, duration time.Duration)
	RecordBusinessMetric(metric string, value float64, labels map[string]string)

	// SLI/SLO 相关
	RecordSLI(sliType string, value float64, labels map[string]string)
	GetSLIMetrics() *SLIMetrics
	GenerateAlertRules() []AlertRule

	// 服务器
	StartServer(ctx context.Context) error
	GetHandler() http.Handler

	// 健康检查
	HealthCheck() error
}

// prometheusMetrics Prometheus 指标实现
type prometheusMetrics struct {
	config   *config.MetricsConfig
	registry *prometheus.Registry
	mu       sync.RWMutex

	// 指标缓存
	counters   map[string]*prometheus.CounterVec
	histograms map[string]*prometheus.HistogramVec
	gauges     map[string]*prometheus.GaugeVec

	// 预定义指标
	httpRequestsTotal   *prometheus.CounterVec
	httpRequestDuration *prometheus.HistogramVec
	dbOperationsTotal   *prometheus.CounterVec
	dbOperationDuration *prometheus.HistogramVec
	cacheOperationsTotal *prometheus.CounterVec
	cacheOperationDuration *prometheus.HistogramVec

	// SLI指标
	sliMetrics *SLIMetrics
	businessMetrics map[string]*prometheus.GaugeVec
	sliCounters map[string]*prometheus.CounterVec

	server *http.Server
}

// New 创建新的指标管理器
func New(cfg *config.MetricsConfig) (Metrics, error) {
	if cfg == nil {
		return nil, fmt.Errorf("metrics config cannot be nil")
	}

	if !cfg.Enabled {
		return &noopMetrics{}, nil
	}

	registry := prometheus.NewRegistry()

	m := &prometheusMetrics{
		config:     cfg,
		registry:   registry,
		counters:   make(map[string]*prometheus.CounterVec),
		histograms: make(map[string]*prometheus.HistogramVec),
		gauges:     make(map[string]*prometheus.GaugeVec),
		sliMetrics: &SLIMetrics{
			AvailabilityTarget: 0.999,
			LatencyTarget:      100 * time.Millisecond,
			ErrorRateTarget:    0.001,
			ThroughputTarget:   1000,
		},
		businessMetrics: make(map[string]*prometheus.GaugeVec),
		sliCounters:     make(map[string]*prometheus.CounterVec),
	}

	// 注册默认指标收集器
	if cfg.EnableGoMetrics {
		registry.MustRegister(prometheus.NewGoCollector())
	}

	if cfg.EnableProcessMetrics {
		registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	}

	// 初始化预定义指标
	if err := m.initPredefinedMetrics(); err != nil {
		return nil, fmt.Errorf("failed to initialize predefined metrics: %w", err)
	}

	return m, nil
}

// initPredefinedMetrics 初始化预定义指标
func (m *prometheusMetrics) initPredefinedMetrics() error {
	// HTTP 请求指标
	m.httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Name:      "http_requests_total",
			Help:      "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	m.httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: m.config.Namespace,
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request duration in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	// 数据库操作指标
	m.dbOperationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Name:      "database_operations_total",
			Help:      "Total number of database operations",
		},
		[]string{"operation", "table", "success"},
	)

	m.dbOperationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: m.config.Namespace,
			Name:      "database_operation_duration_seconds",
			Help:      "Database operation duration in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"operation", "table"},
	)

	// 缓存操作指标
	m.cacheOperationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Name:      "cache_operations_total",
			Help:      "Total number of cache operations",
		},
		[]string{"operation", "hit"},
	)

	m.cacheOperationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: m.config.Namespace,
			Name:      "cache_operation_duration_seconds",
			Help:      "Cache operation duration in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"operation"},
	)

	// 注册所有预定义指标
	m.registry.MustRegister(
		m.httpRequestsTotal,
		m.httpRequestDuration,
		m.dbOperationsTotal,
		m.dbOperationDuration,
		m.cacheOperationsTotal,
		m.cacheOperationDuration,
	)

	return nil
}

// IncCounter 增加计数器
func (m *prometheusMetrics) IncCounter(name string, labels ...string) {
	m.AddCounter(name, 1, labels...)
}

// AddCounter 添加计数器值
func (m *prometheusMetrics) AddCounter(name string, value float64, labels ...string) {
	counter := m.getOrCreateCounter(name, labels)
	counter.Add(value)
}

// ObserveHistogram 观察直方图值
func (m *prometheusMetrics) ObserveHistogram(name string, value float64, labels ...string) {
	histogram := m.getOrCreateHistogram(name, labels)
	histogram.Observe(value)
}

// SetGauge 设置仪表盘值
func (m *prometheusMetrics) SetGauge(name string, value float64, labels ...string) {
	gauge := m.getOrCreateGauge(name, labels)
	gauge.Set(value)
}

// IncGauge 增加仪表盘值
func (m *prometheusMetrics) IncGauge(name string, labels ...string) {
	gauge := m.getOrCreateGauge(name, labels)
	gauge.Inc()
}

// DecGauge 减少仪表盘值
func (m *prometheusMetrics) DecGauge(name string, labels ...string) {
	gauge := m.getOrCreateGauge(name, labels)
	gauge.Dec()
}

// RecordHTTPRequest 记录HTTP请求指标
func (m *prometheusMetrics) RecordHTTPRequest(method, path, status string, duration time.Duration) {
	m.httpRequestsTotal.WithLabelValues(method, path, status).Inc()
	m.httpRequestDuration.WithLabelValues(method, path).Observe(duration.Seconds())
}

// RecordDatabaseOperation 记录数据库操作指标
func (m *prometheusMetrics) RecordDatabaseOperation(operation, table string, duration time.Duration, success bool) {
	successStr := "false"
	if success {
		successStr = "true"
	}
	m.dbOperationsTotal.WithLabelValues(operation, table, successStr).Inc()
	m.dbOperationDuration.WithLabelValues(operation, table).Observe(duration.Seconds())
}

// RecordCacheOperation 记录缓存操作指标
func (m *prometheusMetrics) RecordCacheOperation(operation string, hit bool, duration time.Duration) {
	hitStr := "false"
	if hit {
		hitStr = "true"
	}
	m.cacheOperationsTotal.WithLabelValues(operation, hitStr).Inc()
	m.cacheOperationDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// RecordBusinessMetric 记录业务指标
func (m *prometheusMetrics) RecordBusinessMetric(metric string, value float64, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if gauge, exists := m.businessMetrics[metric]; exists {
		labelValues := make([]string, 0, len(labels))
		for _, v := range labels {
			labelValues = append(labelValues, v)
		}
		gauge.WithLabelValues(labelValues...).Set(value)
		return
	}
	
	// 创建新的业务指标
	labelNames := make([]string, 0, len(labels))
	for k := range labels {
		labelNames = append(labelNames, k)
	}
	
	gauge := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: m.config.Namespace,
			Name:      fmt.Sprintf("business_%s", metric),
			Help:      fmt.Sprintf("Business metric for %s", metric),
		},
		labelNames,
	)
	
	m.registry.MustRegister(gauge)
	m.businessMetrics[metric] = gauge
	
	labelValues := make([]string, 0, len(labels))
	for _, v := range labels {
		labelValues = append(labelValues, v)
	}
	gauge.WithLabelValues(labelValues...).Set(value)
}

// RecordSLI 记录SLI指标
func (m *prometheusMetrics) RecordSLI(sliType string, value float64, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	key := fmt.Sprintf("sli_%s", sliType)
	if counter, exists := m.sliCounters[key]; exists {
		labelValues := make([]string, 0, len(labels))
		for _, v := range labels {
			labelValues = append(labelValues, v)
		}
		counter.WithLabelValues(labelValues...).Add(value)
		return
	}
	
	// 创建新的SLI计数器
	labelNames := make([]string, 0, len(labels))
	for k := range labels {
		labelNames = append(labelNames, k)
	}
	
	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Name:      key,
			Help:      fmt.Sprintf("SLI metric for %s", sliType),
		},
		labelNames,
	)
	
	m.registry.MustRegister(counter)
	m.sliCounters[key] = counter
	
	labelValues := make([]string, 0, len(labels))
	for _, v := range labels {
		labelValues = append(labelValues, v)
	}
	counter.WithLabelValues(labelValues...).Add(value)
}

// GetSLIMetrics 获取SLI指标配置
func (m *prometheusMetrics) GetSLIMetrics() *SLIMetrics {
	return m.sliMetrics
}

// GenerateAlertRules 生成告警规则
func (m *prometheusMetrics) GenerateAlertRules() []AlertRule {
	rules := []AlertRule{
		{
			Name:     "HighErrorRate",
			Expr:     fmt.Sprintf("rate(%s_http_requests_total{status=~\"5..\"}[5m]) > %f", m.config.Namespace, m.sliMetrics.ErrorRateTarget),
			For:      "2m",
			Severity: "critical",
			Labels: map[string]string{
				"service": m.config.Namespace,
			},
			Annotations: map[string]string{
				"summary":     "应用错误率过高",
				"description": "错误率超过SLO目标",
			},
		},
		{
			Name:     "HighLatency",
			Expr:     fmt.Sprintf("histogram_quantile(0.99, rate(%s_http_request_duration_seconds_bucket[5m])) > %f", m.config.Namespace, m.sliMetrics.LatencyTarget.Seconds()),
			For:      "5m",
			Severity: "warning",
			Labels: map[string]string{
				"service": m.config.Namespace,
			},
			Annotations: map[string]string{
				"summary":     "应用延迟过高",
				"description": "P99延迟超过SLO目标",
			},
		},
		{
			Name:     "LowAvailability",
			Expr:     fmt.Sprintf("(1 - rate(%s_http_requests_total{status=~\"5..\"}[5m]) / rate(%s_http_requests_total[5m])) < %f", m.config.Namespace, m.config.Namespace, m.sliMetrics.AvailabilityTarget),
			For:      "5m",
			Severity: "critical",
			Labels: map[string]string{
				"service": m.config.Namespace,
			},
			Annotations: map[string]string{
				"summary":     "应用可用性过低",
				"description": "可用性低于SLO目标",
			},
		},
	}
	
	return rules
}

// StartServer 启动指标服务器
func (m *prometheusMetrics) StartServer(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle(m.config.Path, promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))

	m.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", m.config.Port),
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		m.server.Shutdown(context.Background())
	}()

	return m.server.ListenAndServe()
}

// GetHandler 获取HTTP处理器
func (m *prometheusMetrics) GetHandler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// HealthCheck 健康检查
func (m *prometheusMetrics) HealthCheck() error {
	return nil
}

// 辅助方法
func (m *prometheusMetrics) getOrCreateCounter(name string, labelNames []string) prometheus.Counter {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := name
	if counter, exists := m.counters[key]; exists {
		return counter.WithLabelValues(labelNames...)
	}

	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Name:      name,
			Help:      fmt.Sprintf("Counter for %s", name),
		},
		[]string{"label"},
	)

	m.registry.MustRegister(counter)
	m.counters[key] = counter
	return counter.WithLabelValues(labelNames...)
}

func (m *prometheusMetrics) getOrCreateHistogram(name string, labelNames []string) prometheus.Observer {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := name
	if histogram, exists := m.histograms[key]; exists {
		return histogram.WithLabelValues(labelNames...)
	}

	histogram := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: m.config.Namespace,
			Name:      name,
			Help:      fmt.Sprintf("Histogram for %s", name),
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"label"},
	)

	m.registry.MustRegister(histogram)
	m.histograms[key] = histogram
	return histogram.WithLabelValues(labelNames...)
}

func (m *prometheusMetrics) getOrCreateGauge(name string, labelNames []string) prometheus.Gauge {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := name
	if gauge, exists := m.gauges[key]; exists {
		return gauge.WithLabelValues(labelNames...)
	}

	gauge := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: m.config.Namespace,
			Name:      name,
			Help:      fmt.Sprintf("Gauge for %s", name),
		},
		[]string{"label"},
	)

	m.registry.MustRegister(gauge)
	m.gauges[key] = gauge
	return gauge.WithLabelValues(labelNames...)
}

// noopMetrics 空操作指标实现（当指标被禁用时使用）
type noopMetrics struct{}

func (n *noopMetrics) IncCounter(name string, labels ...string)                                        {}
func (n *noopMetrics) AddCounter(name string, value float64, labels ...string)                        {}
func (n *noopMetrics) ObserveHistogram(name string, value float64, labels ...string)                  {}
func (n *noopMetrics) SetGauge(name string, value float64, labels ...string)                          {}
func (n *noopMetrics) IncGauge(name string, labels ...string)                                         {}
func (n *noopMetrics) DecGauge(name string, labels ...string)                                         {}
func (n *noopMetrics) RecordHTTPRequest(method, path, status string, duration time.Duration)          {}
func (n *noopMetrics) RecordDatabaseOperation(operation, table string, duration time.Duration, success bool) {}
func (n *noopMetrics) RecordCacheOperation(operation string, hit bool, duration time.Duration)       {}
func (n *noopMetrics) RecordBusinessMetric(metric string, value float64, labels map[string]string)   {}
func (n *noopMetrics) RecordSLI(sliType string, value float64, labels map[string]string)             {}
func (n *noopMetrics) GetSLIMetrics() *SLIMetrics                                                     { return &SLIMetrics{} }
func (n *noopMetrics) GenerateAlertRules() []AlertRule                                                { return []AlertRule{} }
func (n *noopMetrics) StartServer(ctx context.Context) error                                          { return nil }
func (n *noopMetrics) GetHandler() http.Handler                                                       { return http.NotFoundHandler() }
func (n *noopMetrics) HealthCheck() error                                                             { return nil }

// 全局指标管理器
var (
	globalMetrics Metrics
	once          sync.Once
)

// Init 初始化全局指标管理器
func Init(cfg *config.MetricsConfig) error {
	var err error
	once.Do(func() {
		globalMetrics, err = New(cfg)
	})
	return err
}

// GetGlobal 获取全局指标管理器
func GetGlobal() Metrics {
	if globalMetrics == nil {
		return &noopMetrics{}
	}
	return globalMetrics
}

// 便捷方法
func IncCounter(name string, labels ...string) {
	GetGlobal().IncCounter(name, labels...)
}

func AddCounter(name string, value float64, labels ...string) {
	GetGlobal().AddCounter(name, value, labels...)
}

func ObserveHistogram(name string, value float64, labels ...string) {
	GetGlobal().ObserveHistogram(name, value, labels...)
}

func SetGauge(name string, value float64, labels ...string) {
	GetGlobal().SetGauge(name, value, labels...)
}

func RecordHTTPRequest(method, path, status string, duration time.Duration) {
	GetGlobal().RecordHTTPRequest(method, path, status, duration)
}

func RecordDatabaseOperation(operation, table string, duration time.Duration, success bool) {
	GetGlobal().RecordDatabaseOperation(operation, table, duration, success)
}

func RecordCacheOperation(operation string, hit bool, duration time.Duration) {
	GetGlobal().RecordCacheOperation(operation, hit, duration)
}