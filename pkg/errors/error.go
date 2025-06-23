// Package errors 提供统一的错误处理机制，支持错误分类、错误链、上下文信息和结构化日志
package errors

import (
	"context"
	"fmt"
	"net/http"
)

// ============================================================================
// 错误分类和错误码定义
// ============================================================================

// ErrorCategory 错误分类枚举
type ErrorCategory string

const (
	CategoryValidation ErrorCategory = "VALIDATION" // 参数验证错误
	CategoryAuth       ErrorCategory = "AUTH"       // 认证授权错误
	CategoryBusiness   ErrorCategory = "BUSINESS"   // 业务逻辑错误
	CategorySystem     ErrorCategory = "SYSTEM"     // 系统级错误
	CategoryNetwork    ErrorCategory = "NETWORK"    // 网络相关错误
	CategoryDatabase   ErrorCategory = "DATABASE"   // 数据库相关错误
)

// 错误码常量定义
const (
	// 通用错误码
	ErrCodeCommonNotFound     = "COMMON_001"
	ErrCodeCommonUnauthorized = "COMMON_002"
	ErrCodeCommonValidation   = "COMMON_003"
	ErrCodeCommonInternal     = "COMMON_004"

	// 配置模块错误码
	ErrCodeConfigNotFound   = "CONFIG_001"
	ErrCodeConfigInvalid    = "CONFIG_002"
	ErrCodeConfigValidation = "CONFIG_003"
	ErrCodeConfigLoad       = "CONFIG_004"

	// 用户模块错误码
	ErrCodeUserNotFound    = "USER_001"
	ErrCodeUserExists      = "USER_002"
	ErrCodeInvalidPassword = "USER_003"

	// 数据库模块错误码
	ErrCodeDBConnection  = "DB_001"
	ErrCodeDBQuery       = "DB_002"
	ErrCodeDBTransaction = "DB_003"
)

// ============================================================================
// 预定义的通用业务错误实例
// ============================================================================

var (
	CommonNotFound     = NewValidationError(ErrCodeCommonNotFound, "资源未找到")
	CommonUnauthorized = NewAuthError(ErrCodeCommonUnauthorized, "未授权访问")
	CommonValidation   = NewValidationError(ErrCodeCommonValidation, "验证失败")
	CommonInternal     = NewSystemError(ErrCodeCommonInternal, "内部服务器错误")
)

// ============================================================================
// 核心错误类型定义
// ============================================================================

// BusinessError 统一的业务错误类型，支持错误分类、错误链和上下文信息
type BusinessError struct {
	Category ErrorCategory `json:"category"`          // 错误分类
	Code     string        `json:"code"`              // 错误码
	Message  string        `json:"message"`           // 错误消息
	Details  any           `json:"details,omitempty"` // 详细信息
	Cause    error         `json:"-"`                 // 原始错误，不序列化
}

// Error 实现 error 接口
func (e *BusinessError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s:%s] %s: %v", e.Category, e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s:%s] %s", e.Category, e.Code, e.Message)
}

// Unwrap 支持错误链，实现 Go 1.13+ 的错误包装机制
func (e *BusinessError) Unwrap() error {
	return e.Cause
}

// Is 支持错误比较，基于错误码进行比较
func (e *BusinessError) Is(target error) bool {
	if be, ok := target.(*BusinessError); ok {
		return e.Code == be.Code
	}
	return false
}

// ============================================================================
// 核心构造函数和方法
// ============================================================================

// NewBusinessError 创建新的业务错误
func NewBusinessError(category ErrorCategory, code, message string) *BusinessError {
	return &BusinessError{
		Category: category,
		Code:     code,
		Message:  message,
	}
}

// WithDetails 添加详细信息
func (e *BusinessError) WithDetails(details any) *BusinessError {
	e.Details = details
	return e
}

// WithCause 添加原始错误，支持错误链
func (e *BusinessError) WithCause(cause error) *BusinessError {
	e.Cause = cause
	return e
}

// WithContext 从上下文中提取追踪信息并添加到错误详情中
func (e *BusinessError) WithContext(ctx context.Context) *BusinessError {
	if ctx == nil {
		return e
	}

	// 确保 Details 是 map 类型
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}

	details, ok := e.Details.(map[string]interface{})
	if !ok {
		// 如果 Details 不是 map，创建新的 map 并保留原有 Details
		originalDetails := e.Details
		details = map[string]interface{}{
			"original_details": originalDetails,
		}
		e.Details = details
	}

	// 提取常见的上下文信息
	if traceID := ctx.Value("trace_id"); traceID != nil {
		details["trace_id"] = traceID
	}
	if requestID := ctx.Value("request_id"); requestID != nil {
		details["request_id"] = requestID
	}
	if userID := ctx.Value("user_id"); userID != nil {
		details["user_id"] = userID
	}

	return e
}

// ============================================================================
// 错误转换和日志方法
// ============================================================================

// HTTPStatus 根据错误分类返回对应的 HTTP 状态码
func (e *BusinessError) HTTPStatus() int {
	switch e.Category {
	case CategoryValidation:
		return http.StatusBadRequest // 400
	case CategoryAuth:
		return http.StatusUnauthorized // 401
	case CategoryBusiness:
		return http.StatusUnprocessableEntity // 422
	case CategoryNetwork:
		return http.StatusServiceUnavailable // 503
	case CategoryDatabase:
		return http.StatusInternalServerError // 500
	case CategorySystem:
		return http.StatusInternalServerError // 500
	default:
		return http.StatusInternalServerError // 500
	}
}

// LogFields 返回结构化日志字段，便于日志系统记录
func (e *BusinessError) LogFields() map[string]interface{} {
	fields := map[string]interface{}{
		"error_code":     e.Code,
		"error_category": string(e.Category),
		"error_message":  e.Message,
		"http_status":    e.HTTPStatus(),
	}

	if e.Details != nil {
		fields["error_details"] = e.Details
	}

	if e.Cause != nil {
		fields["error_cause"] = e.Cause.Error()
	}

	return fields
}

// ============================================================================
// 便捷构造函数
// ============================================================================

// NewValidationError 创建参数验证错误
func NewValidationError(code, message string) *BusinessError {
	return NewBusinessError(CategoryValidation, code, message)
}

// NewAuthError 创建认证授权错误
func NewAuthError(code, message string) *BusinessError {
	return NewBusinessError(CategoryAuth, code, message)
}

// NewBusinessLogicError 创建业务逻辑错误
func NewBusinessLogicError(code, message string) *BusinessError {
	return NewBusinessError(CategoryBusiness, code, message)
}

// NewSystemError 创建系统级错误
func NewSystemError(code, message string) *BusinessError {
	return NewBusinessError(CategorySystem, code, message)
}

// NewNetworkError 创建网络相关错误
func NewNetworkError(code, message string) *BusinessError {
	return NewBusinessError(CategoryNetwork, code, message)
}

// NewDatabaseError 创建数据库相关错误
func NewDatabaseError(code, message string) *BusinessError {
	return NewBusinessError(CategoryDatabase, code, message)
}

// ============================================================================
// 特定模块错误构造函数
// ============================================================================

// NewConfigNotFoundError 创建配置文件未找到错误
func NewConfigNotFoundError(details string) *BusinessError {
	return NewValidationError(ErrCodeConfigNotFound, "配置文件未找到").WithDetails(details)
}

// NewConfigInvalidError 创建配置项无效错误
func NewConfigInvalidError(field string, value interface{}) *BusinessError {
	return NewValidationError(ErrCodeConfigInvalid, "配置项无效").WithDetails(map[string]interface{}{
		"field": field,
		"value": value,
	})
}

// NewConfigValidationError 创建配置验证失败错误
func NewConfigValidationError(field, rule string) *BusinessError {
	return NewValidationError(ErrCodeConfigValidation, "配置验证失败").WithDetails(map[string]interface{}{
		"field": field,
		"rule":  rule,
	})
}

// NewUserNotFoundError 创建用户未找到错误
func NewUserNotFoundError(userID string) *BusinessError {
	return NewValidationError(ErrCodeUserNotFound, "用户不存在").WithDetails(map[string]interface{}{
		"user_id": userID,
	})
}

// NewUserExistsError 创建用户已存在错误
func NewUserExistsError(identifier string) *BusinessError {
	return NewValidationError(ErrCodeUserExists, "用户已存在").WithDetails(map[string]interface{}{
		"identifier": identifier,
	})
}

// NewInvalidPasswordError 创建密码无效错误
func NewInvalidPasswordError() *BusinessError {
	return NewAuthError(ErrCodeInvalidPassword, "密码错误")
}

// NewDBConnectionError 创建数据库连接错误
func NewDBConnectionError(cause error) *BusinessError {
	return NewDatabaseError(ErrCodeDBConnection, "数据库连接失败").WithCause(cause)
}

// NewDBQueryError 创建数据库查询错误
func NewDBQueryError(query string, cause error) *BusinessError {
	return NewDatabaseError(ErrCodeDBQuery, "数据库查询失败").WithDetails(map[string]interface{}{
		"query": query,
	}).WithCause(cause)
}

// NewDBTransactionError 创建数据库事务错误
func NewDBTransactionError(operation string, cause error) *BusinessError {
	return NewDatabaseError(ErrCodeDBTransaction, "数据库事务失败").WithDetails(map[string]interface{}{
		"operation": operation,
	}).WithCause(cause)
}
