// Package errors 提供统一的错误处理机制
// 包含错误定义、错误包装、错误码等功能
package errors

import (
	"fmt"
	"net/http"
)

// ErrorType 错误类型
type ErrorType string

const (
	// ErrorTypeValidation 验证错误
	ErrorTypeValidation ErrorType = "validation"
	// ErrorTypeNotFound 资源未找到错误
	ErrorTypeNotFound ErrorType = "not_found"
	// ErrorTypeUnauthorized 未授权错误
	ErrorTypeUnauthorized ErrorType = "unauthorized"
	// ErrorTypeForbidden 禁止访问错误
	ErrorTypeForbidden ErrorType = "forbidden"
	// ErrorTypeConflict 冲突错误
	ErrorTypeConflict ErrorType = "conflict"
	// ErrorTypeInternal 内部错误
	ErrorTypeInternal ErrorType = "internal"
	// ErrorTypeExternal 外部服务错误
	ErrorTypeExternal ErrorType = "external"
	// ErrorTypeTimeout 超时错误
	ErrorTypeTimeout ErrorType = "timeout"
	// ErrorTypeRateLimit 限流错误
	ErrorTypeRateLimit ErrorType = "rate_limit"
)

// AppError 应用错误结构
type AppError struct {
	Type    ErrorType `json:"type"`
	Code    string    `json:"code"`
	Message string    `json:"message"`
	Details string    `json:"details,omitempty"`
	Cause   error     `json:"-"`
}

// Error 实现error接口
func (e *AppError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap 实现errors.Unwrap接口
func (e *AppError) Unwrap() error {
	return e.Cause
}

// HTTPStatus 返回对应的HTTP状态码
func (e *AppError) HTTPStatus() int {
	switch e.Type {
	case ErrorTypeValidation:
		return http.StatusBadRequest
	case ErrorTypeNotFound:
		return http.StatusNotFound
	case ErrorTypeUnauthorized:
		return http.StatusUnauthorized
	case ErrorTypeForbidden:
		return http.StatusForbidden
	case ErrorTypeConflict:
		return http.StatusConflict
	case ErrorTypeTimeout:
		return http.StatusRequestTimeout
	case ErrorTypeRateLimit:
		return http.StatusTooManyRequests
	case ErrorTypeExternal:
		return http.StatusBadGateway
	case ErrorTypeInternal:
		fallthrough
	default:
		return http.StatusInternalServerError
	}
}

// New 创建新的应用错误
func New(errorType ErrorType, code, message string) *AppError {
	return &AppError{
		Type:    errorType,
		Code:    code,
		Message: message,
	}
}

// NewWithDetails 创建带详细信息的应用错误
func NewWithDetails(errorType ErrorType, code, message, details string) *AppError {
	return &AppError{
		Type:    errorType,
		Code:    code,
		Message: message,
		Details: details,
	}
}

// Wrap 包装现有错误
func Wrap(err error, errorType ErrorType, code, message string) *AppError {
	return &AppError{
		Type:    errorType,
		Code:    code,
		Message: message,
		Cause:   err,
	}
}

// WrapWithDetails 包装现有错误并添加详细信息
func WrapWithDetails(err error, errorType ErrorType, code, message, details string) *AppError {
	return &AppError{
		Type:    errorType,
		Code:    code,
		Message: message,
		Details: details,
		Cause:   err,
	}
}

// 预定义的常用错误

// NewValidationError 创建验证错误
func NewValidationError(message string) *AppError {
	return New(ErrorTypeValidation, "VALIDATION_ERROR", message)
}

// NewNotFoundError 创建资源未找到错误
func NewNotFoundError(resource string) *AppError {
	return New(ErrorTypeNotFound, "NOT_FOUND", fmt.Sprintf("%s not found", resource))
}

// NewUnauthorizedError 创建未授权错误
func NewUnauthorizedError(message string) *AppError {
	if message == "" {
		message = "Unauthorized access"
	}
	return New(ErrorTypeUnauthorized, "UNAUTHORIZED", message)
}

// NewForbiddenError 创建禁止访问错误
func NewForbiddenError(message string) *AppError {
	if message == "" {
		message = "Access forbidden"
	}
	return New(ErrorTypeForbidden, "FORBIDDEN", message)
}

// NewConflictError 创建冲突错误
func NewConflictError(message string) *AppError {
	return New(ErrorTypeConflict, "CONFLICT", message)
}

// NewInternalError 创建内部错误
func NewInternalError(message string) *AppError {
	if message == "" {
		message = "Internal server error"
	}
	return New(ErrorTypeInternal, "INTERNAL_ERROR", message)
}

// NewExternalError 创建外部服务错误
func NewExternalError(service, message string) *AppError {
	return NewWithDetails(ErrorTypeExternal, "EXTERNAL_ERROR",
		fmt.Sprintf("External service error: %s", message), service)
}

// NewTimeoutError 创建超时错误
func NewTimeoutError(operation string) *AppError {
	return NewWithDetails(ErrorTypeTimeout, "TIMEOUT",
		"Operation timeout", operation)
}

// NewRateLimitError 创建限流错误
func NewRateLimitError() *AppError {
	return New(ErrorTypeRateLimit, "RATE_LIMIT_EXCEEDED", "Rate limit exceeded")
}

// 错误检查函数

// IsAppError 检查是否为应用错误
func IsAppError(err error) bool {
	_, ok := err.(*AppError)
	return ok
}

// IsType 检查错误类型
func IsType(err error, errorType ErrorType) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Type == errorType
	}
	return false
}

// IsValidationError 检查是否为验证错误
func IsValidationError(err error) bool {
	return IsType(err, ErrorTypeValidation)
}

// IsNotFoundError 检查是否为资源未找到错误
func IsNotFoundError(err error) bool {
	return IsType(err, ErrorTypeNotFound)
}

// IsUnauthorizedError 检查是否为未授权错误
func IsUnauthorizedError(err error) bool {
	return IsType(err, ErrorTypeUnauthorized)
}

// IsForbiddenError 检查是否为禁止访问错误
func IsForbiddenError(err error) bool {
	return IsType(err, ErrorTypeForbidden)
}

// IsConflictError 检查是否为冲突错误
func IsConflictError(err error) bool {
	return IsType(err, ErrorTypeConflict)
}

// IsInternalError 检查是否为内部错误
func IsInternalError(err error) bool {
	return IsType(err, ErrorTypeInternal)
}

// IsExternalError 检查是否为外部服务错误
func IsExternalError(err error) bool {
	return IsType(err, ErrorTypeExternal)
}

// IsTimeoutError 检查是否为超时错误
func IsTimeoutError(err error) bool {
	return IsType(err, ErrorTypeTimeout)
}

// IsRateLimitError 检查是否为限流错误
func IsRateLimitError(err error) bool {
	return IsType(err, ErrorTypeRateLimit)
}

// GetHTTPStatus 获取错误对应的HTTP状态码
func GetHTTPStatus(err error) int {
	if appErr, ok := err.(*AppError); ok {
		return appErr.HTTPStatus()
	}
	return http.StatusInternalServerError
}

// ErrorResponse HTTP错误响应结构
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Type    string `json:"type,omitempty"`
	Details string `json:"details,omitempty"`
}

// ToErrorResponse 将错误转换为HTTP响应结构
func ToErrorResponse(err error) ErrorResponse {
	if appErr, ok := err.(*AppError); ok {
		return ErrorResponse{
			Error:   appErr.Message,
			Code:    appErr.Code,
			Type:    string(appErr.Type),
			Details: appErr.Details,
		}
	}

	return ErrorResponse{
		Error: err.Error(),
		Code:  "UNKNOWN_ERROR",
		Type:  string(ErrorTypeInternal),
	}
}
