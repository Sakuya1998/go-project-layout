package errors

import (
	"errors"
	"fmt"
)

// Sentinel errors
var (
	ErrNotFound     = errors.New("resource not found")
	ErrUnauthorized = errors.New("unauthorized access")
	ErrValidation   = errors.New("validation failed")
	ErrInternal     = errors.New("internal server error")
)

// 业务错误类型
type BusinessError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

func (e *BusinessError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func NewBusinessError(code, message string) *BusinessError {
	return &BusinessError{
		Code:    code,
		Message: message,
	}
}

func (e *BusinessError) WithDetails(details any) *BusinessError {
	e.Details = details
	return e
}
