// Package utils 提供常用的工具函数
// 包含字符串处理、时间处理、验证等功能
package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// StringUtils 字符串工具
type StringUtils struct{}

// NewStringUtils 创建字符串工具实例
func NewStringUtils() *StringUtils {
	return &StringUtils{}
}

// IsEmpty 检查字符串是否为空
func (s *StringUtils) IsEmpty(str string) bool {
	return len(strings.TrimSpace(str)) == 0
}

// IsNotEmpty 检查字符串是否不为空
func (s *StringUtils) IsNotEmpty(str string) bool {
	return !s.IsEmpty(str)
}

// DefaultIfEmpty 如果字符串为空则返回默认值
func (s *StringUtils) DefaultIfEmpty(str, defaultStr string) string {
	if s.IsEmpty(str) {
		return defaultStr
	}
	return str
}

// Truncate 截断字符串到指定长度
func (s *StringUtils) Truncate(str string, length int) string {
	if len(str) <= length {
		return str
	}
	return str[:length]
}

// ToCamelCase 转换为驼峰命名
func (s *StringUtils) ToCamelCase(str string) string {
	if str == "" {
		return ""
	}

	words := strings.FieldsFunc(str, func(c rune) bool {
		return !unicode.IsLetter(c) && !unicode.IsNumber(c)
	})

	if len(words) == 0 {
		return ""
	}

	result := strings.ToLower(words[0])
	for i := 1; i < len(words); i++ {
		if len(words[i]) > 0 {
			result += strings.ToUpper(string(words[i][0])) + strings.ToLower(words[i][1:])
		}
	}

	return result
}

// ToPascalCase 转换为帕斯卡命名
func (s *StringUtils) ToPascalCase(str string) string {
	camelCase := s.ToCamelCase(str)
	if len(camelCase) == 0 {
		return ""
	}
	return strings.ToUpper(string(camelCase[0])) + camelCase[1:]
}

// ToSnakeCase 转换为蛇形命名
func (s *StringUtils) ToSnakeCase(str string) string {
	if str == "" {
		return ""
	}

	var result strings.Builder
	for i, r := range str {
		if unicode.IsUpper(r) {
			if i > 0 {
				result.WriteRune('_')
			}
			result.WriteRune(unicode.ToLower(r))
		} else {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// TimeUtils 时间工具
type TimeUtils struct{}

// NewTimeUtils 创建时间工具实例
func NewTimeUtils() *TimeUtils {
	return &TimeUtils{}
}

// Now 获取当前时间
func (t *TimeUtils) Now() time.Time {
	return time.Now()
}

// NowUnix 获取当前Unix时间戳
func (t *TimeUtils) NowUnix() int64 {
	return time.Now().Unix()
}

// NowUnixMilli 获取当前毫秒时间戳
func (t *TimeUtils) NowUnixMilli() int64 {
	return time.Now().UnixMilli()
}

// FormatTime 格式化时间
func (t *TimeUtils) FormatTime(time time.Time, layout string) string {
	return time.Format(layout)
}

// ParseTime 解析时间字符串
func (t *TimeUtils) ParseTime(timeStr, layout string) (time.Time, error) {
	return time.Parse(layout, timeStr)
}

// IsToday 检查是否为今天
func (t *TimeUtils) IsToday(checkTime time.Time) bool {
	now := time.Now()
	return checkTime.Year() == now.Year() &&
		checkTime.Month() == now.Month() &&
		checkTime.Day() == now.Day()
}

// ValidatorUtils 验证工具
type ValidatorUtils struct{}

// NewValidatorUtils 创建验证工具实例
func NewValidatorUtils() *ValidatorUtils {
	return &ValidatorUtils{}
}

// IsEmail 验证邮箱格式
func (v *ValidatorUtils) IsEmail(email string) bool {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(pattern, email)
	return matched
}

// IsPhone 验证手机号格式（中国大陆）
func (v *ValidatorUtils) IsPhone(phone string) bool {
	pattern := `^1[3-9]\d{9}$`
	matched, _ := regexp.MatchString(pattern, phone)
	return matched
}

// IsURL 验证URL格式
func (v *ValidatorUtils) IsURL(url string) bool {
	pattern := `^https?://[\w\-]+(\.[\w\-]+)+([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?$`
	matched, _ := regexp.MatchString(pattern, url)
	return matched
}

// IsNumeric 验证是否为数字
func (v *ValidatorUtils) IsNumeric(str string) bool {
	pattern := `^\d+$`
	matched, _ := regexp.MatchString(pattern, str)
	return matched
}

// CryptoUtils 加密工具
type CryptoUtils struct{}

// NewCryptoUtils 创建加密工具实例
func NewCryptoUtils() *CryptoUtils {
	return &CryptoUtils{}
}

// GenerateRandomString 生成随机字符串
func (c *CryptoUtils) GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateUUID 生成简单的UUID（基于随机数）
func (c *CryptoUtils) GenerateUUID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// 设置版本号和变体
	bytes[6] = (bytes[6] & 0x0f) | 0x40 // 版本 4
	bytes[8] = (bytes[8] & 0x3f) | 0x80 // 变体 10

	return fmt.Sprintf("%x-%x-%x-%x-%x",
		bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16]), nil
}

// 全局工具实例
var (
	StringUtil    = NewStringUtils()
	TimeUtil      = NewTimeUtils()
	ValidatorUtil = NewValidatorUtils()
	CryptoUtil    = NewCryptoUtils()
)

// 便捷方法

// IsEmpty 检查字符串是否为空
func IsEmpty(str string) bool {
	return StringUtil.IsEmpty(str)
}

// IsNotEmpty 检查字符串是否不为空
func IsNotEmpty(str string) bool {
	return StringUtil.IsNotEmpty(str)
}

// DefaultIfEmpty 如果字符串为空则返回默认值
func DefaultIfEmpty(str, defaultStr string) string {
	return StringUtil.DefaultIfEmpty(str, defaultStr)
}

// ToCamelCase 转换为驼峰命名
func ToCamelCase(str string) string {
	return StringUtil.ToCamelCase(str)
}

// ToPascalCase 转换为帕斯卡命名
func ToPascalCase(str string) string {
	return StringUtil.ToPascalCase(str)
}

// ToSnakeCase 转换为蛇形命名
func ToSnakeCase(str string) string {
	return StringUtil.ToSnakeCase(str)
}

// Now 获取当前时间
func Now() time.Time {
	return TimeUtil.Now()
}

// NowUnix 获取当前Unix时间戳
func NowUnix() int64 {
	return TimeUtil.NowUnix()
}

// IsEmail 验证邮箱格式
func IsEmail(email string) bool {
	return ValidatorUtil.IsEmail(email)
}

// IsPhone 验证手机号格式
func IsPhone(phone string) bool {
	return ValidatorUtil.IsPhone(phone)
}

// GenerateRandomString 生成随机字符串
func GenerateRandomString(length int) (string, error) {
	return CryptoUtil.GenerateRandomString(length)
}

// GenerateUUID 生成UUID
func GenerateUUID() (string, error) {
	return CryptoUtil.GenerateUUID()
}