package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTManager JWT管理器
type JWTManager struct {
	secretKey     []byte
	tokenDuration time.Duration
	issuer        string
}

// Claims JWT声明结构
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// NewJWTManager 创建JWT管理器
func NewJWTManager(secretKey string, tokenDuration time.Duration, issuer string) *JWTManager {
	return &JWTManager{
		secretKey:     []byte(secretKey),
		tokenDuration: tokenDuration,
		issuer:        issuer,
	}
}

// GenerateToken 生成JWT token
func (j *JWTManager) GenerateToken(userID, username, role string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.tokenDuration)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(j.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken 验证JWT token
func (j *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// 验证签名方法
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	// 验证issuer
	if claims.Issuer != j.issuer {
		return nil, errors.New("invalid token issuer")
	}

	return claims, nil
}

// RefreshToken 刷新token
func (j *JWTManager) RefreshToken(tokenString string) (string, error) {
	claims, err := j.ValidateToken(tokenString)
	if err != nil {
		return "", fmt.Errorf("invalid token for refresh: %w", err)
	}

	// 检查token是否即将过期（剩余时间少于总时长的1/3）
	remaining := time.Until(claims.ExpiresAt.Time)
	if remaining > j.tokenDuration/3 {
		return "", errors.New("token is still valid, no need to refresh")
	}

	return j.GenerateToken(claims.UserID, claims.Username, claims.Role)
}

// ExtractUserFromContext 从context中提取用户信息
func ExtractUserFromContext(ctx context.Context) (*Claims, error) {
	claims, ok := ctx.Value("user").(*Claims)
	if !ok {
		return nil, errors.New("user not found in context")
	}
	return claims, nil
}

// SetUserToContext 将用户信息设置到context中
func SetUserToContext(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, "user", claims)
}

// HasRole 检查用户是否具有指定角色
func (c *Claims) HasRole(role string) bool {
	return c.Role == role
}

// IsAdmin 检查用户是否为管理员
func (c *Claims) IsAdmin() bool {
	return c.HasRole("admin")
}

// GetUserID 获取用户ID
func (c *Claims) GetUserID() string {
	return c.UserID
}

// GetUsername 获取用户名
func (c *Claims) GetUsername() string {
	return c.Username
}

// IsExpired 检查token是否已过期
func (c *Claims) IsExpired() bool {
	return time.Now().After(c.ExpiresAt.Time)
}

// TimeToExpiry 获取距离过期的时间
func (c *Claims) TimeToExpiry() time.Duration {
	return time.Until(c.ExpiresAt.Time)
}