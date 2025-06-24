package middleware

import (
	"fmt"
	"sync"
	"time"
)

// RateLimitConfig 限流配置
type RateLimitConfig struct {
	TokensPerSecond float64       // 每秒生成的令牌数
	BurstSize       int           // 令牌桶容量
	WindowSize      time.Duration // 滑动窗口大小
	KeyType         string        // 限流键类型: ip, user, api_key, path, combined
	KeyPrefix       string        // 限流键前缀
}

// TokenBucket 令牌桶
type TokenBucket struct {
	tokens    float64   // 当前令牌数
	lastRefill time.Time // 上次填充时间
	rate      float64   // 每秒填充速率
	capacity  int       // 桶容量
}

// TokenBucketLimiter 令牌桶限流器
type TokenBucketLimiter struct {
	config  RateLimitConfig
	buckets map[string]*TokenBucket
	mu      sync.Mutex
}

// NewTokenBucketLimiter 创建令牌桶限流器
func NewTokenBucketLimiter(config RateLimitConfig) *TokenBucketLimiter {
	return &TokenBucketLimiter{
		config:  config,
		buckets: make(map[string]*TokenBucket),
		mu:      sync.Mutex{},
	}
}

// Allow 检查是否允许请求通过
func (l *TokenBucketLimiter) Allow(key string) (bool, int, time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	// 获取或创建令牌桶
	bucket, exists := l.buckets[key]
	if !exists {
		bucket = &TokenBucket{
			tokens:    float64(l.config.BurstSize),
			lastRefill: time.Now(),
			rate:      l.config.TokensPerSecond,
			capacity:  l.config.BurstSize,
		}
		l.buckets[key] = bucket
	}
	
	// 计算需要填充的令牌
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill).Seconds()
	bucket.lastRefill = now
	
	// 填充令牌
	bucket.tokens = bucket.tokens + elapsed*bucket.rate
	if bucket.tokens > float64(bucket.capacity) {
		bucket.tokens = float64(bucket.capacity)
	}
	
	// 检查是否有足够的令牌
	if bucket.tokens < 1 {
		// 计算下次可用时间
		timeToRefill := time.Duration((1 - bucket.tokens) / bucket.rate * float64(time.Second))
		resetTime := now.Add(timeToRefill)
		return false, 0, resetTime
	}
	
	// 消耗令牌
	bucket.tokens--
	
	// 计算剩余令牌和重置时间
	remaining := int(bucket.tokens)
	timeToRefill := time.Duration((float64(bucket.capacity) - bucket.tokens) / bucket.rate * float64(time.Second))
	resetTime := now.Add(timeToRefill)
	
	return true, remaining, resetTime
}

// buildLimitKey 构建限流键
func buildLimitKey(clientIP, userID, apiKey, path string) string {
	// 根据可用信息构建键
	if userID != "" {
		return fmt.Sprintf("user:%s", userID)
	}
	if apiKey != "" {
		return fmt.Sprintf("api:%s", apiKey)
	}
	return fmt.Sprintf("ip:%s:path:%s", clientIP, path)
}