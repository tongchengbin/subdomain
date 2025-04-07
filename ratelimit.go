package subdomain

import (
	"sync"
	"time"
)

// RateLimiter 定义速率限制器接口
type RateLimiter interface {
	// Allow 检查是否允许当前请求通过
	// 如果允许，返回true；否则返回false
	Allow() bool
	
	// Wait 等待直到允许请求通过
	// 返回等待的时间
	Wait() time.Duration
	
	// SetRate 设置新的速率限制
	// rate: 每秒允许的请求数
	SetRate(rate int)
	
	// SetBurstSize 设置新的突发大小
	// burstSize: 突发请求的最大数量
	SetBurstSize(burstSize int)
	
	// GetRate 获取当前速率限制
	GetRate() int
	
	// GetBurstSize 获取当前突发大小
	GetBurstSize() int
	
	// RemainingTokens 获取当前剩余的令牌数
	RemainingTokens() int
}

// TokenBucketLimiter 提供基于令牌桶算法的速率限制功能
type TokenBucketLimiter struct {
	rate       int           // 每秒允许的请求数
	interval   time.Duration // 令牌桶填充间隔
	tokens     int           // 当前可用令牌数
	maxTokens  int           // 最大令牌数
	lastRefill time.Time     // 上次填充时间
	mu         sync.Mutex    // 互斥锁，保护并发访问
}

// 全局速率限制器管理器
var (
	globalLimiters     = make(map[string]RateLimiter)
	globalLimiterMutex sync.RWMutex
	defaultLimiterName = "default"
)

// NewTokenBucketLimiter 创建一个新的基于令牌桶算法的速率限制器
// rate: 每秒允许的请求数
// burstSize: 突发请求的最大数量（如果为0，则默认为rate）
func NewTokenBucketLimiter(rate int, burstSize int) *TokenBucketLimiter {
	if rate <= 0 {
		rate = 1000 // 默认每秒1000个请求
	}
	
	if burstSize <= 0 {
		burstSize = rate // 默认突发大小等于速率
	}
	
	return &TokenBucketLimiter{
		rate:       rate,
		interval:   time.Second / time.Duration(rate),
		tokens:     burstSize,
		maxTokens:  burstSize,
		lastRefill: time.Now(),
	}
}

// GetGlobalLimiter 获取指定名称的全局速率限制器
// 如果不存在则创建一个新的
func GetGlobalLimiter(name string, rate int, burstSize int) RateLimiter {
	if name == "" {
		name = defaultLimiterName
	}
	
	globalLimiterMutex.RLock()
	limiter, exists := globalLimiters[name]
	globalLimiterMutex.RUnlock()
	
	if !exists {
		limiter = NewTokenBucketLimiter(rate, burstSize)
		
		globalLimiterMutex.Lock()
		globalLimiters[name] = limiter
		globalLimiterMutex.Unlock()
	}
	
	return limiter
}

// SetGlobalLimiter 设置指定名称的全局速率限制器
func SetGlobalLimiter(name string, limiter RateLimiter) {
	if name == "" {
		name = defaultLimiterName
	}
	
	globalLimiterMutex.Lock()
	globalLimiters[name] = limiter
	globalLimiterMutex.Unlock()
}

// UpdateGlobalLimiter 更新指定名称的全局速率限制器的速率
func UpdateGlobalLimiter(name string, rate int, burstSize int) RateLimiter {
	if name == "" {
		name = defaultLimiterName
	}
	
	globalLimiterMutex.RLock()
	limiter, exists := globalLimiters[name]
	globalLimiterMutex.RUnlock()
	
	if exists {
		limiter.SetRate(rate)
		limiter.SetBurstSize(burstSize)
	} else {
		limiter = NewTokenBucketLimiter(rate, burstSize)
		
		globalLimiterMutex.Lock()
		globalLimiters[name] = limiter
		globalLimiterMutex.Unlock()
	}
	
	return limiter
}

// GetAllGlobalLimiters 获取所有全局速率限制器的名称
func GetAllGlobalLimiters() []string {
	globalLimiterMutex.RLock()
	defer globalLimiterMutex.RUnlock()
	
	names := make([]string, 0, len(globalLimiters))
	for name := range globalLimiters {
		names = append(names, name)
	}
	
	return names
}

// refill 根据经过的时间填充令牌
func (l *TokenBucketLimiter) refill() {
	now := time.Now()
	elapsed := now.Sub(l.lastRefill)
	
	// 计算应该添加的令牌数
	tokensToAdd := int(elapsed.Seconds() * float64(l.rate))
	if tokensToAdd > 0 {
		l.tokens = min(l.maxTokens, l.tokens+tokensToAdd)
		l.lastRefill = now
	}
}

// Allow 检查是否允许当前请求通过
// 如果允许，返回true；否则返回false
func (l *TokenBucketLimiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	l.refill()
	
	if l.tokens > 0 {
		l.tokens--
		return true
	}
	
	return false
}

// Wait 等待直到允许请求通过
// 返回等待的时间
func (l *TokenBucketLimiter) Wait() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	l.refill()
	
	if l.tokens > 0 {
		l.tokens--
		return 0
	}
	
	// 计算需要等待的时间
	tokensNeeded := 1
	waitTime := time.Duration(float64(tokensNeeded) / float64(l.rate) * float64(time.Second))
	
	// 模拟等待
	time.Sleep(waitTime)
	l.tokens = 0
	l.lastRefill = time.Now()
	
	return waitTime
}

// SetRate 设置新的速率限制
// rate: 每秒允许的请求数
func (l *TokenBucketLimiter) SetRate(rate int) {
	if rate <= 0 {
		rate = 1000 // 默认每秒1000个请求
	}
	
	l.mu.Lock()
	defer l.mu.Unlock()
	
	l.rate = rate
	l.interval = time.Second / time.Duration(rate)
}

// SetBurstSize 设置新的突发大小
// burstSize: 突发请求的最大数量
func (l *TokenBucketLimiter) SetBurstSize(burstSize int) {
	if burstSize <= 0 {
		burstSize = l.rate // 默认突发大小等于速率
	}
	
	l.mu.Lock()
	defer l.mu.Unlock()
	
	// 更新最大令牌数
	l.maxTokens = burstSize
	l.tokens = min(l.tokens, l.maxTokens)
}

// GetRate 获取当前速率限制
func (l *TokenBucketLimiter) GetRate() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	return l.rate
}

// GetBurstSize 获取当前突发大小
func (l *TokenBucketLimiter) GetBurstSize() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	return l.maxTokens
}

// RemainingTokens 获取当前剩余的令牌数
func (l *TokenBucketLimiter) RemainingTokens() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	l.refill()
	return l.tokens
}

// 为了向后兼容，保留原来的RateLimiter类型别名
type RateLimiterLegacy = TokenBucketLimiter

// 为了向后兼容，保留原来的NewRateLimiter函数
func NewRateLimiter(rate int, burstSize int) *TokenBucketLimiter {
	return NewTokenBucketLimiter(rate, burstSize)
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
