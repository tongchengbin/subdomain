package subdomain

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
	"time"
)

// TestLogger 测试用的Logger实现
type TestLogger struct {
	t *testing.T
}

// NewTestLogger 创建一个测试用的Logger
func NewTestLogger(t *testing.T) *TestLogger {
	return &TestLogger{t: t}
}

// Debug 输出调试级别日志
func (l *TestLogger) Debug(format string, args ...interface{}) {
	l.t.Logf("[DEBUG] "+format, args...)
}

// Info 输出信息级别日志
func (l *TestLogger) Info(format string, args ...interface{}) {
	l.t.Logf("[INFO] "+format, args...)
}

// Warning 输出警告级别日志
func (l *TestLogger) Warning(format string, args ...interface{}) {
	l.t.Logf("[WARN] "+format, args...)
}

// Error 输出错误级别日志
func (l *TestLogger) Error(format string, args ...interface{}) {
	l.t.Logf("[ERROR] "+format, args...)
}

func TestWildcard(t *testing.T) {
	// 创建DNS发现实例并使用测试logger
	testLogger := NewTestLogger(t)
	discovery := NewDnsDiscovery(
		WithLogger(testLogger),
	)
	defer discovery.Close()

	// 测试通配符检测
	isWildcard := discovery.CheckWildcard("fang.com")
	assert.True(t, isWildcard)
}

// TestSingleDomainScan 测试扫描单个目标域名
func TestSingleDomainScan(t *testing.T) {
	// 创建DNS发现实例并使用测试logger
	testLogger := NewTestLogger(t)
	discovery := NewDnsDiscovery(
		WithLogger(testLogger),
	)
	defer discovery.Close()

	// 准备测试域名和字典
	domain := "hackerone.com"
	wordlist := []string{"www", "mail", "ftp", "api", "ctf", "frp"}
	// 执行扫描
	results := discovery.ScanWithWordlist(domain, wordlist)
	// 验证结果
	t.Logf("扫描域名 %s 发现 %d 个子域名", domain, len(results))
	for _, result := range results {
		t.Logf("  域名: %s, IP: %v, CNAME: %s", result.Domain, result.IP, result.CNAME)
	}
	// 验证扫描是否成功完成
	if len(results) == 0 {
		t.Log("警告: 未发现任何子域名，这可能是正常的，但也可能表明扫描未正确执行")
	}
}

// TestRateLimit 测试速率限制功能
func TestRateLimit(t *testing.T) {
	// 创建低速率的限制器
	lowRate := 10 // 每秒10个请求
	limiter := NewTokenBucketLimiter(lowRate, lowRate)

	// 创建使用低速率限制器的DNS发现实例并使用测试logger
	testLogger := NewTestLogger(t)
	discovery := NewDnsDiscovery(
		WithRateLimiter(limiter),
		WithTimeout(time.Second*10),
		WithLogger(testLogger),
	)
	defer discovery.Close()

	// 准备测试域名和较大的字典
	domain := "hackerone.com"
	wordlist := make([]string, 100) // 100个子域名
	for i := 0; i < 100; i++ {
		wordlist[i] = fmt.Sprintf("sub%d", i)
	}

	// 记录开始时间
	startTime := time.Now()

	// 执行扫描
	discovery.ScanWithWordlist(domain, wordlist)

	// 计算扫描耗时
	duration := time.Since(startTime)

	// 验证速率限制是否生效
	// 理论上，发送100个请求，速率为10/秒，至少需要10秒
	minExpectedDuration := time.Second * 10 / 2 // 考虑到并发和其他因素，使用一半的理论时间作为下限
	if duration < minExpectedDuration {
		t.Errorf("速率限制似乎未生效。扫描耗时 %v，但预期至少需要 %v", duration, minExpectedDuration)
	} else {
		t.Logf("速率限制正常工作。扫描耗时 %v，符合预期", duration)
	}
}

// TestCallbackFunction 测试回调函数功能
func TestCallbackFunction(t *testing.T) {
	// 创建DNS发现实例并使用测试logger
	testLogger := NewTestLogger(t)
	discovery := NewDnsDiscovery(
		WithLogger(testLogger),
	)
	defer discovery.Close()

	// 准备测试域名和字典
	domain := "hackerone.com"
	wordlist := []string{"www", "mail", "ftp", "api", "blog"}

	// 创建通道用于接收回调结果
	resultChan := make(chan *DnsResult, len(wordlist))
	var callbackCount int
	var callbackMutex sync.Mutex

	// 执行带回调的扫描
	discovery.ScanWithCallback(domain, wordlist, func(result *DnsResult) {
		// 将结果发送到通道
		resultChan <- result
		// 计数回调次数
		callbackMutex.Lock()
		callbackCount++
		callbackMutex.Unlock()
		t.Logf("回调接收到域名: %s, IP: %v", result.Domain, result.IP)
	})
	// 关闭结果通道
	close(resultChan)
	// 收集所有回调结果
	var results []*DnsResult
	for result := range resultChan {
		results = append(results, result)
	}
	// 验证结果
	t.Logf("通过回调收到 %d 个结果", len(results))
	t.Logf("回调函数被调用 %d 次", callbackCount)

	// 验证是否有回调结果
	if len(results) == 0 && callbackCount == 0 {
		t.Log("警告: 未通过回调收到任何结果，这可能是正常的，但也可能表明回调机制未正确工作")
	}
}

// TestConcurrentScans 测试多个扫描任务的结果隔离
func TestConcurrentScans(t *testing.T) {
	// 创建DNS发现实例并使用测试logger
	testLogger := NewTestLogger(t)
	discovery := NewDnsDiscovery(
		WithLogger(testLogger),
	)
	defer discovery.Close()

	// 准备测试域名和字典
	domainA := "example.com"
	domainB := "example.org"
	wordlist := []string{"www", "mail", "api"}

	// 创建通道用于接收结果
	resultsChanA := make(chan *DnsResult, 10)
	resultsChanB := make(chan *DnsResult, 10)

	// 并发执行两个扫描任务
	var wg sync.WaitGroup
	wg.Add(2)

	// 扫描任务A
	go func() {
		defer wg.Done()
		discovery.ScanWithCallback(domainA, wordlist, func(result *DnsResult) {
			// 验证结果属于正确的域名
			if !contains(result.Domain, domainA) {
				t.Errorf("任务A收到了错误的结果: %s，不属于域名 %s", result.Domain, domainA)
			}
			resultsChanA <- result
		})
		close(resultsChanA)
	}()

	// 扫描任务B
	go func() {
		defer wg.Done()
		discovery.ScanWithCallback(domainB, wordlist, func(result *DnsResult) {
			// 验证结果属于正确的域名
			if !contains(result.Domain, domainB) {
				t.Errorf("任务B收到了错误的结果: %s，不属于域名 %s", result.Domain, domainB)
			}
			resultsChanB <- result
		})
		close(resultsChanB)
	}()

	// 等待所有扫描完成
	wg.Wait()

	// 收集结果
	var resultsA, resultsB []*DnsResult
	for result := range resultsChanA {
		resultsA = append(resultsA, result)
	}
	for result := range resultsChanB {
		resultsB = append(resultsB, result)
	}

	// 验证结果
	t.Logf("任务A发现 %d 个子域名", len(resultsA))
	t.Logf("任务B发现 %d 个子域名", len(resultsB))
}

// 辅助函数：检查域名是否包含指定的父域名
func contains(domain, parent string) bool {
	// 简单检查域名是否以父域名结尾
	// 例如 "www.example.com" 包含 "example.com"
	lenDomain := len(domain)
	lenParent := len(parent)
	return lenDomain > lenParent && domain[lenDomain-lenParent:] == parent
}
