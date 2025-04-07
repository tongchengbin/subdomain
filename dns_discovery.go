package subdomain

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/projectdiscovery/gologger"
)

const DNsType = "a"

// DnsResult 表示DNS查询结果
type DnsResult struct {
	Domain  string   // 域名
	IP      []string // IP地址
	CNAME   string   // CNAME记录
	QueryID uint16   // DNS查询ID，用于关联请求和响应
	Source  string   // 来源标识，用于区分不同的扫描任务
}

// DomainCallback 定义发现域名时的回调函数类型
type DomainCallback func(result *DnsResult)

// ResultCollector 定义结果收集器接口
type ResultCollector interface {
	// Collect 收集DNS查询结果
	Collect(result *DnsResult)
	// Done 标记收集完成
	Done()
	// GetResults 获取收集的结果
	GetResults() []*DnsResult
	// IsDone 检查是否已完成
	IsDone() bool
	// Wait 等待所有查询完成或超时
	Wait(maxWaitTime time.Duration)
	// Close 关闭收集器，释放资源
	Close()
}

// BatchResultCollector 批量结果收集器实现
type BatchResultCollector struct {
	sourcePort int                   // 源端口，用于标识批次
	resultMap  map[string]*DnsResult // 结果映射
	mutex      sync.RWMutex          // 互斥锁
	doneChan   chan struct{}         // 完成信号通道
	callback   DomainCallback        // 可选的回调函数

	// 请求跟踪
	pendingMutex   sync.RWMutex         // 待处理请求互斥锁
	pendingQueries map[string]time.Time // 待处理的查询，键为域名，值为发送时间
	timeout        time.Duration        // 单个查询超时时间

	// 等待条件
	waitCond      *sync.Cond    // 等待条件变量
	cleanupTicker *time.Ticker  // 清理超时查询的定时器
	cleanupDone   chan struct{} // 清理协程结束信号

	// 结果统计
	totalQueries   int // 总查询数量
	processedCount int // 已处理查询数量（成功或超时）
}

// NewBatchResultCollector 创建新的批量结果收集器
func NewBatchResultCollector(sourcePort int, callback DomainCallback, timeout time.Duration) *BatchResultCollector {
	c := &BatchResultCollector{
		sourcePort:     sourcePort,
		resultMap:      make(map[string]*DnsResult),
		doneChan:       make(chan struct{}),
		callback:       callback,
		pendingQueries: make(map[string]time.Time),
		timeout:        timeout,
		cleanupDone:    make(chan struct{}),
	}
	c.waitCond = sync.NewCond(&c.pendingMutex)

	// 启动清理超时查询的协程
	c.cleanupTicker = time.NewTicker(time.Millisecond * 100)
	go c.cleanupRoutine()

	return c
}

// cleanupRoutine 清理超时查询的协程
func (c *BatchResultCollector) cleanupRoutine() {
	dnsDiscovery := GetDnsDiscoveryInstance() // 获取DNS发现实例的函数，需要实现
	sourcePort := c.sourcePort

	for {
		select {
		case <-c.cleanupTicker.C:
			// 清理超时的查询
			count, timedOutDomains := c.CleanupTimedOutQueries()

			// 如果有查询超时，尝试重试
			if count > 0 && dnsDiscovery != nil {
				for _, domain := range timedOutDomains {
					// 重试超时的查询
					dnsDiscovery.retryQuery(domain, sourcePort)
				}
			}

			// 如果有查询超时或没有待处理查询，通知等待者
			if count > 0 || !c.HasPendingQueries() {
				c.waitCond.Broadcast()
			}
		case <-c.cleanupDone:
			// 结束清理协程
			c.cleanupTicker.Stop()
			return
		}
	}
}

// CleanupTimedOutQueries 清理超时的查询
func (c *BatchResultCollector) CleanupTimedOutQueries() (int, []string) {
	c.pendingMutex.Lock()
	defer c.pendingMutex.Unlock()

	now := time.Now()
	count := 0
	timedOutDomains := make([]string, 0)

	for domain, sendTime := range c.pendingQueries {
		if now.Sub(sendTime) > c.timeout {
			// 记录超时的域名，稍后处理重试
			timedOutDomains = append(timedOutDomains, domain)
			delete(c.pendingQueries, domain)
			c.processedCount++
			count++
		}
	}

	// 如果已处理所有查询，通知等待者
	if c.processedCount >= c.totalQueries {
		c.waitCond.Broadcast()
	}

	// 返回超时的域名列表，可用于重试
	return count, timedOutDomains
}

// AddPendingQuery 添加待处理的查询
func (c *BatchResultCollector) AddPendingQuery(domain string) {
	c.pendingMutex.Lock()
	defer c.pendingMutex.Unlock()
	c.pendingQueries[domain] = time.Now()
	c.totalQueries++
}

// RemovePendingQuery 移除待处理的查询
func (c *BatchResultCollector) RemovePendingQuery(domain string) {
	c.pendingMutex.Lock()
	defer c.pendingMutex.Unlock()

	// 检查域名是否在待处理查询中
	_, exists := c.pendingQueries[domain]
	if exists {
		delete(c.pendingQueries, domain)
		c.processedCount++

		// 如果已处理所有查询或没有待处理查询，通知等待者
		if c.processedCount >= c.totalQueries || len(c.pendingQueries) == 0 {
			c.waitCond.Broadcast()
		}
	}
}

// HasPendingQueries 检查是否有待处理的查询
func (c *BatchResultCollector) HasPendingQueries() bool {
	c.pendingMutex.RLock()
	defer c.pendingMutex.RUnlock()
	return len(c.pendingQueries) > 0
}

// GetPendingQueriesCount 获取待处理查询数量
func (c *BatchResultCollector) GetPendingQueriesCount() int {
	c.pendingMutex.RLock()
	defer c.pendingMutex.RUnlock()
	return len(c.pendingQueries)
}

// GetProcessedCount 获取已处理查询数量
func (c *BatchResultCollector) GetProcessedCount() int {
	c.pendingMutex.RLock()
	defer c.pendingMutex.RUnlock()
	return c.processedCount
}

// GetTotalQueries 获取总查询数量
func (c *BatchResultCollector) GetTotalQueries() int {
	c.pendingMutex.RLock()
	defer c.pendingMutex.RUnlock()
	return c.totalQueries
}

// Wait 等待所有查询完成或超时
func (c *BatchResultCollector) Wait(maxWaitTime time.Duration) {
	deadline := time.Now().Add(maxWaitTime)

	c.pendingMutex.Lock()
	defer c.pendingMutex.Unlock()

	// 如果没有查询或已经处理完所有查询，直接返回
	if c.totalQueries == 0 || c.processedCount >= c.totalQueries {
		return
	}

	// 循环等待，直到处理完所有查询、没有待处理查询或超过最大等待时间
	for c.processedCount < c.totalQueries && len(c.pendingQueries) > 0 && time.Now().Before(deadline) {
		// 计算剩余等待时间
		remainingTime := deadline.Sub(time.Now())
		if remainingTime <= 0 {
			break
		}
		// 等待条件变量通知或超时
		waitTimer := time.NewTimer(remainingTime)
		waitDone := make(chan struct{})

		go func() {
			select {
			case <-waitTimer.C:
				// 超时，唤醒等待者
				c.waitCond.Broadcast()
			case <-waitDone:
				// 等待结束，停止定时器
				waitTimer.Stop()
			}
		}()
		// 等待条件变量通知
		c.waitCond.Wait()
		close(waitDone)
	}
	// 如果还有待处理查询但已超时，将它们标记为已处理
	if len(c.pendingQueries) > 0 {
		for domain := range c.pendingQueries {
			delete(c.pendingQueries, domain)
			c.processedCount++
		}
	}
}

// Close 关闭收集器，释放资源
func (c *BatchResultCollector) Close() {
	// 停止清理协程
	close(c.cleanupDone)

	// 标记完成
	c.Done()
}

// Collect 收集DNS查询结果
func (c *BatchResultCollector) Collect(result *DnsResult) {
	if result == nil {
		return
	}

	// 移除待处理查询
	c.RemovePendingQuery(result.Domain)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// 检查是否已存在该域名
	existing, exists := c.resultMap[result.Domain]
	if exists {
		// 合并结果
		if len(result.IP) > 0 {
			// 添加新的IP地址
			for _, ip := range result.IP {
				// 检查IP是否已存在
				ipExists := false
				for _, existingIP := range existing.IP {
					if existingIP == ip {
						ipExists = true
						break
					}
				}
				if !ipExists {
					existing.IP = append(existing.IP, ip)
				}
			}
		}
		if result.CNAME != "" {
			existing.CNAME = result.CNAME
		}
		c.resultMap[result.Domain] = existing

		// 执行回调
		if c.callback != nil {
			// 创建副本以避免竞争条件
			resultCopy := *existing
			go c.callback(&resultCopy)
		}
	} else {
		// 添加新结果
		c.resultMap[result.Domain] = result

		// 执行回调
		if c.callback != nil {
			// 创建副本以避免竞争条件
			resultCopy := *result
			go c.callback(&resultCopy)
		}
	}
}

// Done 标记收集完成
func (c *BatchResultCollector) Done() {
	select {
	case <-c.doneChan:
		// 通道已关闭，无需重复关闭
	default:
		close(c.doneChan)
	}
}

// GetResults 获取收集的结果
func (c *BatchResultCollector) GetResults() []*DnsResult {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	results := make([]*DnsResult, 0, len(c.resultMap))
	for _, result := range c.resultMap {
		results = append(results, result)
	}
	return results
}

// IsDone 检查是否已完成
func (c *BatchResultCollector) IsDone() bool {
	select {
	case <-c.doneChan:
		return true
	default:
		return false
	}
}

type DNSRequest struct {
	Domain string
	Source int
}

// DnsDiscovery 提供DNS发现功能
type DnsDiscovery struct {
	rateLimiter  RateLimiter            // 速率限制器
	dnsServers   []net.IP               // DNS服务器IP地址
	timeout      time.Duration          // 超时时间
	handle       *pcap.Handle           // 数据包捕获句柄
	captureMutex sync.Mutex             // 数据包捕获互斥锁
	stopChan     chan struct{}          // 停止信号通道
	resultChan   chan *DnsResult        // 结果通道
	packetSource *gopacket.PacketSource // 数据包源

	// 查询映射，用于关联DNS查询ID和源信息
	queryMapMutex      sync.RWMutex
	queryMap           map[uint16]string // 键为DNS查询ID，值为源标识
	dnsServersTemplate []gopacket.SerializableLayer
	ethLayer           gopacket.SerializableLayer
	sourceIP           net.IP

	// 结果收集器注册表，键为源端口
	collectorsMutex sync.RWMutex
	collectors      map[int]ResultCollector

	//	重试队列
	reqChan chan *DNSRequest

	// 请求缓存，用于过期处理和重试
	requestCache     map[string]*RequestCacheItem // 域名 -> 缓存项
	requestCacheLock sync.RWMutex
	cacheHead        *RequestCacheItem // 链表头部（最早的请求）
	cacheTail        *RequestCacheItem // 链表尾部（最新的请求）
}

// RequestCacheItem 请求缓存项
type RequestCacheItem struct {
	Domain     string            // 域名
	SourcePort int               // 源端口
	SendTime   time.Time         // 发送时间
	RetryCount int               // 重试次数
	Next       *RequestCacheItem // 链表的下一个节点
	Prev       *RequestCacheItem // 链表的上一个节点
}

// NewDnsDiscovery 创建一个新的DNS发现实例
func NewDnsDiscovery(options ...DnsDiscoveryOption) *DnsDiscovery {
	// 创建默认实例
	d := &DnsDiscovery{
		rateLimiter: NewTokenBucketLimiter(1000, 1000), // 默认每秒1000个请求
		dnsServers:  []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("1.1.1.1")},
		timeout:     time.Second * 5,

		captureMutex: sync.Mutex{},
		stopChan:     make(chan struct{}),
		resultChan:   make(chan *DnsResult, 1000),
		queryMap:     make(map[uint16]string),
		collectors:   make(map[int]ResultCollector),
		reqChan:      make(chan *DNSRequest, 1000),       // 设置合理的缓冲区大小
		requestCache: make(map[string]*RequestCacheItem), // 初始化请求缓存
		cacheHead:    nil,
		cacheTail:    nil,
	}
	// 应用选项
	for _, option := range options {
		option(d)
	}
	// init packet source
	_ = d.initNetworkPacketCapture()
	// start capture
	go d.capturePackets()
	// 启动重试处理协程
	go d.processRetries()
	// 启动过期请求处理协程
	go d.processExpiredRequests()

	// 设置全局实例
	SetDnsDiscoveryInstance(d)

	return d
}

// DnsDiscoveryOption 定义DNS发现选项函数类型
type DnsDiscoveryOption func(*DnsDiscovery)

// WithRateLimiter 设置速率限制器
func WithRateLimiter(limiter RateLimiter) DnsDiscoveryOption {
	return func(d *DnsDiscovery) {
		d.rateLimiter = limiter
	}
}

// WithDnsServers 设置DNS服务器
func WithDnsServers(servers []string) DnsDiscoveryOption {
	return func(d *DnsDiscovery) {
		d.initDnsServers(servers)
	}
}

// WithTimeout 设置超时时间
func WithTimeout(timeout time.Duration) DnsDiscoveryOption {
	return func(d *DnsDiscovery) {
		d.timeout = timeout
	}
}

// RegisterCollector 注册结果收集器
func (d *DnsDiscovery) RegisterCollector(sourcePort int, collector ResultCollector) {
	d.collectorsMutex.Lock()
	defer d.collectorsMutex.Unlock()
	d.collectors[sourcePort] = collector
}

// UnregisterCollector 注销结果收集器
func (d *DnsDiscovery) UnregisterCollector(sourcePort int) {
	d.collectorsMutex.Lock()
	defer d.collectorsMutex.Unlock()
	delete(d.collectors, sourcePort)
}

// GetCollector 获取结果收集器
func (d *DnsDiscovery) GetCollector(sourcePort int) ResultCollector {
	d.collectorsMutex.RLock()
	defer d.collectorsMutex.RUnlock()
	return d.collectors[sourcePort]
}

// ScanWithDomains 扫描指定的域名列表
func (d *DnsDiscovery) ScanWithDomains(domains []string) []*DnsResult {
	// 获取空闲端口作为批次标识
	freePort, err := GetFreePort()
	if err != nil {
		gologger.Warning().Msgf("dns_discovery.go:subdomain:ScanWithDomains: %s", err)
		return nil
	}
	// 创建并注册结果收集器
	collector := NewBatchResultCollector(freePort, nil, d.timeout)
	d.RegisterCollector(freePort, collector)
	defer func() {
		collector.Close()
		d.UnregisterCollector(freePort)
	}()
	// 发送DNS查询
	for _, domain := range domains {
		// 添加到待处理查询
		collector.AddPendingQuery(domain)
		err := d.sendDnsQuery(domain, freePort)
		if err != nil {
			gologger.Warning().Msgf("dns_discovery.go:subdomain:ScanWithDomains: %s", err)
			// 如果发送失败，从待处理查询中移除
			collector.RemovePendingQuery(domain)
		}
	}

	// 计算最大等待时间：每个域名的超时时间总和，但不超过合理的上限
	domainCount := len(domains)
	maxWaitTime := d.timeout * time.Duration(domainCount)
	// 设置一个合理的上限，避免等待时间过长
	maxUpperLimit := time.Second * 60 // 最长等待60秒
	if maxWaitTime > maxUpperLimit {
		maxWaitTime = maxUpperLimit
	}
	// 等待所有查询完成或超时
	collector.Wait(maxWaitTime)
	// 返回收集的结果
	return collector.GetResults()
}

// ScanWithWordlist 使用字典扫描指定域名的子域名
func (d *DnsDiscovery) ScanWithWordlist(domain string, wordlist []string) []*DnsResult {
	// 创建完整的子域名列表
	domains := make([]string, 0, len(wordlist))
	for _, word := range wordlist {
		domains = append(domains, fmt.Sprintf("%s.%s", word, domain))
	}
	// 使用ScanWithDomains方法扫描
	return d.ScanWithDomains(domains)
}

// ScanWithCallback 使用回调函数扫描域名
func (d *DnsDiscovery) ScanWithCallback(domain string, wordlist []string, callback DomainCallback) []*DnsResult {
	// 创建完整的子域名列表
	domains := make([]string, 0, len(wordlist))
	for _, word := range wordlist {
		domains = append(domains, fmt.Sprintf("%s.%s", word, domain))
	}

	// 获取空闲端口作为批次标识
	freePort, err := GetFreePort()
	if err != nil {
		gologger.Warning().Msgf("dns_discovery.go:subdomain:ScanWithCallback: %s", err)
		return nil
	}

	// 创建并注册结果收集器
	collector := NewBatchResultCollector(freePort, callback, d.timeout)
	d.RegisterCollector(freePort, collector)
	defer func() {
		collector.Close()
		d.UnregisterCollector(freePort)
	}()

	// 发送DNS查询
	for _, domain := range domains {
		// 添加到待处理查询
		collector.AddPendingQuery(domain)
		err := d.sendDnsQuery(domain, freePort)
		if err != nil {
			gologger.Warning().Msgf("dns_discovery.go:subdomain:ScanWithCallback: %s", err)
			// 如果发送失败，从待处理查询中移除
			collector.RemovePendingQuery(domain)
		}
	}

	// 等待所有查询完成或超时
	maxWaitTime := d.timeout + (time.Second * 2) // 额外等待2秒，确保所有响应都能处理
	collector.Wait(maxWaitTime)

	// 返回收集的结果
	return collector.GetResults()
}

// initDnsServers 初始化DNS服务器IP地址
func (d *DnsDiscovery) initDnsServers(servers []string) {
	d.dnsServers = make([]net.IP, 0, len(servers))
	for _, server := range servers {
		host, _, err := net.SplitHostPort(server)
		if err != nil {
			// 如果没有端口，假设是IP地址
			host = server
		}
		ip := net.ParseIP(host)
		if ip != nil {
			d.dnsServers = append(d.dnsServers, ip)
		}
	}

	// 如果没有有效的DNS服务器，使用默认DNS
	if len(d.dnsServers) == 0 {
		d.dnsServers = append(d.dnsServers, net.ParseIP("8.8.8.8"))
		d.dnsServers = append(d.dnsServers, net.ParseIP("1.1.1.1"))
	}
}

// selectBestInterface 选择最佳网络接口
func (d *DnsDiscovery) selectBestInterface(devices []pcap.Interface) *pcap.Interface {
	// 首先尝试找到非回环接口
	for _, dev := range devices {
		if !isLoopback(dev) && len(dev.Addresses) > 0 {
			// 检查是否有IPv4地址
			for _, addr := range dev.Addresses {
				ip := addr.IP
				if ip.To4() != nil {
					return &dev
				}
			}
		}
	}

	// 如果没有找到非回环接口，尝试找到任何有IPv4地址的接口
	for _, dev := range devices {
		if len(dev.Addresses) > 0 {
			for _, addr := range dev.Addresses {
				ip := addr.IP
				if ip.To4() != nil {
					return &dev
				}
			}
		}
	}

	// 如果没有找到任何合适的接口，返回nil
	return nil
}

// isLoopback 判断接口是否为回环接口
func isLoopback(dev pcap.Interface) bool {
	// 检查接口名称是否包含"loopback"或"lo"
	if strings.Contains(strings.ToLower(dev.Name), "loopback") || strings.Contains(strings.ToLower(dev.Name), "lo") {
		return true
	}

	// 检查接口地址是否为回环地址
	for _, addr := range dev.Addresses {
		if addr.IP.IsLoopback() {
			return true
		}
	}

	return false
}

// initNetworkPacketCapture 初始化网络数据包捕获
func (d *DnsDiscovery) initNetworkPacketCapture() error {
	// 初始化模板映射
	firstAddr := d.dnsServers[0]
	// get eth by ip
	// 获取到DNS服务器的路由信息
	iFaceName, srcIP, srcMAC, dstMAC, err := getLocalRouteInfo(firstAddr.String())
	if err != nil {
		return fmt.Errorf("获取路由信息失败: %v", err)
	}
	// 构建模板
	d.ethLayer = &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	d.sourceIP = srcIP
	// init handle
	if d.handle == nil {
		d.handle, err = pcap.OpenLive(iFaceName, 65536, true, pcap.BlockForever)
		if err != nil {
			return fmt.Errorf("打开网络接口失败: %v", err)
		}

	}
	return nil
}

// capturePackets 捕获DNS响应包
func (d *DnsDiscovery) capturePackets() {
	// 设置过滤器，只捕获DNS响应包
	err := d.handle.SetBPFFilter("udp and src port 53")
	if err != nil {
		gologger.Error().Msgf("设置BPF过滤器失败: %v", err)
		return
	}
	// 创建数据包源
	d.packetSource = gopacket.NewPacketSource(d.handle, d.handle.LinkType())
	d.packetSource.DecodeOptions.Lazy = true
	d.packetSource.DecodeOptions.NoCopy = true
	d.packetSource.DecodeOptions.SkipDecodeRecovery = true

	// 开始捕获数据包
	for {
		select {
		case <-d.stopChan:
			return
		case packet := <-d.packetSource.Packets():
			// 解析数据包
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer == nil {
				continue
			}
			udp, _ := udpLayer.(*layers.UDP)

			// 获取目标端口（即DNS请求的源端口）
			dstPort := int(udp.DstPort)

			// 查找对应的收集器
			d.collectorsMutex.RLock()
			collector, exists := d.collectors[dstPort]
			d.collectorsMutex.RUnlock()

			// 如果没有找到对应的收集器，继续处理下一个包
			if !exists || collector.IsDone() {
				continue
			}

			dnsLayer := packet.Layer(layers.LayerTypeDNS)
			if dnsLayer == nil {
				continue
			}
			dns, _ := dnsLayer.(*layers.DNS)

			// 只处理响应包
			if !dns.QR {
				continue
			}

			// 解析DNS响应
			for _, answer := range dns.Answers {
				result := &DnsResult{
					QueryID: dns.ID,
				}

				// 获取域名
				if len(dns.Questions) > 0 {
					result.Domain = string(dns.Questions[0].Name)
				}

				// 获取源标识
				d.queryMapMutex.RLock()
				result.Source = d.queryMap[dns.ID]
				d.queryMapMutex.RUnlock()

				// 解析IP地址
				switch answer.Type {
				case layers.DNSTypeA:
					result.IP = append(result.IP, answer.IP.String())
				case layers.DNSTypeAAAA:
					result.IP = append(result.IP, answer.IP.String())
				case layers.DNSTypeCNAME:
					result.CNAME = string(answer.CNAME)
				}

				// 将结果发送到收集器
				collector.Collect(result)
			}
		}
	}
}

func formatDNS(dns *layers.DNS) string {
	var result string
	result += fmt.Sprintf("ID: %d, QR: %t, OpCode: %d, AA: %t, TC: %t, RD: %t, RA: %t, Z: %d, ResponseCode: %d, QDCount: %d, ANCount: %d, NSCount: %d, ARCount: %d\n",
		dns.ID, dns.QR, dns.OpCode, dns.AA, dns.TC, dns.RD, dns.RA, dns.Z, dns.ResponseCode, dns.QDCount, dns.ANCount, dns.NSCount, dns.ARCount)

	// 打印问题部分
	result += "Questions:\n"
	for _, q := range dns.Questions {
		result += fmt.Sprintf("  Name: %s, Type: %d, Class: %d\n", string(q.Name), q.Type, q.Class)
	}

	// 打印应答部分
	result += "Answers:\n"
	for _, a := range dns.Answers {
		result += fmt.Sprintf("  Name: %s, Type: %d, Class: %d, TTL: %d, IP: %s, NS: %s, CNAME: %s, PTR: %s, TXTs: %v, SOA: %v, SRV: %v\n",
			string(a.Name), a.Type, a.Class, a.TTL, a.IP, string(a.NS), string(a.CNAME), string(a.PTR), a.TXTs, a.SOA, a.SRV)
	}

	return result
}

// sendDnsQuery 发送DNS查询
func (d *DnsDiscovery) sendDnsQuery(domain string, sourcePort int) error {
	// 等待速率限制器
	if d.rateLimiter != nil {
		d.rateLimiter.Wait()
	}
	// 为当前任务生成一个唯一的DNS查询ID
	dnsID := uint16(time.Now().UnixNano() & 0xFFFF)
	// 保存查询映射
	d.queryMapMutex.Lock()
	d.queryMap[dnsID] = fmt.Sprintf("%d", sourcePort)
	d.queryMapMutex.Unlock()
	// 发送DNS查询
	serverIndex := 0
	dnsServer := d.dnsServers[serverIndex%len(d.dnsServers)]
	// UDP layer
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(sourcePort),
		DstPort: layers.UDPPort(53),
	}
	dns := &layers.DNS{
		ID:      dnsID,
		QDCount: 1,
		RD:      true, //递归查询标识
	}
	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    d.sourceIP,
		DstIP:    dnsServer,
	}
	dns.Questions = append(dns.Questions,
		layers.DNSQuestion{
			Name:  []byte(domain),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		})
	_ = udp.SetNetworkLayerForChecksum(ipLayer)
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buffer, opts, d.ethLayer, ipLayer, udp, dns)
	if err != nil {
		gologger.Error().Msgf("Sync DNS Failed to serialize layers:%v", err)
		// 发送失败，移除查询映射
		d.queryMapMutex.Lock()
		delete(d.queryMap, dnsID)
		d.queryMapMutex.Unlock()
		// 从请求缓存中移除
		d.removeRequestFromCache(domain)
		return nil
	}
	// 发送 DNS 请求包
	err = d.handle.WritePacketData(buffer.Bytes())
	if err != nil {
		// 发送失败，移除查询映射
		d.queryMapMutex.Lock()
		delete(d.queryMap, dnsID)
		d.queryMapMutex.Unlock()
		// 从请求缓存中移除
		d.removeRequestFromCache(domain)
		return nil
	}
	return nil
}

// 处理DNS结果
func (d *DnsDiscovery) handleDnsResponse(packet gopacket.Packet) {
	// 解析DNS响应
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	dns, _ := dnsLayer.(*layers.DNS)
	if !dns.QR {
		return
	}
	// 获取查询ID
	id := dns.ID
	// 获取查询域名
	d.queryMapMutex.RLock()
	domain, ok := d.queryMap[id]
	d.queryMapMutex.RUnlock()
	if !ok {
		return
	}
	// 从查询映射中移除
	d.queryMapMutex.Lock()
	delete(d.queryMap, id)
	d.queryMapMutex.Unlock()

	// 从请求缓存中移除
	d.removeRequestFromCache(domain)

	// 处理DNS响应
	// ...其余代码保持不变
}

// 添加一个全局实例获取函数
var globalDnsDiscovery *DnsDiscovery
var globalDnsDiscoveryMutex sync.RWMutex

// SetDnsDiscoveryInstance 设置全局DNS发现实例
func SetDnsDiscoveryInstance(d *DnsDiscovery) {
	globalDnsDiscoveryMutex.Lock()
	defer globalDnsDiscoveryMutex.Unlock()
	globalDnsDiscovery = d
}

// GetDnsDiscoveryInstance 获取全局DNS发现实例
func GetDnsDiscoveryInstance() *DnsDiscovery {
	globalDnsDiscoveryMutex.RLock()
	defer globalDnsDiscoveryMutex.RUnlock()
	return globalDnsDiscovery
}

// 添加请求到缓存
func (d *DnsDiscovery) addRequestToCache(domain string, sourcePort int) {
	d.requestCacheLock.Lock()
	defer d.requestCacheLock.Unlock()

	// 创建新的缓存项
	item := &RequestCacheItem{
		Domain:     domain,
		SourcePort: sourcePort,
		SendTime:   time.Now(),
		RetryCount: 0,
		Next:       nil,
		Prev:       nil,
	}

	// 如果已存在，先从链表中移除
	if oldItem, exists := d.requestCache[domain]; exists {
		d.removeFromList(oldItem)
	}

	// 添加到Map
	d.requestCache[domain] = item

	// 添加到链表尾部（最新的请求）
	d.addToTail(item)
}

// 从缓存中移除请求
func (d *DnsDiscovery) removeRequestFromCache(domain string) {
	d.requestCacheLock.Lock()
	defer d.requestCacheLock.Unlock()

	// 从Map中获取缓存项
	item, exists := d.requestCache[domain]
	if !exists {
		return
	}

	// 从链表中移除
	d.removeFromList(item)

	// 从Map中移除
	delete(d.requestCache, domain)
}

// 添加缓存项到链表尾部
func (d *DnsDiscovery) addToTail(item *RequestCacheItem) {
	if d.cacheTail == nil { // 链表为空
		d.cacheHead = item
		d.cacheTail = item
		return
	}

	// 添加到尾部
	d.cacheTail.Next = item
	item.Prev = d.cacheTail
	d.cacheTail = item
}

// 从链表中移除缓存项
func (d *DnsDiscovery) removeFromList(item *RequestCacheItem) {
	// 处理前驱节点
	if item.Prev != nil {
		item.Prev.Next = item.Next
	} else { // 是头节点
		d.cacheHead = item.Next
	}

	// 处理后继节点
	if item.Next != nil {
		item.Next.Prev = item.Prev
	} else { // 是尾节点
		d.cacheTail = item.Prev
	}

	// 清除引用
	item.Next = nil
	item.Prev = nil
}

// 处理过期请求
func (d *DnsDiscovery) processExpiredRequests() {
	maxRetries := 2 // 最大重试次数
	for {
		select {
		case <-d.stopChan:
			return
		default:
			d.requestCacheLock.Lock()
			now := time.Now()
			expiredItems := make([]*RequestCacheItem, 0)

			// 从链表头部开始检查（最早的请求）
			current := d.cacheHead
			for current != nil && len(expiredItems) < 100 { // 限制每次处理的数量
				if now.Sub(current.SendTime) > d.timeout && current.RetryCount < maxRetries {
					// 记录过期的请求
					expiredItems = append(expiredItems, current)
					// 更新重试次数和发送时间
					current.RetryCount++
					current.SendTime = now
					// 将节点移动到链表尾部（更新后的请求）
					next := current.Next // 保存下一个节点
					d.removeFromList(current)
					d.addToTail(current)
					current = next // 继续处理下一个节点
				} else if current.RetryCount >= maxRetries {
					// 超过最大重试次数，从缓存中移除
					next := current.Next // 保存下一个节点
					domain := current.Domain
					d.removeFromList(current)
					delete(d.requestCache, domain)
					current = next // 继续处理下一个节点
				} else {
					// 如果当前请求未过期，后面的请求也不会过期（按时间顺序排列）
					break
				}
			}
			d.requestCacheLock.Unlock()

			// 重试过期请求
			for _, item := range expiredItems {
				// 非阻塞方式发送到重试通道
				d.retryQuery(item.Domain, item.SourcePort)
			}

			// 短暂休眠，避免CPU占用过高
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// processRetries 处理重试请求
func (d *DnsDiscovery) processRetries() {
	for {
		select {
		case <-d.stopChan:
			return
		case req := <-d.reqChan:
			// 处理重试请求
			err := d.sendDnsQuery(req.Domain, req.Source)
			if err != nil {
				gologger.Warning().Msgf("重试DNS查询失败: %s", err)
			}
		}
	}
}

// retryQuery 重试DNS查询
func (d *DnsDiscovery) retryQuery(domain string, sourcePort int) {
	req := &DNSRequest{
		Domain: domain,
		Source: sourcePort,
	}

	// 使用非阻塞方式发送到重试通道
	select {
	case d.reqChan <- req:
		// 成功发送到重试通道
		gologger.Debug().Msgf("重试DNS查询: %s", domain)
	default:
		// 通道已满，直接重试
		if d.rateLimiter != nil {
			d.rateLimiter.Wait() // 遵循速率限制
		}
		err := d.sendDnsQuery(domain, sourcePort)
		if err != nil {
			gologger.Warning().Msgf("直接重试DNS查询失败: %s", err)
		}
	}
}

// Stop 停止DNS发现
func (d *DnsDiscovery) Stop() {
	// 发送停止信号
	select {
	case <-d.stopChan:
		// 通道已关闭，无需重复关闭
	default:
		close(d.stopChan)
	}

	// 创建新的停止通道，以便后续扫描
	d.stopChan = make(chan struct{})
}

// Close 关闭DNS发现，释放资源
func (d *DnsDiscovery) Close() {
	d.Stop()

	d.captureMutex.Lock()
	defer d.captureMutex.Unlock()

	if d.handle != nil {
		d.handle.Close()
		d.handle = nil
	}
}
