// Package subdomain 提供子域名扫描功能
package subdomain

import (
	"time"
)

// 默认配置
var (
	DefaultTimeout = 5 * time.Second
	DefaultRate    = 1000 // 每秒请求数
	DefaultBurst   = 1000 // 突发请求数
)

// DefaultDnsServers 默认DNS服务器
var DefaultDnsServers = []string{
	"1.1.1.1",        // Cloudflare DNS
	"9.9.9.9",        // Quad9 DNS
	"208.67.222.222", // OpenDNS
	"8.8.8.8",        // Google DNS
}

// NewDefaultDnsDiscovery 创建一个使用默认配置的DNS发现实例
func NewDefaultDnsDiscovery() *DnsDiscovery {
	return NewDnsDiscovery(
		WithTimeout(DefaultTimeout),
		WithDnsServers(DefaultDnsServers),
		WithRateLimiter(NewTokenBucketLimiter(DefaultRate, DefaultBurst)),
		WithLogger(NewDefaultLogger()),
	)
}
