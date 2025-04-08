# Subdomain Scanner

高性能的子域名扫描库，基于无状态DNS扫描技术，专为大规模子域名发现设计。

## 功能特点

- **高性能设计**：使用无状态DNS扫描技术，避免传统DNS解析的开销
- **速率限制**：基于令牌桶算法的速率限制器，支持全局共享限制
- **DNS优化**：
  - 多DNS服务器轮询机制，将请求分流到多个DNS服务器
  - 丢包重试机制，最多重试2次，超时自动切换到备用服务器
- **高效缓存**：采用链表+Map的复合数据结构，优化过期请求处理
- **错误处理**：容错处理设计，单个子域名查询失败不影响整体扫描
- **资源优化**：共享数据包捕获器，减少资源占用

## 安装

```bash
go get github.com/tongchengbin/subdomain
```

## 快速开始

### 基本使用

```go
package main

import (
    "fmt"
    "github.com/tongchengbin/subdomain"
)

func main() {
    // 创建默认配置的DNS发现实例
    scanner := subdomain.NewDefaultDnsDiscovery()
    
    // 扫描指定域名的子域名
    domains := []string{"example.com", "test.example.com"}
    results := scanner.ScanWithDomains(domains)
    
    // 处理结果
    for _, result := range results {
        fmt.Printf("域名: %s, IP: %v\n", result.Domain, result.IP)
    }
    
    // 关闭扫描器，释放资源
    scanner.Close()
}
```

### 使用字典扫描子域名

```go
package main

import (
    "fmt"
    "github.com/tongchengbin/subdomain"
)

func main() {
    scanner := subdomain.NewDefaultDnsDiscovery()
    
    // 准备字典
    wordlist := []string{"www", "mail", "ftp", "admin", "blog"}
    
    // 扫描子域名
    results := scanner.ScanWithWordlist("example.com", wordlist)
    
    // 处理结果
    for _, result := range results {
        fmt.Printf("发现子域名: %s, IP: %v\n", result.Domain, result.IP)
    }
    
    scanner.Close()
}
```

### 使用回调函数处理结果

```go
package main

import (
    "fmt"
    "github.com/tongchengbin/subdomain"
)

func main() {
    scanner := subdomain.NewDefaultDnsDiscovery()
    
    // 定义回调函数
    callback := func(result *subdomain.DnsResult) {
        fmt.Printf("实时发现: %s -> %v\n", result.Domain, result.IP)
    }
    
    // 使用回调函数扫描
    wordlist := []string{"www", "mail", "api", "dev", "test"}
    scanner.ScanWithCallback("example.com", wordlist, callback)
    
    scanner.Close()
}
```

## 自定义配置

### 自定义DNS服务器

```go
scanner := subdomain.NewDnsDiscovery(
    subdomain.WithDnsServers([]string{
        "8.8.8.8",       // Google DNS
        "1.1.1.1",       // Cloudflare DNS
        "114.114.114.114" // 国内DNS
    }),
)
```

### 自定义超时时间

```go
scanner := subdomain.NewDnsDiscovery(
    subdomain.WithTimeout(10 * time.Second),
)
```

### 自定义速率限制

```go
// 创建速率限制器：每秒2000请求，突发上限3000
limiter := subdomain.NewTokenBucketLimiter(2000, 3000)

scanner := subdomain.NewDnsDiscovery(
    subdomain.WithRateLimiter(limiter),
)
```

### 全局共享速率限制器

```go
// 获取或创建名为"shared"的全局限制器
limiter := subdomain.GetGlobalLimiter("shared", 1000, 1000)

// 更新全局限制器配置
subdomain.UpdateGlobalLimiter("shared", 2000, 2000)

// 在多个扫描器中使用同一个限制器
scanner1 := subdomain.NewDnsDiscovery(
    subdomain.WithRateLimiter(limiter),
)

scanner2 := subdomain.NewDnsDiscovery(
    subdomain.WithRateLimiter(limiter),
)
```

## 高级用法

### 批量结果收集

```go
package main

import (
    "fmt"
    "github.com/tongchengbin/subdomain"
    "time"
)

func main() {
    scanner := subdomain.NewDefaultDnsDiscovery()
    
    // 创建批量结果收集器
    sourcePort, _ := subdomain.GetFreePort()
    collector := subdomain.NewBatchResultCollector(sourcePort, nil, 5*time.Second)
    
    // 注册收集器
    scanner.RegisterCollector(sourcePort, collector)
    
    // 准备域名列表
    domains := []string{"example.com", "test.example.com"}
    
    // 为每个域名发送DNS查询
    for _, domain := range domains {
        collector.AddPendingQuery(domain)
        scanner.sendDnsQuery(domain, sourcePort)
    }
    
    // 等待结果收集完成
    collector.Wait(10 * time.Second)
    
    // 获取结果
    results := collector.GetResults()
    for _, result := range results {
        fmt.Printf("域名: %s, IP: %v\n", result.Domain, result.IP)
    }
    
    // 清理资源
    collector.Close()
    scanner.UnregisterCollector(sourcePort)
    scanner.Close()
}
```

## 性能优化

- 使用共享的全局速率限制器可以在多个扫描任务间平衡资源使用
- 适当调整速率限制和突发值，根据网络条件和目标DNS服务器的承受能力
- 对于大规模扫描，建议使用批量结果收集器，提高效率
- 使用多个DNS服务器可以提高扫描成功率和性能

## 注意事项

- 请合法、合规地使用本工具，仅用于授权的安全测试
- 高速扫描可能会对目标DNS服务器造成压力，请合理设置速率限制
- 某些网络环境可能需要特殊配置，如代理或VPN

## 许可证

MIT License
