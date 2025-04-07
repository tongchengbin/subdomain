## 全网最快的子域名扫描工具

* 基于GoPacket 无状态扫描
* 高性能DNS爆破技术
* 高并发、低资源占用
* 可作为独立工具包集成到其他系统

## 功能特性

### 扫描方法

- **DNS爆破**：使用字典对目标域名进行暴力枚举
  - 支持自定义字典
  - 支持递归扫描
  - 通配符检测和过滤

- **DNS区域传送**：尝试DNS区域传送获取子域名
  - 自动检测目标域名的NS服务器
  - 区域传送结果解析

### 核心优势

- **高性能**：基于Go语言和GoPacket实现的无状态扫描
- **低资源占用**：优化的内存管理和并发控制
- **高可靠性**：结果验证和通配符过滤
- **易扩展**：插件化架构，支持自定义扫描方法

## 快速开始

### 安装

```bash
go get github.com/risk-radar/subdomain
```

### 基本用法

```go
package main

import (
    "fmt"
    "github.com/risk-radar/subdomain"
)

func main() {
    // 创建扫描器实例
    scanner := subdomain.NewScanner()
    
    // 设置扫描选项
    options := &subdomain.ScanOptions{
        Concurrency: 100,
        Timeout: 5,
        WordlistPath: "wordlists/default.txt",
        RecursiveScan: true,
        VerifyResults: true,
        FilterWildcard: true,
    }
    
    // 执行扫描
    results, err := scanner.Scan("example.com", options)
    if err != nil {
        fmt.Printf("扫描错误: %v\n", err)
        return
    }
    
    // 处理结果
    for _, subdomain := range results {
        fmt.Printf("发现子域名: %s (IP: %v)\n", subdomain.Name, subdomain.IP)
    }
}
```

## 与risk_scheduler集成

### 作为执行器集成

```go
// 在risk_scheduler的executor包中实现
type SubdomainExecutor struct {
    scanner subdomain.Scanner
}

func NewSubdomainExecutor() *SubdomainExecutor {
    return &SubdomainExecutor{
        scanner: subdomain.NewScanner(),
    }
}

func (e *SubdomainExecutor) Execute(task *Task) (*Result, error) {
    // 将任务参数转换为扫描选项
    options := &subdomain.ScanOptions{
        Concurrency: task.Config.Concurrency,
        Timeout: task.Config.Timeout,
        WordlistPath: task.Config.WordlistPath,
        // 其他选项...
    }
    
    // 执行扫描
    subdomains, err := e.scanner.Scan(task.Target, options)
    if err != nil {
        return nil, err
    }
    
    // 将结果转换为任务结果格式
    result := &Result{
        TaskID: task.ID,
        Status: "completed",
        Data: convertSubdomainsToResultData(subdomains),
    }
    
    return result, nil
}
```

## API参考

### 核心接口

#### Scanner

```go
// Scanner接口定义
type Scanner interface {
    // 扫描单个域名
    Scan(domain string, options *ScanOptions) ([]Subdomain, error)
    // 批量扫描多个域名
    BatchScan(domains []string, options *ScanOptions) (map[string][]Subdomain, error)
    // 停止正在进行的扫描
    Stop()
}
```

#### Subdomain

```go
// 子域名结构体
type Subdomain struct {
    Name         string   // 子域名名称
    IP           []string // 解析到的IP地址
    CNAME        string   // CNAME记录
    IsWildcard   bool     // 是否为通配符解析
    IsAlive      bool     // 是否存活
    ResponseTime int64    // 响应时间(ms)
}
```

#### ScanOptions

```go
// 扫描选项
type ScanOptions struct {
    Timeout         int      // 超时时间(秒)
    Concurrency     int      // 并发数
    Resolvers       []string // 自定义DNS解析器
    WordlistPath    string   // 字典路径
    RecursiveScan   bool     // 是否递归扫描
    VerifyResults   bool     // 是否验证结果
    FilterWildcard  bool     // 是否过滤通配符
}
```

### 扩展接口

#### 自定义DNS解析器

```go
// DNS解析器接口
type Resolver interface {
    Resolve(domain string) ([]string, error)
    ResolveWithTimeout(domain string, timeout time.Duration) ([]string, error)
}

// 设置自定义解析器
func (s *DefaultScanner) SetResolver(resolver Resolver) {
    s.resolver = resolver
}
```

## 性能优化

- **并发控制**：自适应并发控制，根据系统资源和目标响应情况调整
- **内存管理**：使用对象池减少GC压力
- **结果缓存**：缓存中间结果避免重复计算
- **DNS优化**：使用高效的DNS解析库和本地缓存
- **无状态扫描**：基于GoPacket的无状态DNS扫描，大幅提高性能

## 配置示例

```yaml
# 子域名扫描配置示例
scanner:
  concurrency: 200
  timeout: 5
  resolvers:
    - "8.8.8.8:53"
    - "1.1.1.1:53"
  wordlist: "wordlists/large.txt"
  recursive: true
  verify_results: true
  filter_wildcard: true
```

## 贡献指南

欢迎贡献代码、报告问题或提出改进建议。请遵循以下步骤：

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件#   s u b d o m a i n  
 