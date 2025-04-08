package subdomain

import "github.com/projectdiscovery/gologger"

// Logger 定义日志接口
type Logger interface {
	// Debug 输出调试级别日志
	Debug(format string, args ...interface{})
	// Info 输出信息级别日志
	Info(format string, args ...interface{})
	// Warning 输出警告级别日志
	Warning(format string, args ...interface{})
	// Error 输出错误级别日志
	Error(format string, args ...interface{})
}

// DefaultLogger 默认日志实现，使用gologger
type DefaultLogger struct {
}

// NewDefaultLogger 创建一个新的默认日志实现
func NewDefaultLogger() *DefaultLogger {
	return &DefaultLogger{}
}

// Debug 输出调试级别日志
func (l *DefaultLogger) Debug(format string, args ...interface{}) {

	gologger.Debug().Msgf(format, args...)

}

// Info 输出信息级别日志
func (l *DefaultLogger) Info(format string, args ...interface{}) {

	gologger.Info().Msgf(format, args...)

}

// Warning 输出警告级别日志
func (l *DefaultLogger) Warning(format string, args ...interface{}) {
	gologger.Warning().Msgf(format, args...)

}

// Error 输出错误级别日志
func (l *DefaultLogger) Error(format string, args ...interface{}) {
	gologger.Error().Msgf(format, args...)
}

// NoopLogger 不输出任何日志的实现
type NoopLogger struct{}

// Debug 不执行任何操作
func (l *NoopLogger) Debug(format string, args ...interface{}) {}

// Info 不执行任何操作
func (l *NoopLogger) Info(format string, args ...interface{}) {}

// Warning 不执行任何操作
func (l *NoopLogger) Warning(format string, args ...interface{}) {}

// Error 不执行任何操作
func (l *NoopLogger) Error(format string, args ...interface{}) {}
