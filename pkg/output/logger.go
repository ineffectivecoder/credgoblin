package output

import (
	"fmt"
	"log"
	"os"
	"time"
)

// Logger provides structured logging with colors and levels
type Logger struct {
	verbose bool
}

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
)

// NewLogger creates a new logger
func NewLogger(verbose bool) *Logger {
	return &Logger{
		verbose: verbose,
	}
}

// timestamp returns a formatted timestamp
func (l *Logger) timestamp() string {
	return time.Now().Format("15:04:05")
}

// Info logs an informational message
func (l *Logger) Info(message string) {
	fmt.Printf("%s[%s]%s [%s*%s] %s\n",
		colorGray, l.timestamp(), colorReset,
		colorBlue, colorReset,
		message,
	)
}

// Success logs a success message
func (l *Logger) Success(message string) {
	fmt.Printf("%s[%s]%s [%s+%s] %s\n",
		colorGray, l.timestamp(), colorReset,
		colorGreen, colorReset,
		message,
	)
}

// Warning logs a warning message
func (l *Logger) Warning(message string) {
	fmt.Printf("%s[%s]%s [%s!%s] %s\n",
		colorGray, l.timestamp(), colorReset,
		colorYellow, colorReset,
		message,
	)
}

// Error logs an error message
func (l *Logger) Error(message string) {
	fmt.Printf("%s[%s]%s [%s-%s] %s\n",
		colorGray, l.timestamp(), colorReset,
		colorRed, colorReset,
		message,
	)
}

// Debug logs a debug message (only if verbose is enabled)
func (l *Logger) Debug(message string) {
	if !l.verbose {
		return
	}
	fmt.Printf("%s[%s]%s [%sDBG%s] %s\n",
		colorGray, l.timestamp(), colorReset,
		colorCyan, colorReset,
		message,
	)
}

// Fatal logs a fatal error and exits
func (l *Logger) Fatal(message string) {
	fmt.Printf("%s[%s]%s [%s!%s] %s\n",
		colorGray, l.timestamp(), colorReset,
		colorRed, colorReset,
		message,
	)
	os.Exit(1)
}

// Print prints a message without any formatting
func (l *Logger) Print(message string) {
	fmt.Println(message)
}

// Printf prints a formatted message without any formatting
func (l *Logger) Printf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

// SetVerbose sets the verbose flag
func (l *Logger) SetVerbose(verbose bool) {
	l.verbose = verbose
}

// IsVerbose returns whether verbose logging is enabled
func (l *Logger) IsVerbose() bool {
	return l.verbose
}

// StdLogger returns a standard library logger that writes to this logger
func (l *Logger) StdLogger() *log.Logger {
	return log.New(os.Stdout, "", 0)
}
