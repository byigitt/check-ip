package logger

import (
	"fmt"
	"strings"
	"time"
)

// LogLevel represents different log levels
type LogLevel int

const (
	// LevelError for error messages
	LevelError LogLevel = iota
	// LevelSuccess for success messages
	LevelSuccess
	// LevelInfo for informational messages
	LevelInfo
	// LevelWarning for warning messages
	LevelWarning
	// LevelInit for initialization messages
	LevelInit
)

// GetTimestamp returns the current time formatted as YYYY-MM-DD HH:MM:SS
func GetTimestamp() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// LogWithLevel logs a message with the specified log level and optional error
func LogWithLevel(level LogLevel, message string, err error) {
	timestamp := GetTimestamp()
	var prefix string

	switch level {
	case LevelError:
		prefix = "[!]"
	case LevelSuccess:
		prefix = "[+]"
	case LevelInfo:
		prefix = "[~]"
	case LevelWarning:
		prefix = "[-]"
	case LevelInit:
		prefix = "[*]"
	}

	// Convert message to lowercase
	message = strings.ToLower(message)

	// Format the message
	logMessage := fmt.Sprintf("%s [%s] %s", prefix, timestamp, message)

	// Add error if provided
	if err != nil {
		// Keep error message in original case
		logMessage += fmt.Sprintf(" => %v", err)
	}

	fmt.Println(logMessage)
}

// Error logs an error message
func Error(message string, err error) {
	LogWithLevel(LevelError, message, err)
}

// Success logs a success message
func Success(message string) {
	LogWithLevel(LevelSuccess, message, nil)
}

// Info logs an informational message
func Info(message string) {
	LogWithLevel(LevelInfo, message, nil)
}

// Warning logs a warning message
func Warning(message string) {
	LogWithLevel(LevelWarning, message, nil)
}

// Init logs an initialization message
func Init(message string) {
	LogWithLevel(LevelInit, message, nil)
}

// ErrorWithoutErr logs an error message without an error object
func ErrorWithoutErr(message string) {
	LogWithLevel(LevelError, message, nil)
}
