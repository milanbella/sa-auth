package logger

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

var std = log.New(os.Stderr, "", log.LstdFlags)

// LogErr logs the provided error (if non-nil) and returns it unchanged.
// It is meant to be used inline when propagating errors up the call stack.
func LogErr(err error) error {
	if err == nil {
		return nil
	}
	logErrorWithSkip(err, skipForPublicAPI)
	return err
}

// LogError logs a formatted error message and returns it as an error.
func LogError(format string, args ...interface{}) error {
	err := fmt.Errorf(format, args...)
	logErrorWithSkip(err, skipForPublicAPI)
	return err
}

// LogErrorf logs a formatted error message.
func LogErrorf(format string, args ...interface{}) {
	err := fmt.Errorf(format, args...)
	logErrorWithSkip(err, skipForPublicAPI)
}

// Fatal logs the provided error (if non-nil) and terminates the process.
func Fatal(err error) {
	if err == nil {
		return
	}
	logErrorWithSkip(err, skipForPublicAPI)
	os.Exit(1)
}

// Error logs the provided error (if non-nil).
func Error(err error) {
	if err == nil {
		return
	}
	logErrorWithSkip(err, skipForPublicAPI)
}

// Warn logs a warning message.
func Warn(format string, args ...interface{}) {
	logWithSkip("warning", skipForPublicAPI, fmt.Sprintf(format, args...))
}

// Info logs an informational message.
func Info(format string, args ...interface{}) {
	logWithSkip("info", skipForPublicAPI, fmt.Sprintf(format, args...))
}

const skipForPublicAPI = 3

func logErrorWithSkip(err error, skip int) {
	logWithSkip("error", skip, err.Error())
}

func logWithSkip(level string, skip int, message string) {
	pcs := make([]uintptr, 1)
	n := runtime.Callers(skip, pcs)
	if n == 0 {
		std.Printf("%s: %s", level, message)
		return
	}

	frame, _ := runtime.CallersFrames(pcs).Next()
	file := filepath.Base(frame.File)
	funcName := frame.Function
	if file == "" {
		file = "unknown"
	}
	if funcName == "" {
		funcName = "unknown"
	}

	std.Printf("%s:%s %s: %s", file, funcName, level, message)
}
