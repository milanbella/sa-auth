package logger

import (
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
	logWithSkip(err, 3)
	return err
}

// Fatal logs the provided error (if non-nil) and terminates the process.
func Fatal(err error) {
	if err == nil {
		return
	}
	logWithSkip(err, 3)
	os.Exit(1)
}

// Error logs the provided error (if non-nil).
func Error(err error) {
	if err == nil {
		return
	}
	logWithSkip(err, 3)
}

func logWithSkip(err error, skip int) {
	pcs := make([]uintptr, 1)
	n := runtime.Callers(skip, pcs)
	if n == 0 {
		std.Printf("error: %v", err)
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

	std.Printf("%s:%s error: %v", file, funcName, err)
}
