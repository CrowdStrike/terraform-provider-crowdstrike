package sweep

import (
	"io"
	"log"
	"os"

	"github.com/hashicorp/logutils"
)

var (
	logger      *log.Logger
	logFilter   *logutils.LevelFilter
	logLevels   = []logutils.LogLevel{"TRACE", "DEBUG", "INFO", "WARN", "ERROR"}
	minLogLevel = "INFO"
)

func init() {
	if envLevel := os.Getenv("SWEEP_LOG_LEVEL"); envLevel != "" {
		minLogLevel = envLevel
	}

	logFilter = &logutils.LevelFilter{
		Levels:   logLevels,
		MinLevel: logutils.LogLevel(minLogLevel),
		Writer:   os.Stderr,
	}

	logger = log.New(logFilter, "", log.LstdFlags)

	// Hijack the default logger to filter ALL log output (including Terraform framework logs)
	log.SetOutput(logFilter)
}

func Trace(format string, v ...interface{}) {
	logger.Printf("[TRACE] "+format, v...)
}

func Debug(format string, v ...interface{}) {
	logger.Printf("[DEBUG] "+format, v...)
}

func Info(format string, v ...interface{}) {
	logger.Printf("[INFO] "+format, v...)
}

func Warn(format string, v ...interface{}) {
	logger.Printf("[WARN] "+format, v...)
}

func Error(format string, v ...interface{}) {
	logger.Printf("[ERROR] "+format, v...)
}

func SetOutput(w io.Writer) {
	logFilter.Writer = w
	logger.SetOutput(logFilter)
	log.SetOutput(logFilter)
}

func SetMinLevel(level string) {
	logFilter.MinLevel = logutils.LogLevel(level)
}
