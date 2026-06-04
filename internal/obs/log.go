// Package obs holds observability helpers (structured logging; metrics are a
// fan-out item).
package obs

import (
	"log/slog"
	"os"
	"strings"
)

// Setup installs a JSON slog handler as the default logger at the given level
// (debug|info|warn|error).
func Setup(level string) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	slog.SetDefault(slog.New(h))
}
