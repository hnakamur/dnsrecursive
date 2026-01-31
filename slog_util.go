package dnsrecursive

import (
	"io"
	"log/slog"
	"time"
)

func newSlogJSONHandlerAndLevel(w io.Writer) (slog.Handler, *slog.LevelVar) {
	var level = new(slog.LevelVar)
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			_ = groups
			if a.Key == slog.TimeKey {
				if t, ok := a.Value.Any().(time.Time); ok {
					// format timestamp with millisecond precision
					a.Value = slog.StringValue(t.Format("2006-01-02T15:04:05.000000"))
				}
			}
			return a
		},
	})
	return h, level
}
