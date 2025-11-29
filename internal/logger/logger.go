package logger

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/lumiforge/sellerproof-backend/internal/telegram"
)

type TelegramHandler struct {
	slog.Handler
	tg *telegram.Client
}

func (h *TelegramHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelError && h.tg != nil {
		var sb strings.Builder
		sb.WriteString(r.Message)

		r.Attrs(func(a slog.Attr) bool {
			sb.WriteString(fmt.Sprintf(" | %s: %v", a.Key, a.Value.Any()))
			return true
		})

		fullMessage := sb.String()
		if err := h.tg.SendAlert(fullMessage); err != nil {
			os.Stderr.WriteString("Failed to send telegram alert: " + err.Error() + "\n")
		}
	}
	return h.Handler.Handle(ctx, r)
}

func (h *TelegramHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &TelegramHandler{
		Handler: h.Handler.WithAttrs(attrs),
		tg:      h.tg,
	}
}

func (h *TelegramHandler) WithGroup(name string) slog.Handler {
	return &TelegramHandler{
		Handler: h.Handler.WithGroup(name),
		tg:      h.tg,
	}
}

func New(tg *telegram.Client) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	jsonHandler := slog.NewJSONHandler(os.Stdout, opts)
	tgHandler := &TelegramHandler{
		Handler: jsonHandler,
		tg:      tg,
	}
	return slog.New(tgHandler)
}

type ctxKey struct{}

func WithContext(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}
