package logger

import (
	"context"
	"log/slog"
	"os"

	"github.com/lumiforge/sellerproof-backend/internal/telegram"
)

type TelegramHandler struct {
	slog.Handler
	tg *telegram.Client
}

func (h *TelegramHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelError && h.tg != nil {
		msg := r.Message
		go func() {
			_ = h.tg.SendAlert(msg)
		}()
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