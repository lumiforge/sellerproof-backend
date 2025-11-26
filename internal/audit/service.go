package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/lumiforge/sellerproof-backend/internal/models"
	"github.com/lumiforge/sellerproof-backend/internal/rbac"
	"github.com/lumiforge/sellerproof-backend/internal/ydb"
)

const (
	ActionResultSuccess = "success"
	ActionResultFailure = "failure"
)

// Service coordinates audit logging and retrieval
// It ensures consistent defaults and shields handlers from storage specifics
type Service struct {
	db   ydb.Database
	rbac *rbac.RBAC
	log  *slog.Logger
}

// NewService builds an audit service instance
func NewService(db ydb.Database, rbac *rbac.RBAC, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{db: db, rbac: rbac, log: log}
}

// Record captures runtime context of a user action
type Record struct {
	ID           string
	Timestamp    time.Time
	UserID       *string
	OrgID        *string
	ActionType   string
	ActionResult string
	IPAddress    *string
	UserAgent    *string
	Details      map[string]any
}

// Filter describes query options for reading audit events
type Filter struct {
	UserID     string
	OrgID      string
	ActionType string
	Result     string
	From       *time.Time
	To         *time.Time
	Limit      int
}

// LogAction stores audit record synchronously
func (s *Service) LogAction(ctx context.Context, record Record) error {
	if record.ActionType == "" {
		return errors.New("action_type is required")
	}
	if record.ActionResult == "" {
		record.ActionResult = ActionResultSuccess
	}
	if record.ID == "" {
		record.ID = uuid.New().String()
	}
	if record.Timestamp.IsZero() {
		record.Timestamp = time.Now().UTC()
	}

	detailsJSON := "{}"
	if len(record.Details) > 0 {
		data, err := json.Marshal(record.Details)
		if err != nil {
			return fmt.Errorf("marshal details: %w", err)
		}
		detailsJSON = string(data)
	}

	ydbRecord := &ydb.AuditLog{
		ID:           record.ID,
		Timestamp:    record.Timestamp,
		UserID:       record.UserID,
		OrgID:        record.OrgID,
		ActionType:   record.ActionType,
		ActionResult: record.ActionResult,
		IPAddress:    record.IPAddress,
		UserAgent:    record.UserAgent,
		DetailsJSON:  detailsJSON,
	}

	if err := s.db.CreateAuditLog(ctx, ydbRecord); err != nil {
		s.log.Error("failed to write audit log", "error", err, "action", record.ActionType)
		return err
	}
	return nil
}

// ListAuditLogs fetches stored events matching filter
func (s *Service) ListAuditLogs(ctx context.Context, filter Filter) ([]*models.AuditLog, error) {
	ydbFilter := &ydb.AuditLogFilter{
		UserID:     filter.UserID,
		OrgID:      filter.OrgID,
		ActionType: filter.ActionType,
		Result:     filter.Result,
		From:       filter.From,
		To:         filter.To,
		Limit:      filter.Limit,
	}

	entries, err := s.db.ListAuditLogs(ctx, ydbFilter)
	if err != nil {
		return nil, err
	}

	result := make([]*models.AuditLog, 0, len(entries))
	for _, entry := range entries {
		var details map[string]any
		if entry.DetailsJSON != "" {
			if err := json.Unmarshal([]byte(entry.DetailsJSON), &details); err != nil {
				s.log.Warn("failed to unmarshal audit details", "error", err, "entry_id", entry.ID)
			}
		}

		modelEntry := &models.AuditLog{
			ID:           entry.ID,
			Timestamp:    entry.Timestamp,
			ActionType:   entry.ActionType,
			ActionResult: entry.ActionResult,
			Details:      details,
		}
		if entry.UserID != nil {
			modelEntry.UserID = *entry.UserID
		}
		if entry.OrgID != nil {
			modelEntry.OrgID = *entry.OrgID
		}
		if entry.IPAddress != nil {
			modelEntry.IPAddress = *entry.IPAddress
		}
		if entry.UserAgent != nil {
			modelEntry.UserAgent = *entry.UserAgent
		}
		result = append(result, modelEntry)
	}

	return result, nil
}
