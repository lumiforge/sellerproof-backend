package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/lumiforge/sellerproof-backend/internal/models"
	"github.com/lumiforge/sellerproof-backend/internal/ydb"
)

// Service handles audit logging
type Service struct {
	db ydb.Database
}

// NewService creates a new audit service
func NewService(db ydb.Database) *Service {
	return &Service{
		db: db,
	}
}

// LogActionDetails contains details for an audit action
// Can include various fields depending on the action type
// Details are stored as JSON in the audit log

// LogAction logs an audit action to the database
// Errors in logging are logged but don't interrupt the operation
func (s *Service) LogAction(
	ctx context.Context,
	userID string,
	orgID string,
	actionType models.AuditActionType,
	actionResult models.AuditActionResult,
	ipAddress string,
	userAgent string,
	details map[string]interface{},
) error {
	// Handle nil details
	if details == nil {
		details = make(map[string]interface{})
	}

	// Convert details to JSON
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		slog.Error("Failed to marshal audit details", "error", err, "action_type", actionType)
		detailsJSON = []byte("{}")
	}

	auditLog := &models.AuditLog{
		ID:           uuid.New().String(),
		Timestamp:    time.Now().UTC(),
		UserID:       userID,
		OrgID:        orgID,
		ActionType:   string(actionType),
		ActionResult: string(actionResult),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		Details:      detailsJSON,
	}

	// Save to database
	if err := s.db.InsertAuditLog(ctx, auditLog); err != nil {
		slog.Error("Failed to insert audit log",
			"error", err,
			"user_id", userID,
			"org_id", orgID,
			"action_type", actionType,
		)
		// Don't return error - logging failures shouldn't interrupt operations
		return nil
	}

	return nil
}

// GetLogs retrieves audit logs with filtering and pagination
func (s *Service) GetLogs(
	ctx context.Context,
	filters map[string]interface{},
	limit int,
	offset int,
) ([]*models.AuditLog, int64, error) {
	if limit > 1000 {
		limit = 1000
	}
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	return s.db.GetAuditLogs(ctx, filters, limit, offset)
}
