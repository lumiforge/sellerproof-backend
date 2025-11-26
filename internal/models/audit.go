package models

import "time"

// AuditLog represents an audit log entry returned via API
// @Description Audit trail entry with contextual metadata
type AuditLog struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	UserID       string                 `json:"user_id,omitempty"`
	OrgID        string                 `json:"org_id,omitempty"`
	ActionType   string                 `json:"action_type"`
	ActionResult string                 `json:"action_result"`
	IPAddress    string                 `json:"ip_address,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	Details      map[string]interface{} `json:"details,omitempty"`
}
