package models

import (
	"encoding/json"
	"time"
)

// AuditLog представляет запись аудита в системе
// @Description	Audit log entry for user actions
type AuditLog struct {
	ID           string          `json:"id"`
	Timestamp    time.Time       `json:"timestamp"`
	UserID       string          `json:"user_id"`
	OrgID        string          `json:"org_id"`
	ActionType   string          `json:"action_type"`
	ActionResult string          `json:"action_result"`
	IPAddress    string          `json:"ip_address"`
	UserAgent    string          `json:"user_agent"`
	Details      json.RawMessage `json:"details"`
}

// AuditActionType содержит константы для типов действий
type AuditActionType string

const (
	// Authentication actions
	// AuditLoginSuccess AuditActionType = "login_success"
	// AuditLoginFailure AuditActionType = "login_failure"
	// AuditLogout       AuditActionType = "logout"

	// Registration actions
	AuditRegisterSuccess AuditActionType = "register_success"
	AuditEmailVerified   AuditActionType = "email_verified"

	// Video actions
	// AuditVideoUploadStart     AuditActionType = "video_upload_start"
	AuditVideoUploadComplete  AuditActionType = "video_upload_complete"
	AuditVideoRevoked         AuditActionType = "video_revoked"
	AuditVideoDownloadPrivate AuditActionType = "video_download_private"
	// AuditVideoDownloadPublic  AuditActionType = "video_download_public"

	// Organization actions
	AuditOrgUserInvite          AuditActionType = "org_user_invite"
	AuditOrgInvitationAccepted  AuditActionType = "org_invitation_accepted"
	AuditOrgRoleChanged         AuditActionType = "org_role_changed"
	AuditOrgMemberStatusChanged AuditActionType = "org_member_status_changed"
	AuditOrgDelete              AuditActionType = "org_delete"

	// Error actions
	// AuditAPIError         AuditActionType = "api_error"
	// AuditPermissionDenied AuditActionType = "permission_denied"
)

// AuditActionResult содержит константы для результатов действий
type AuditActionResult string

const (
	AuditResultSuccess AuditActionResult = "success"
	AuditResultFailure AuditActionResult = "failure"
)

// GetAuditLogs request model
// @Description	Request filters for audit logs listing
type GetAuditLogsRequest struct {
	UserID     string `query:"user_id"`
	OrgID      string `query:"org_id"`
	ActionType string `query:"action_type"`
	Result     string `query:"result"`
	From       string `query:"from"`
	To         string `query:"to"`
	Limit      int    `query:"limit"`
	Offset     int    `query:"offset"`
}

// GetAuditLogsResponse response for audit logs listing
// @Description	Audit logs list with pagination
type GetAuditLogsResponse struct {
	Logs   []*AuditLog `json:"logs"`
	Total  int64       `json:"total"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
}
