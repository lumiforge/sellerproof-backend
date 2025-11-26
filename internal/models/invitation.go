package models

// InviteUserRequest represents a request to invite a user to organization
// @Description	Invite user request with email and role
type InviteUserRequest struct {
	Email string `json:"email" validate:"required,email"`
	Role  string `json:"role" validate:"required,oneof=user manager admin"`
	OrgID string `json:"org_id" validate:"required"`
}

// InviteUserResponse represents a response for user invitation
// @Description	Invite user response with invitation details
type InviteUserResponse struct {
	InvitationID string `json:"invitation_id"`
	InviteCode   string `json:"invite_code"`
	ExpiresAt    int64  `json:"expires_at"`
	Email        string `json:"email"`
	Role         string `json:"role"`
}

// AcceptInvitationRequest represents a request to accept invitation
// @Description	Accept invitation request with invite code
type AcceptInvitationRequest struct {
	InviteCode string `json:"invite_code" validate:"required"`
}

// AcceptInvitationResponse represents a response for accepting invitation
// @Description	Accept invitation response with membership details
type AcceptInvitationResponse struct {
	MembershipID string `json:"membership_id"`
	OrgID        string `json:"org_id"`
	Role         string `json:"role"`
	Message      string `json:"message"`
}

// ListInvitationsResponse represents a list of invitations
// @Description	List of invitations for organization
type ListInvitationsResponse struct {
	Invitations []*InvitationInfo `json:"invitations"`
	Total       int               `json:"total"`
}

// InvitationInfo represents invitation information
// @Description	Invitation details
type InvitationInfo struct {
	InvitationID string `json:"invitation_id"`
	Email        string `json:"email"`
	Role         string `json:"role"`
	Status       string `json:"status"` // "pending", "accepted", "expired", "cancelled"
	InvitedBy    string `json:"invited_by"`
	CreatedAt    int64  `json:"created_at"`
	ExpiresAt    int64  `json:"expires_at"`
	AcceptedAt   *int64 `json:"accepted_at,omitempty"`
}

// UpdateMemberRoleRequest represents a request to update member role
// @Description	Update member role request
type UpdateMemberRoleRequest struct {
	NewRole string `json:"new_role" validate:"required,oneof=user manager admin"`
}

// MemberInfo represents organization member information
// @Description	Organization member details
type MemberInfo struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	FullName  string `json:"full_name"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	JoinedAt  int64  `json:"joined_at"`
	InvitedBy string `json:"invited_by"`
}

// ListMembersResponse represents a list of organization members
// @Description	List of organization members
type ListMembersResponse struct {
	Members []*MemberInfo `json:"members"`
	Total   int           `json:"total"`
}
