package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRBAC_CheckPermissionWithRole(t *testing.T) {
	rbac := NewRBAC()

	tests := []struct {
		name       string
		role       Role
		permission Permission
		want       bool
	}{
		// Admin permissions
		{"Admin can view logs", RoleAdmin, PermissionAdminViewLogs, true},
		{"Admin can manage org", RoleAdmin, PermissionOrgManage, true},
		{"Admin can view video", RoleAdmin, PermissionVideoView, true},

		// Manager permissions
		{"Manager can manage users", RoleManager, PermissionOrgUserManage, true},
		{"Manager can view video", RoleManager, PermissionVideoView, true},
		{"Manager CANNOT view admin logs", RoleManager, PermissionAdminViewLogs, false},
		{"Manager CANNOT manage org settings", RoleManager, PermissionOrgManage, false},

		// User permissions
		{"User can view video", RoleUser, PermissionVideoView, true},
		{"User can edit own profile", RoleUser, PermissionUserEditProfile, true},
		{"User CANNOT manage users", RoleUser, PermissionOrgUserManage, false},
		{"User CANNOT manage org", RoleUser, PermissionOrgManage, false},
		{"User CANNOT view admin logs", RoleUser, PermissionAdminViewLogs, false},

		// Invalid role
		{"Unknown role has no permissions", "super_hacker", PermissionVideoView, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rbac.CheckPermissionWithRole(tt.role, tt.permission)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRBAC_CanManageRole(t *testing.T) {
	rbac := NewRBAC()

	tests := []struct {
		name       string
		userRole   Role
		targetRole Role
		want       bool
	}{
		// Admin hierarchy
		{"Admin can manage Admin", RoleAdmin, RoleAdmin, true},
		{"Admin can manage Manager", RoleAdmin, RoleManager, true},
		{"Admin can manage User", RoleAdmin, RoleUser, true},

		// Manager hierarchy
		{"Manager can manage User", RoleManager, RoleUser, true},
		{"Manager CANNOT manage Admin", RoleManager, RoleAdmin, false},
		{"Manager CANNOT manage Manager", RoleManager, RoleManager, false},

		// User hierarchy
		{"User CANNOT manage User", RoleUser, RoleUser, false},
		{"User CANNOT manage Manager", RoleUser, RoleManager, false},
		{"User CANNOT manage Admin", RoleUser, RoleAdmin, false},

		// Invalid roles
		{"Invalid role cannot manage", "hacker", RoleUser, false},
		{"Valid role cannot manage invalid role", RoleAdmin, "ghost", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rbac.CanManageRole(tt.userRole, tt.targetRole)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRBAC_GetRolePermissions(t *testing.T) {
	rbac := NewRBAC()

	// Проверяем, что метод возвращает список и он не пустой для валидной роли
	perms := rbac.GetRolePermissions(RoleUser)
	assert.NotEmpty(t, perms)
	assert.Contains(t, perms, PermissionVideoView)
	assert.NotContains(t, perms, PermissionOrgManage)

	// Проверяем для невалидной роли
	emptyPerms := rbac.GetRolePermissions("invalid_role")
	assert.Empty(t, emptyPerms)
}
