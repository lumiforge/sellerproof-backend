package rbac

import (
	"context"

	app_errors "github.com/lumiforge/sellerproof-backend/internal/errors"
)

// Permission представляет разрешение в системе
type Permission string

const (
	// Видео разрешения
	PermissionVideoView     Permission = "video:view"
	PermissionVideoUpload   Permission = "video:upload"
	PermissionVideoDelete   Permission = "video:delete"
	PermissionVideoRestore  Permission = "video:restore"
	PermissionVideoDownload Permission = "video:download"
	PermissionVideoShare    Permission = "video:share"
	PermissionVideoSearch   Permission = "video:search"

	// Организационные разрешения
	PermissionOrgView       Permission = "org:view"
	PermissionOrgManage     Permission = "org:manage"
	PermissionOrgUserManage Permission = "org:user_manage"
	PermissionOrgRoleManage Permission = "org:role_manage"

	// Пользовательские разрешения
	PermissionUserViewProfile Permission = "user:view_profile"
	PermissionUserEditProfile Permission = "user:edit_profile"

	// Административные разрешения
	PermissionAdminViewLogs   Permission = "admin:view_logs"
	PermissionAdminManageSubs Permission = "admin:manage_subscriptions"
)

// Role представляет роль в системе
type Role string

const (
	RoleAdmin   Role = "admin"
	RoleManager Role = "manager"
	RoleUser    Role = "user"
)

// RBAC управляет ролями и разрешениями
type RBAC struct {
	rolePermissions map[Role][]Permission
}

// NewRBAC создает новый RBAC менеджер
func NewRBAC() *RBAC {
	rbac := &RBAC{
		rolePermissions: make(map[Role][]Permission),
	}

	// Инициализация разрешений для ролей
	rbac.initializeRolePermissions()

	return rbac
}

// initializeRolePermissions инициализирует разрешения для каждой роли
func (r *RBAC) initializeRolePermissions() {
	// Admin - все разрешения
	r.rolePermissions[RoleAdmin] = []Permission{
		PermissionVideoView,
		PermissionVideoUpload,
		PermissionVideoDelete,
		PermissionVideoRestore,
		PermissionVideoDownload,
		PermissionVideoShare,
		PermissionVideoSearch,
		PermissionOrgView,
		PermissionOrgManage,
		PermissionOrgUserManage,
		PermissionOrgRoleManage,
		PermissionUserViewProfile,
		PermissionUserEditProfile,
		PermissionAdminViewLogs,
		PermissionAdminManageSubs,
	}

	// Manager - разрешения в рамках своей организации
	r.rolePermissions[RoleManager] = []Permission{
		PermissionVideoView,
		PermissionVideoUpload,
		PermissionVideoDelete,
		PermissionVideoRestore,
		PermissionVideoDownload,
		PermissionVideoShare,
		PermissionVideoSearch,
		PermissionOrgView,
		PermissionOrgUserManage,
		PermissionOrgRoleManage,
		PermissionUserViewProfile,
		PermissionUserEditProfile,
	}

	// User - базовые разрешения
	r.rolePermissions[RoleUser] = []Permission{
		PermissionVideoView,
		PermissionVideoDownload,
		PermissionVideoRestore,
		PermissionVideoShare,
		PermissionVideoSearch,
		PermissionUserViewProfile,
		PermissionUserEditProfile,
	}
}

// CheckPermission проверяет, имеет ли пользователь указанное разрешение
func (r *RBAC) CheckPermission(ctx context.Context, userID, orgID string, permission Permission) (bool, error) {
	// В реальном приложении здесь нужно получить роль пользователя из базы данных
	// Для упрощения используем контекст или передаем роль напрямую

	// Получаем роль из контекста (если установлена)
	if roleValue := ctx.Value("user_role"); roleValue != nil {
		if role, ok := roleValue.(Role); ok {
			return r.hasPermission(role, permission), nil
		}
	}

	// Если роль не найдена в контексте, возвращаем false
	return false, app_errors.ErrUserRoleNotFoundInContext
}

// CheckPermissionWithRole проверяет разрешение для указанной роли
func (r *RBAC) CheckPermissionWithRole(role Role, permission Permission) bool {
	return r.hasPermission(role, permission)
}

// hasPermission проверяет, имеет ли роль указанное разрешение
func (r *RBAC) hasPermission(role Role, permission Permission) bool {
	permissions, exists := r.rolePermissions[role]
	if !exists {
		return false
	}

	for _, p := range permissions {
		if p == permission {
			return true
		}
	}

	return false
}

// GetRolePermissions возвращает все разрешения для роли
func (r *RBAC) GetRolePermissions(role Role) []Permission {
	permissions, exists := r.rolePermissions[role]
	if !exists {
		return []Permission{}
	}

	// Возвращаем копию среза для безопасности
	result := make([]Permission, len(permissions))
	copy(result, permissions)
	return result
}

// GetAllRoles возвращает все доступные роли
func (r *RBAC) GetAllRoles() []Role {
	return []Role{RoleAdmin, RoleManager, RoleUser}
}

// GetAllPermissions возвращает все доступные разрешения
func (r *RBAC) GetAllPermissions() []Permission {
	allPermissions := make(map[Permission]bool)

	for _, permissions := range r.rolePermissions {
		for _, permission := range permissions {
			allPermissions[permission] = true
		}
	}

	result := make([]Permission, 0, len(allPermissions))
	for permission := range allPermissions {
		result = append(result, permission)
	}

	return result
}

// RoleHierarchy определяет иерархию ролей
var RoleHierarchy = map[Role]int{
	RoleUser:    1,
	RoleManager: 2,
	RoleAdmin:   3,
}

// CanManageRole проверяет, может ли пользователь с ролью userRole управлять ролью targetRole
func (r *RBAC) CanManageRole(userRole Role, targetRole Role) bool {
	_, userExists := RoleHierarchy[userRole]
	_, targetExists := RoleHierarchy[targetRole]

	if !userExists || !targetExists {
		return false
	}

	// Admin может управлять всеми
	if userRole == RoleAdmin {
		return true
	}

	// Manager может управлять только User
	if userRole == RoleManager && targetRole == RoleUser {
		return true
	}

	// User не может управлять другими ролями
	return false
}

// IsValidRole проверяет, является ли роль валидной
func (r *RBAC) IsValidRole(role Role) bool {
	_, exists := r.rolePermissions[role]
	return exists
}

// IsValidPermission проверяет, является ли разрешение валидным
func (r *RBAC) IsValidPermission(permission Permission) bool {
	for _, permissions := range r.rolePermissions {
		for _, p := range permissions {
			if p == permission {
				return true
			}
		}
	}
	return false
}
