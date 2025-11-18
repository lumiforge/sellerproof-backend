package ydb

import (
	"context"
)

// Database определяет интерфейс для работы с базой данных
type Database interface {
	// Пользователи
	CreateUser(ctx context.Context, user *User) error
	GetUserByID(ctx context.Context, userID string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, userID string) error

	// Организации
	CreateOrganization(ctx context.Context, org *Organization) error
	GetOrganizationByID(ctx context.Context, orgID string) (*Organization, error)
	GetOrganizationsByOwner(ctx context.Context, ownerID string) ([]*Organization, error)
	UpdateOrganization(ctx context.Context, org *Organization) error

	// Членство в организациях
	CreateMembership(ctx context.Context, membership *Membership) error
	GetMembership(ctx context.Context, userID, orgID string) (*Membership, error)
	GetMembershipsByUser(ctx context.Context, userID string) ([]*Membership, error)
	GetMembershipsByOrg(ctx context.Context, orgID string) ([]*Membership, error)
	UpdateMembership(ctx context.Context, membership *Membership) error
	DeleteMembership(ctx context.Context, membershipID string) error

	// Тарифные планы
	GetPlanByID(ctx context.Context, planID string) (*Plan, error)
	GetAllPlans(ctx context.Context) ([]*Plan, error)

	// Подписки
	CreateSubscription(ctx context.Context, subscription *Subscription) error
	GetSubscriptionByID(ctx context.Context, subscriptionID string) (*Subscription, error)
	GetSubscriptionByUser(ctx context.Context, userID string) (*Subscription, error)
	GetSubscriptionByOrg(ctx context.Context, orgID string) (*Subscription, error)
	UpdateSubscription(ctx context.Context, subscription *Subscription) error
	CreateSubscriptionHistory(ctx context.Context, history *SubscriptionHistory) error
	GetSubscriptionHistory(ctx context.Context, subscriptionID string) ([]*SubscriptionHistory, error)

	// Email логи
	CreateEmailLog(ctx context.Context, log *EmailLog) error
	GetEmailLogsByUser(ctx context.Context, userID string) ([]*EmailLog, error)
	UpdateEmailLog(ctx context.Context, log *EmailLog) error

	// Refresh токены
	CreateRefreshToken(ctx context.Context, token *RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
	GetRefreshTokensByUser(ctx context.Context, userID string) ([]*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenHash string) error
	RevokeAllUserRefreshTokens(ctx context.Context, userID string) error
	CleanupExpiredTokens(ctx context.Context) error

	// Инициализация и миграции
	Initialize(ctx context.Context) error
	Close() error
}
