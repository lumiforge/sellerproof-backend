// internal/plan/mock_database_test.go
package plan

import (
	"context"
	"errors"
	"time"

	"github.com/lumiforge/sellerproof-backend/internal/models"
	"github.com/lumiforge/sellerproof-backend/internal/ydb"
)

type mockDatabase struct {
	plans []*ydb.Plan
	err   error
}

// Пользователи
func (m *mockDatabase) CreateUser(ctx context.Context, user *ydb.User) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) GetUserByID(ctx context.Context, userID string) (*ydb.User, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) GetUserByEmail(ctx context.Context, email string) (*ydb.User, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) UpdateUser(ctx context.Context, user *ydb.User) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) DeleteUser(ctx context.Context, userID string) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) UpdateUserPasswordResetInfo(ctx context.Context, userID string, code string, expiresAt time.Time) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) UpdateUserPassword(ctx context.Context, userID string, passwordHash string) error {
	return errors.New("not implemented")
}

// Организации
func (m *mockDatabase) CreateOrganization(ctx context.Context, org *ydb.Organization) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) GetOrganizationByID(ctx context.Context, orgID string) (*ydb.Organization, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) GetOrganizationsByIDs(ctx context.Context, orgIDs []string) ([]*ydb.Organization, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) GetOrganizationsByOwner(ctx context.Context, ownerID string) ([]*ydb.Organization, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) UpdateOrganization(ctx context.Context, org *ydb.Organization) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) DeleteOrganizationTx(ctx context.Context, orgID string) error {
	return errors.New("not implemented")
}

// Членство в организациях
func (m *mockDatabase) CreateMembership(ctx context.Context, membership *ydb.Membership) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) GetMembership(ctx context.Context, userID, orgID string) (*ydb.Membership, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) GetMembershipsByUser(ctx context.Context, userID string) ([]*ydb.Membership, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) GetMembershipsByOrg(ctx context.Context, orgID string) ([]*ydb.Membership, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) UpdateMembership(ctx context.Context, membership *ydb.Membership) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) DeleteMembership(ctx context.Context, membershipID string) error {
	return errors.New("not implemented")
}

// Тарифные планы
func (m *mockDatabase) GetPlanByID(ctx context.Context, planID string) (*ydb.Plan, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) GetAllPlans(ctx context.Context) ([]*ydb.Plan, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.plans, nil
}

// Подписки
func (m *mockDatabase) CreateSubscription(ctx context.Context, subscription *ydb.Subscription) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) GetSubscriptionByUser(ctx context.Context, userID string) (*ydb.Subscription, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) UpdateSubscription(ctx context.Context, subscription *ydb.Subscription) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) CreateSubscriptionHistory(ctx context.Context, history *ydb.SubscriptionHistory) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) GetSubscriptionHistory(ctx context.Context, subscriptionID string) ([]*ydb.SubscriptionHistory, error) {
	return nil, errors.New("not implemented")
}

// Транзакционная регистрация
func (m *mockDatabase) RegisterUserTx(ctx context.Context, user *ydb.User, org *ydb.Organization, membership *ydb.Membership, subscription *ydb.Subscription, invitationID string) error {
	return errors.New("not implemented")
}

// Email логи
func (m *mockDatabase) CreateEmailLog(ctx context.Context, log *ydb.EmailLog) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) GetEmailLogsByUser(ctx context.Context, userID string) ([]*ydb.EmailLog, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) UpdateEmailLog(ctx context.Context, log *ydb.EmailLog) error {
	return errors.New("not implemented")
}

// Refresh токены
func (m *mockDatabase) CreateRefreshToken(ctx context.Context, token *ydb.RefreshToken) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) GetRefreshToken(ctx context.Context, tokenHash string) (*ydb.RefreshToken, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) GetRefreshTokensByUser(ctx context.Context, userID string) ([]*ydb.RefreshToken, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) CleanupExpiredTokens(ctx context.Context) error {
	return errors.New("not implemented")
}

// Приглашения
func (m *mockDatabase) CreateInvitation(ctx context.Context, invitation *ydb.Invitation) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) GetInvitationByID(ctx context.Context, invitationID string) (*ydb.Invitation, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) GetInvitationByCode(ctx context.Context, code string) (*ydb.Invitation, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) GetInvitationByEmail(ctx context.Context, orgID, email string) (*ydb.Invitation, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) GetInvitationsByOrg(ctx context.Context, orgID string) ([]*ydb.Invitation, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) UpdateInvitationStatus(ctx context.Context, invitationID, status string) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) UpdateInvitationStatusWithAcceptTime(ctx context.Context, invitationID, status string, acceptedAt time.Time) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) DeleteInvitation(ctx context.Context, invitationID string) error {
	return errors.New("not implemented")
}

// Видео
func (m *mockDatabase) CreateVideo(ctx context.Context, video *ydb.Video) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) GetVideo(ctx context.Context, videoID string) (*ydb.Video, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) UpdateVideo(ctx context.Context, video *ydb.Video) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) UpdateVideoStatus(ctx context.Context, videoID, status, publicURL string) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) GetStorageUsage(ctx context.Context, ownerID string, subscriptionStartDate time.Time) (int64, error) {
	return 0, errors.New("not implemented")
}

func (m *mockDatabase) GetVideoByShareToken(ctx context.Context, token string) (*ydb.Video, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) SearchVideos(ctx context.Context, orgID, userID, query string, limit, offset int) ([]*ydb.Video, int64, error) {
	return nil, 0, errors.New("not implemented")
}

// Публичные шаринги видео
func (m *mockDatabase) CreatePublicVideoShare(ctx context.Context, share *ydb.PublicVideoShare) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) GetPublicVideoShareByToken(ctx context.Context, token string) (*ydb.PublicVideoShare, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) GetActivePublicVideoShare(ctx context.Context, videoID string) (*ydb.PublicVideoShare, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDatabase) IncrementAccessCount(ctx context.Context, token string) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) RevokePublicVideoShare(ctx context.Context, videoID, userID string) error {
	return errors.New("not implemented")
}

// Аудит
func (m *mockDatabase) InsertAuditLog(ctx context.Context, auditLog *models.AuditLog) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) GetAuditLogs(ctx context.Context, filters map[string]interface{}, limit, offset int) ([]*models.AuditLog, int64, error) {
	return nil, 0, errors.New("not implemented")
}

// Инициализация и миграции
func (m *mockDatabase) Initialize(ctx context.Context) error {
	return errors.New("not implemented")
}

func (m *mockDatabase) Close() error {
	return nil
}

func (m *mockDatabase) PublishVideoTx(ctx context.Context, share *ydb.PublicVideoShare, videoID, publicURL, status string) error {
	return errors.New("not implemented")
}
