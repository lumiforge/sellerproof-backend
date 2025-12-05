package audit

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/lumiforge/sellerproof-backend/internal/models"
	"github.com/lumiforge/sellerproof-backend/internal/ydb/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestService_LogAction_Success(t *testing.T) {
	// Arrange
	mockDB := new(mocks.Database)
	service := NewService(mockDB)
	ctx := context.Background()

	userID := "user-123"
	orgID := "org-456"
	actionType := models.AuditActionType("test_action")
	actionResult := models.AuditResultSuccess
	ip := "127.0.0.1"
	ua := "Go-Test-Agent"
	details := map[string]interface{}{
		"foo": "bar",
		"id":  123,
	}

	// Expectation: InsertAuditLog is called with correct data and valid JSON
	mockDB.On("InsertAuditLog", ctx, mock.MatchedBy(func(log *models.AuditLog) bool {
		if log.UserID != userID || log.OrgID != orgID {
			return false
		}
		if log.ActionType != string(actionType) || log.ActionResult != string(actionResult) {
			return false
		}

		// Verify JSON marshaling
		var decodedDetails map[string]interface{}
		if err := json.Unmarshal(log.Details, &decodedDetails); err != nil {
			return false
		}

		// Check content of JSON
		return decodedDetails["foo"] == "bar" && decodedDetails["id"] == float64(123) // JSON numbers are floats
	})).Return(nil)

	// Act
	err := service.LogAction(ctx, userID, orgID, actionType, actionResult, ip, ua, details)

	// Assert
	assert.NoError(t, err)
	mockDB.AssertExpectations(t)
}

func TestService_LogAction_DBError_Suppressed(t *testing.T) {
	// Arrange
	mockDB := new(mocks.Database)
	service := NewService(mockDB)
	ctx := context.Background()

	// Simulate DB error
	dbError := errors.New("connection lost")

	// Expectation: InsertAuditLog is called but fails
	mockDB.On("InsertAuditLog", ctx, mock.Anything).Return(dbError)

	// Act
	err := service.LogAction(
		ctx,
		"user-1",
		"org-1",
		models.AuditActionType("login"),
		models.AuditResultFailure,
		"1.1.1.1",
		"agent",
		nil,
	)

	// Assert
	assert.NoError(t, err, "LogAction should not return error even if DB fails")
	mockDB.AssertExpectations(t)
}
