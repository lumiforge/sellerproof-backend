package plan

import (
	"context"

	"github.com/lumiforge/sellerproof-backend/internal/models"
	"github.com/lumiforge/sellerproof-backend/internal/ydb"
)

// Service реализует бизнес-логику для тарифных планов
type Service struct {
	db ydb.Database
}

// NewService создает новый plan сервис
func NewService(db ydb.Database) *Service {
	return &Service{
		db: db,
	}
}

// GetAllPlans возвращает список всех доступных тарифных планов
func (s *Service) GetAllPlans(ctx context.Context) ([]*models.PlanResponse, error) {
	plans, err := s.db.GetAllPlans(ctx)
	if err != nil {
		return nil, err
	}

	response := make([]*models.PlanResponse, 0, len(plans))
	for _, plan := range plans {
		response = append(response, &models.PlanResponse{
			PlanID:              plan.PlanID,
			Name:                plan.Name,
			VideoLimitMB:        plan.VideoLimitMB,
			OrdersPerMonthLimit: plan.OrdersPerMonthLimit,
			PriceRub:            plan.PriceRub,
			BillingCycle:        plan.BillingCycle,
			Features:            plan.Features,
		})
	}

	return response, nil
}
