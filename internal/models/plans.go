package models

type PlanResponse struct {
	PlanID              string  `json:"plan_id"`
	Name                string  `json:"name"`
	VideoLimitMB        int64   `json:"video_limit_mb"`
	OrdersPerMonthLimit int64   `json:"orders_per_month_limit"`
	PriceRub            float64 `json:"price_rub"`
	BillingCycle        string  `json:"billing_cycle"`
	Features            string  `json:"features"`
}
