package models

// SubscriptionDetails represents subscription information
type SubscriptionDetails struct {
	SubscriptionID      string `json:"subscription_id"`
	PlanID              string `json:"plan_id"`
	VideoLimitMB        int64  `json:"video_limit_mb"`
	OrdersPerMonthLimit int64  `json:"orders_per_month_limit"`
	IsActive            bool   `json:"is_active"`
	TrialEndsAt         int64  `json:"trial_ends_at"`
	StartedAt           int64  `json:"started_at"`
	ExpiresAt           int64  `json:"expires_at"`
	BillingCycle        string `json:"billing_cycle"`
}

// StorageUsage represents storage and video usage statistics
type StorageUsage struct {
	VideosCount       int64   `json:"videos_count"`
	VideosAvailable   int64   `json:"videos_available"`
	VideosPercentUsed float64 `json:"videos_percent_used"`
}

// GetSubscriptionResponse represents the response for getting subscription details
type GetSubscriptionResponse struct {
	Subscription *SubscriptionDetails `json:"subscription"`
	Usage        *StorageUsage        `json:"usage"`
}
