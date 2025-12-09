package models

// SubscriptionDetails represents subscription information
type SubscriptionDetails struct {
	SubscriptionID  string `json:"subscription_id"`
	PlanID          string `json:"plan_id"`
	StorageLimitMB  int64  `json:"storage_limit_mb"`
	VideoCountLimit int64  `json:"video_count_limit"`
	IsActive        bool   `json:"is_active"`
	TrialEndsAt     int64  `json:"trial_ends_at"`
	StartedAt       int64  `json:"started_at"`
	ExpiresAt       int64  `json:"expires_at"`
	BillingCycle    string `json:"billing_cycle"`
}

// StorageUsage represents storage and video usage statistics
type StorageUsage struct {
	StorageUsedMB      int64   `json:"storage_used_mb"`
	StorageAvailableMB int64   `json:"storage_available_mb"`
	StoragePercentUsed float64 `json:"storage_percent_used"`
	VideosCount        int64   `json:"videos_count"`
	VideosAvailable    int64   `json:"videos_available"`
	VideosPercentUsed  float64 `json:"videos_percent_used"`
}

// GetSubscriptionResponse represents the response for getting subscription details
type GetSubscriptionResponse struct {
	Subscription *SubscriptionDetails `json:"subscription"`
	Usage        *StorageUsage        `json:"usage"`
}