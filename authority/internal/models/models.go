package models

import "time"

type Subscriber struct {
	ID        string
	Email     string
	Password  string
	Role      string
	CreatedAt time.Time
}

type Session struct {
	ID           string
	SubscriberID string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

type Subscription struct {
	ID                 string
	SubscriberID       string
	Tier               string
	Status             string
	TokensIssued       int64
	BandwidthUsed      int64
	CurrentPeriodStart time.Time
	CurrentPeriodEnd   time.Time
	CreatedAt          time.Time
}

type RelayNode struct {
	ID            string
	APIKeyHash    string
	Endpoint      string
	Region        string
	Role          string
	Status        string
	LastHeartbeat *time.Time
	CreatedAt     time.Time
}
