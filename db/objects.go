package db

import (
	"math/big"
	"time"
)

// User is db definition of a user in SSO System
type User struct {
	ID            string `gorm:"primary_key"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     *time.Time
	PublicKey     string
	CertificateID big.Int
	Certificate   Certificate `gorm:"foreignkey:CertificateID"`
}

// Certificate is db definition for saving certificate instance in DB as a string
type Certificate struct {
	ID        big.Int `gorm:"primary_key"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
	Instance  string
}

// APILog is db definition of a Log of API service consume
type APILog struct {
	ID             int `gorm:"primary_key"`
	Timestamp      time.Time
	TTL            string
	ResponseStatus int
	Path           string
	Method         string
	ClientIP       string
	ClientTools    string
	Protocol       string
}
