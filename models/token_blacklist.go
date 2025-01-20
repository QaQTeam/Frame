package models

import (
	"time"

	"gorm.io/gorm"
)

type TokenBlacklist struct {
	gorm.Model
	Token     string    `json:"token" gorm:"size:500;not null;unique"`
	ExpiredAt time.Time `json:"expired_at" gorm:"not null"`
}

func (TokenBlacklist) TableName() string {
	return "token_blacklist"
}
