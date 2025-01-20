package models

import "time"

type User struct {
	ID        uint64     `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" gorm:"index"`
	Username  string     `json:"username" gorm:"size:20;not null;unique"`
	Password  string     `json:"password" gorm:"size:60;not null"`
	Role      string     `json:"role" gorm:"size:10;not null;default:'user'"`
	Email     string     `json:"email" gorm:"size:128"`
	Phone     string     `json:"phone" gorm:"size:20"`
}

func (User) TableName() string {
	return "users"
}
