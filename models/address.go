package models

import "time"

// Address 地址模型
type Address struct {
	ID         uint64     `json:"id" gorm:"primaryKey"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	DeletedAt  *time.Time `json:"deleted_at,omitempty" gorm:"index"`
	UserID     uint64     `json:"user_id" gorm:"not null;index"`
	Name       string     `json:"name" gorm:"size:20;not null"`
	Phone      string     `json:"phone" gorm:"size:20;not null"`
	Province   string     `json:"province" gorm:"size:20;not null"`
	City       string     `json:"city" gorm:"size:20;not null"`
	District   string     `json:"district" gorm:"size:20;not null"`
	Street     string     `json:"street" gorm:"size:50;not null"`
	Detail     string     `json:"detail" gorm:"size:100;not null"`
	PostalCode string     `json:"postal_code" gorm:"size:10"`
	Tag        string     `json:"tag" gorm:"size:10"`
	IsDefault  bool       `json:"is_default" gorm:"default:false"`

	// 关联
	User User `json:"-" gorm:"foreignKey:UserID"`
}

func (Address) TableName() string {
	return "addresses"
}
