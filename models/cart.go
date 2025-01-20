package models

import "time"

// CartItem 购物车商品模型
type CartItem struct {
	ID           uint64     `json:"id" gorm:"primaryKey"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty" gorm:"index"`
	UserID       uint64     `gorm:"not null;index" json:"user_id"`
	ProductID    uint64     `gorm:"not null;index" json:"product_id"`
	Quantity     int        `gorm:"not null;default:1" json:"quantity"`
	Price        float64    `gorm:"type:decimal(10,2);not null" json:"price"`
	ProductName  string     `gorm:"size:255;not null" json:"product_name"`
	ProductImage string     `gorm:"size:1024" json:"product_image"`
	Selected     bool       `gorm:"not null;default:true" json:"selected"`

	// 关联
	User    User    `gorm:"foreignKey:UserID" json:"-"`
	Product Product `gorm:"foreignKey:ProductID" json:"product"`
}

func (CartItem) TableName() string {
	return "cart_items"
}
