package models

import "time"

// Product 商品模型
type Product struct {
	ID          uint64     `gorm:"primaryKey" json:"id"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `gorm:"index" json:"deleted_at,omitempty"`
	Name        string     `gorm:"size:255;not null" json:"name"`
	Description string     `gorm:"type:text" json:"description"`
	Price       float64    `gorm:"type:decimal(10,2);not null" json:"price"`
	Stock       int        `gorm:"not null" json:"stock"`
	ImageURL    string     `gorm:"size:255" json:"image_url"`
	IsOnSale    bool       `gorm:"not null;default:true" json:"is_on_sale"`
	Categories  []Category `gorm:"many2many:product_categories;" json:"categories"`
}

// Category 商品分类模型
type Category struct {
	ID          uint64     `gorm:"primaryKey" json:"id"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `gorm:"index" json:"deleted_at,omitempty"`
	Name        string     `gorm:"size:50;not null;unique" json:"name"`
	Description string     `gorm:"size:200" json:"description"`
	Products    []Product  `gorm:"many2many:product_categories;" json:"products"`
}
