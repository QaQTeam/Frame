package models

import (
	"time"
)

// OrderStatus 订单状态
type OrderStatus string

const (
	OrderStatusPending   OrderStatus = "pending"   // 待支付
	OrderStatusPaid      OrderStatus = "paid"      // 已支付
	OrderStatusShipped   OrderStatus = "shipped"   // 已发货
	OrderStatusCompleted OrderStatus = "completed" // 已完成
	OrderStatusCancelled OrderStatus = "cancelled" // 已取消
	OrderStatusRefunded  OrderStatus = "refunded"  // 已退款
)

// Order 订单模型
type Order struct {
	ID          uint64      `json:"id" gorm:"primaryKey"`
	OrderNumber string      `json:"order_number" gorm:"unique;not null"`
	UserID      uint64      `json:"user_id" gorm:"not null"`
	Status      OrderStatus `json:"status" gorm:"not null;default:pending"`
	TotalAmount float64     `json:"total_amount" gorm:"type:decimal(10,2);not null"`
	AddressID   uint64      `json:"address_id" gorm:"not null"`
	Remark      string      `json:"remark" gorm:"type:text"`
	ExpiredAt   time.Time   `json:"expired_at" gorm:"not null"`
	CreatedAt   time.Time   `json:"created_at" gorm:"not null"`
	UpdatedAt   time.Time   `json:"updated_at" gorm:"not null"`
	DeletedAt   *time.Time  `json:"deleted_at,omitempty" gorm:"index"`

	// 关联
	User    User        `json:"user" gorm:"foreignKey:UserID"`
	Address Address     `json:"address" gorm:"foreignKey:AddressID"`
	Items   []OrderItem `json:"items" gorm:"foreignKey:OrderID"`
}

// OrderItem 订单项模型
type OrderItem struct {
	ID           uint64    `json:"id" gorm:"primaryKey"`
	OrderID      uint64    `json:"order_id" gorm:"not null"`
	ProductID    uint64    `json:"product_id" gorm:"not null"`
	ProductName  string    `json:"product_name" gorm:"not null"`
	ProductImage string    `json:"product_image"`
	Price        float64   `json:"price" gorm:"type:decimal(10,2);not null"`
	Quantity     int       `json:"quantity" gorm:"not null"`
	CreatedAt    time.Time `json:"created_at" gorm:"not null"`
	UpdatedAt    time.Time `json:"updated_at" gorm:"not null"`

	// 关联
	Order   Order   `json:"-" gorm:"foreignKey:OrderID"`
	Product Product `json:"product" gorm:"foreignKey:ProductID"`
}

// TableName 指定表名
func (Order) TableName() string {
	return "orders"
}

// TableName 指定表名
func (OrderItem) TableName() string {
	return "order_items"
}
