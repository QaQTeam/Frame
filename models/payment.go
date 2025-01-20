package models

import (
	"time"
)

// PaymentMethod 支付方式
type PaymentMethod string

const (
	PaymentMethodAlipay PaymentMethod = "alipay" // 支付宝
	PaymentMethodWechat PaymentMethod = "wechat" // 微信支付
)

// PaymentStatus 支付状态
type PaymentStatus string

const (
	PaymentStatusPending   PaymentStatus = "pending"   // 待支付
	PaymentStatusPaid      PaymentStatus = "paid"      // 已支付
	PaymentStatusCancelled PaymentStatus = "cancelled" // 已取消
	PaymentStatusRefunded  PaymentStatus = "refunded"  // 已退款
)

// Payment 支付记录模型
type Payment struct {
	ID            uint64        `json:"id" gorm:"primaryKey"`
	PaymentNumber string        `json:"payment_number" gorm:"unique;not null"`
	OrderID       uint64        `json:"order_id" gorm:"not null"`
	UserID        uint64        `json:"user_id" gorm:"not null"`
	Amount        float64       `json:"amount" gorm:"type:decimal(10,2);not null"`
	PaymentMethod PaymentMethod `json:"payment_method" gorm:"not null"`
	Status        PaymentStatus `json:"status" gorm:"not null;default:pending"`
	PaidAt        *time.Time    `json:"paid_at,omitempty"`
	CreatedAt     time.Time     `json:"created_at" gorm:"not null"`
	UpdatedAt     time.Time     `json:"updated_at" gorm:"not null"`
	DeletedAt     *time.Time    `json:"deleted_at,omitempty" gorm:"index"`

	// 关联
	Order Order `json:"order" gorm:"foreignKey:OrderID"`
	User  User  `json:"user" gorm:"foreignKey:UserID"`
}

// TableName 指定表名
func (Payment) TableName() string {
	return "payments"
}
