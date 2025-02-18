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
	ID            uint64        `json:"id" gorm:"primaryKey"`                      // 支付记录ID，主键
	PaymentNumber string        `json:"payment_number" gorm:"unique;not null"`     // 支付编号，唯一且不能为空
	OrderID       uint64        `json:"order_id" gorm:"not null"`                  // 关联的订单ID，外键，不能为空
	UserID        uint64        `json:"user_id" gorm:"not null"`                   // 关联的用户ID，外键，不能为空
	Amount        float64       `json:"amount" gorm:"type:decimal(10,2);not null"` // 支付金额，类型为小数，不能为空
	PaymentMethod PaymentMethod `json:"payment_method" gorm:"not null"`            // 支付方式，不能为空
	Status        PaymentStatus `json:"status" gorm:"not null;default:pending"`    // 支付状态，默认为“待支付”
	PaidAt        *time.Time    `json:"paid_at,omitempty"`                         // 支付时间，如果已支付，存储支付的时间戳，可为空
	CreatedAt     time.Time     `json:"created_at" gorm:"not null"`                // 支付记录创建时间，不能为空
	UpdatedAt     time.Time     `json:"updated_at" gorm:"not null"`                // 支付记录更新时间，不能为空
	DeletedAt     *time.Time    `json:"deleted_at,omitempty" gorm:"index"`         // 删除时间（软删除），索引，可为空

	// 关联
	Order Order `json:"order" gorm:"foreignKey:OrderID"` // 关联的订单，外键关联Order模型
	User  User  `json:"user" gorm:"foreignKey:UserID"`   // 关联的用户，外键关联User模型
}

// TableName 指定表名
func (Payment) TableName() string {
	return "payments" // 指定该模型对应的数据库表名为"payments"
}
