package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"qaqmall/models"
)

type PaymentHandler struct {
	db *gorm.DB
}

func NewPaymentHandler(db *gorm.DB) *PaymentHandler {
	return &PaymentHandler{db: db}
}

// CreatePayment 创建支付
func (h *PaymentHandler) CreatePayment(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到用户信息"})
		return
	}

	var req struct {
		OrderID       uint64               `json:"order_id" binding:"required"`
		PaymentMethod models.PaymentMethod `json:"payment_method" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 开始事务
	tx := h.db.Begin()

	// 查找订单
	var order models.Order
	if err := tx.First(&order, req.OrderID).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusNotFound, gin.H{"error": "订单不存在"})
		return
	}

	// 验证订单所有者
	if order.UserID != userID.(uint64) {
		tx.Rollback()
		c.JSON(http.StatusForbidden, gin.H{"error": "无权支付该订单"})
		return
	}

	// 验证订单状态
	if order.Status != models.OrderStatusPending {
		tx.Rollback()
		c.JSON(http.StatusBadRequest, gin.H{"error": "订单状态不正确"})
		return
	}

	// 验证订单是否过期
	if time.Now().After(order.ExpiredAt) {
		tx.Rollback()
		c.JSON(http.StatusBadRequest, gin.H{"error": "订单已过期"})
		return
	}

	// 生成支付单号
	paymentNumber := fmt.Sprintf("PAY%s%d", time.Now().Format("20060102150405"), userID)

	// 创建支付记录
	payment := models.Payment{
		PaymentNumber: paymentNumber,
		OrderID:       order.ID,
		UserID:        userID.(uint64),
		Amount:        order.TotalAmount,
		PaymentMethod: req.PaymentMethod,
		Status:        models.PaymentStatusPending,
	}

	if err := tx.Create(&payment).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建支付记录失败"})
		return
	}

	// 提交事务
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建支付记录失败"})
		return
	}

	// 返回支付信息
	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "创建支付记录成功",
		"data": gin.H{
			"payment_id":     payment.ID,
			"payment_number": payment.PaymentNumber,
			"amount":         payment.Amount,
			"expired_at":     order.ExpiredAt,
		},
	})
}

// PaymentCallback 支付回调
func (h *PaymentHandler) PaymentCallback(c *gin.Context) {
	// 在实际项目中，这里需要验证签名等安全措施
	var req struct {
		PaymentNumber string `json:"payment_number" binding:"required"`
		Status        string `json:"status" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 开始事务
	tx := h.db.Begin()

	// 查找支付记录
	var payment models.Payment
	if err := tx.Where("payment_number = ?", req.PaymentNumber).First(&payment).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusNotFound, gin.H{"error": "支付记录不存在"})
		return
	}

	// 检查支付状态
	if payment.Status != models.PaymentStatusPending {
		tx.Rollback()
		c.JSON(http.StatusBadRequest, gin.H{"error": "支付状态不正确"})
		return
	}

	// 更新支付状态
	paidAt := time.Now()
	updates := map[string]interface{}{
		"status":  models.PaymentStatusPaid,
		"paid_at": &paidAt,
	}

	if err := tx.Model(&payment).Updates(updates).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新支付状态失败"})
		return
	}

	// 更新订单状态
	if err := tx.Model(&models.Order{}).Where("id = ?", payment.OrderID).
		Update("status", models.OrderStatusPaid).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新订单状态失败"})
		return
	}

	// 提交事务
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "处理支付回调失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "支付成功",
	})
}

// GetPayment 获取支付详情
func (h *PaymentHandler) GetPayment(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到用户信息"})
		return
	}

	paymentID := c.Param("id")
	var payment models.Payment
	if err := h.db.First(&payment, paymentID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "支付记录不存在"})
		return
	}

	if payment.UserID != userID.(uint64) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权查看该支付记录"})
		return
	}

	c.JSON(http.StatusOK, payment)
}
