package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"qaqmall/models"
)

type OrderHandler struct {
	db *gorm.DB
}

func NewOrderHandler(db *gorm.DB) *OrderHandler {
	return &OrderHandler{db: db}
}

// CreateOrder 创建订单
func (h *OrderHandler) CreateOrder(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到用户信息"})
		return
	}

	var req struct {
		AddressID uint64 `json:"address_id" binding:"required"`
		Items     []struct {
			ProductID uint64 `json:"product_id" binding:"required"`
			Quantity  int    `json:"quantity" binding:"required,min=1"`
		} `json:"items" binding:"required,min=1"`
		Remark string `json:"remark"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 开始事务
	tx := h.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 验证地址
	var address models.Address
	if err := tx.First(&address, req.AddressID).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的收货地址"})
		return
	}

	if address.UserID != userID.(uint64) {
		tx.Rollback()
		c.JSON(http.StatusForbidden, gin.H{"error": "无权使用该地址"})
		return
	}

	// 生成订单号
	orderNumber := fmt.Sprintf("%s%d", time.Now().Format("20060102150405"), userID)

	// 创建订单
	order := models.Order{
		OrderNumber: orderNumber,
		UserID:      userID.(uint64),
		Status:      models.OrderStatusPending,
		AddressID:   req.AddressID,
		Remark:      req.Remark,
		ExpiredAt:   time.Now().Add(30 * time.Minute), // 30分钟后过期
	}

	if err := tx.Create(&order).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建订单失败"})
		return
	}

	// 处理订单项
	var totalAmount float64
	for _, item := range req.Items {
		var product models.Product
		if err := tx.First(&product, item.ProductID).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusBadRequest, gin.H{"error": "商品不存在"})
			return
		}

		if !product.IsOnSale {
			tx.Rollback()
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("商品 %s 已下架", product.Name)})
			return
		}

		if product.Stock < item.Quantity {
			tx.Rollback()
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("商品 %s 库存不足", product.Name)})
			return
		}

		// 创建订单项
		orderItem := models.OrderItem{
			OrderID:      order.ID,
			ProductID:    product.ID,
			ProductName:  product.Name,
			ProductImage: product.ImageURL,
			Price:        product.Price,
			Quantity:     item.Quantity,
		}

		if err := tx.Create(&orderItem).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "创建订单项失败"})
			return
		}

		// 扣减库存
		if err := tx.Model(&product).Update("stock", product.Stock-item.Quantity).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "更新库存失败"})
			return
		}

		totalAmount += product.Price * float64(item.Quantity)
	}

	// 更新订单总金额
	if err := tx.Model(&order).Update("total_amount", totalAmount).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新订单金额失败"})
		return
	}

	// 提交事务
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建订单失败"})
		return
	}

	// 返回订单信息
	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "创建订单成功",
		"data": gin.H{
			"order_id":     order.ID,
			"order_number": order.OrderNumber,
			"total_amount": totalAmount,
			"expired_at":   order.ExpiredAt,
		},
	})
}

// GetOrder 获取订单详情
func (h *OrderHandler) GetOrder(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到用户信息"})
		return
	}

	orderID := c.Param("id")
	var order models.Order
	if err := h.db.Preload("Items").Preload("Items.Product").Preload("Address").First(&order, orderID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "订单不存在"})
		return
	}

	if order.UserID != userID.(uint64) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权查看该订单"})
		return
	}

	c.JSON(http.StatusOK, order)
}

// GetOrders 获取订单列表
func (h *OrderHandler) GetOrders(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到用户信息"})
		return
	}

	var orders []models.Order
	if err := h.db.Where("user_id = ?", userID).Preload("Items").Preload("Items.Product").Preload("Address").Find(&orders).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取订单列表失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"items": orders,
	})
}

// UpdateOrder 修改订单信息
func (h *OrderHandler) UpdateOrder(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到用户信息"})
		return
	}

	orderID := c.Param("id")
	var order models.Order
	if err := h.db.First(&order, orderID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "订单不存在"})
		return
	}

	if order.UserID != userID.(uint64) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权修改该订单"})
		return
	}

	if order.Status != models.OrderStatusPending {
		c.JSON(http.StatusBadRequest, gin.H{"error": "只能修改待支付的订单"})
		return
	}

	var req struct {
		AddressID uint64 `json:"address_id"`
		Remark    string `json:"remark"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 如果修改了地址，验证新地址
	if req.AddressID > 0 {
		var address models.Address
		if err := h.db.First(&address, req.AddressID).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的收货地址"})
			return
		}

		if address.UserID != userID.(uint64) {
			c.JSON(http.StatusForbidden, gin.H{"error": "无权使用该地址"})
			return
		}

		order.AddressID = req.AddressID
	}

	order.Remark = req.Remark

	if err := h.db.Save(&order).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新订单失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "更新订单成功",
		"data":    order,
	})
}

// CancelOrder 取消订单
func (h *OrderHandler) CancelOrder(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到用户信息"})
		return
	}

	orderID := c.Param("id")
	var order models.Order
	if err := h.db.Preload("Items").First(&order, orderID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "订单不存在"})
		return
	}

	if order.UserID != userID.(uint64) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权取消该订单"})
		return
	}

	if order.Status != models.OrderStatusPending {
		c.JSON(http.StatusBadRequest, gin.H{"error": "只能取消待支付的订单"})
		return
	}

	// 开始事务
	tx := h.db.Begin()

	// 更新订单状态
	if err := tx.Model(&order).Update("status", models.OrderStatusCancelled).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "取消订单失败"})
		return
	}

	// 恢复库存
	for _, item := range order.Items {
		if err := tx.Model(&models.Product{}).Where("id = ?", item.ProductID).
			UpdateColumn("stock", gorm.Expr("stock + ?", item.Quantity)).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "恢复库存失败"})
			return
		}
	}

	// 提交事务
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "取消订单失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "取消订单成功",
	})
}
