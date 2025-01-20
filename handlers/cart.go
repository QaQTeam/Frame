package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"qaqmall/models"
)

type CartHandler struct {
	db *gorm.DB
}

func NewCartHandler(db *gorm.DB) *CartHandler {
	return &CartHandler{db: db}
}

func (h *CartHandler) ListCart(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到用户信息"})
		return
	}

	var cartItems []models.CartItem
	if err := h.db.Where("user_id = ?", userID).Find(&cartItems).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取购物车失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"items": cartItems,
	})
}

func (h *CartHandler) AddToCart(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到用户信息"})
		return
	}

	var req struct {
		ProductID uint64 `json:"product_id"`
		Quantity  int    `json:"quantity"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 检查商品是否存在
	var product models.Product
	if err := h.db.First(&product, req.ProductID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "商品不存在"})
		return
	}

	// 检查购物车中是否已存在该商品
	var existingItem models.CartItem
	if err := h.db.Where("user_id = ? AND product_id = ?", userID, req.ProductID).First(&existingItem).Error; err == nil {
		// 如果存在，更新数量
		existingItem.Quantity += req.Quantity
		if err := h.db.Save(&existingItem).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "更新购物车失败"})
			return
		}
		c.JSON(http.StatusOK, existingItem)
		return
	}

	// 如果不存在，创建新记录
	item := models.CartItem{
		UserID:       userID.(uint64),
		ProductID:    req.ProductID,
		Quantity:     req.Quantity,
		ProductName:  product.Name,
		Price:        product.Price,
		ProductImage: product.ImageURL,
		Selected:     true,
	}
	if err := h.db.Create(&item).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "添加到购物车失败"})
		return
	}

	c.JSON(http.StatusOK, item)
}

func (h *CartHandler) UpdateCartItem(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到用户信息"})
		return
	}

	itemID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的购物车项ID"})
		return
	}

	var updateInfo struct {
		Quantity int  `json:"quantity"`
		Selected bool `json:"selected"`
	}
	if err := c.ShouldBindJSON(&updateInfo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	var item models.CartItem
	if err := h.db.Where("id = ? AND user_id = ?", itemID, userID).First(&item).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "购物车项不存在"})
		return
	}

	item.Quantity = updateInfo.Quantity
	item.Selected = updateInfo.Selected

	if err := h.db.Save(&item).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新购物车失败"})
		return
	}

	c.JSON(http.StatusOK, item)
}

func (h *CartHandler) RemoveFromCart(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到用户信息"})
		return
	}

	itemID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的购物车项ID"})
		return
	}

	result := h.db.Where("id = ? AND user_id = ?", itemID, userID).Delete(&models.CartItem{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除购物车项失败"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "购物车项不存在"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "购物车项已删除"})
}

func (h *CartHandler) EmptyCart(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到用户信息"})
		return
	}

	result := h.db.Where("user_id = ?", userID).Delete(&models.CartItem{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "清空购物车失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "购物车已清空"})
}
