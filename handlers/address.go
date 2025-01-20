package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"qaqmall/models"
)

type AddressHandler struct {
	db *gorm.DB
}

func NewAddressHandler(db *gorm.DB) *AddressHandler {
	return &AddressHandler{db: db}
}

func (h *AddressHandler) ListAddresses(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到用户信息"})
		return
	}

	var addresses []models.Address
	if err := h.db.Where("user_id = ?", userID).Find(&addresses).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取地址列表失败"})
		return
	}

	c.JSON(http.StatusOK, addresses)
}

func (h *AddressHandler) CreateAddress(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到用户信息"})
		return
	}

	var address models.Address
	if err := c.ShouldBindJSON(&address); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	address.UserID = userID.(uint64)

	// 如果是第一个地址，设为默认地址
	var count int64
	h.db.Model(&models.Address{}).Where("user_id = ?", userID).Count(&count)
	if count == 0 {
		address.IsDefault = true
	}

	if err := h.db.Create(&address).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建地址失败"})
		return
	}

	c.JSON(http.StatusOK, address)
}

func (h *AddressHandler) UpdateAddress(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到用户信息"})
		return
	}

	addressID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的地址ID"})
		return
	}

	var address models.Address
	if err := h.db.Where("id = ? AND user_id = ?", addressID, userID).First(&address).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "地址不存在"})
		return
	}

	if err := c.ShouldBindJSON(&address); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	address.ID = addressID
	address.UserID = userID.(uint64)

	if err := h.db.Save(&address).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新地址失败"})
		return
	}

	c.JSON(http.StatusOK, address)
}

func (h *AddressHandler) DeleteAddress(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到用户信息"})
		return
	}

	addressID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的地址ID"})
		return
	}

	result := h.db.Where("id = ? AND user_id = ?", addressID, userID).Delete(&models.Address{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除地址失败"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "地址不存在"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "地址已删除"})
}
