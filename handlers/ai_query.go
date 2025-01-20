package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"qaqmall/models"
)

type AIQueryHandler struct {
	db *gorm.DB
}

func NewAIQueryHandler(db *gorm.DB) *AIQueryHandler {
	return &AIQueryHandler{db: db}
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type OpenAIRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature"`
}

type OpenAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// Query 统一的AI查询接口
func (h *AIQueryHandler) Query(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到用户信息"})
		return
	}

	var req struct {
		Query string `json:"query" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	// 获取用户相关信息
	var contextInfo string

	// 获取购物车信息
	var cartItems []models.CartItem
	h.db.Where("user_id = ?", userID).Preload("Product").Find(&cartItems)

	var cartInfo string
	if len(cartItems) > 0 {
		cartInfo = "您的购物车中有："
		for _, item := range cartItems {
			cartInfo += fmt.Sprintf("\n- %s (数量: %d, 单价: %.2f元)",
				item.ProductName, item.Quantity, item.Price)
		}
	} else {
		cartInfo = "您的购物车目前是空的"
	}

	// 获取商品信息
	var products []models.Product
	h.db.Where("is_on_sale = ?", true).Limit(10).Find(&products)

	var productInfo string
	if len(products) > 0 {
		productInfo = "当前热销商品有："
		for _, product := range products {
			productInfo += fmt.Sprintf("\n- %s (价格: %.2f元, 库存: %d)",
				product.Name, product.Price, product.Stock)
		}
	} else {
		productInfo = "当前没有在售商品"
	}

	// 获取订单信息
	var orders []models.Order
	h.db.Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(5).
		Preload("Items").
		Find(&orders)

	var orderInfo string
	if len(orders) > 0 {
		orderInfo = "您的最近订单有："
		for _, order := range orders {
			orderInfo += fmt.Sprintf("\n- 订单号: %s (状态: %s, 总金额: %.2f元)",
				order.OrderNumber, order.Status, order.TotalAmount)
		}
	} else {
		orderInfo = "您还没有任何订单"
	}

	contextInfo = fmt.Sprintf("以下是您的相关信息：\n\n%s\n\n%s\n\n%s",
		cartInfo, productInfo, orderInfo)

	// 构建 OpenAI 请求
	openaiReq := OpenAIRequest{
		Model: "gpt-3.5-turbo",
		Messages: []Message{
			{
				Role: "system",
				Content: `你是一个购物商城的智能助手，可以帮助用户查询商品、购物车、订单等信息。
请根据提供的上下文信息，用自然、友好的语言回答用户的问题。
如果用户询问的信息不在上下文中，请告诉用户你只能查询到有限的信息。`,
			},
			{
				Role: "user",
				Content: fmt.Sprintf("上下文信息：\n%s\n\n用户问题：%s",
					contextInfo, req.Query),
			},
		},
		Temperature: 0.7,
	}

	// 发送请求到 OpenAI API
	jsonData, err := json.Marshal(openaiReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "处理请求失败"})
		return
	}

	client := &http.Client{}
	request, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions",
		bytes.NewBuffer(jsonData))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建请求失败"})
		return
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer sk-xxx")

	response, err := client.Do(request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "调用AI服务失败"})
		return
	}
	defer response.Body.Close()

	var openaiResp OpenAIResponse
	if err := json.NewDecoder(response.Body).Decode(&openaiResp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "解析AI响应失败"})
		return
	}

	if len(openaiResp.Choices) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AI响应为空"})
		return
	}

	// 返回AI的回答
	c.JSON(http.StatusOK, gin.H{
		"answer": strings.TrimSpace(openaiResp.Choices[0].Message.Content),
	})
}
