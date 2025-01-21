package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"qaqmall/middleware"
	"qaqmall/models"
)

type UserHandler struct {
	db *gorm.DB
}

func NewUserHandler(db *gorm.DB) *UserHandler {
	return &UserHandler{db: db}
}

func (h *UserHandler) Register(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"error":   "无效的请求参数",
			"details": err.Error(),
		})
		return
	}

	// 验证必要字段
	if user.Username == "" || user.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":  400,
			"error": "用户名和密码不能为空",
		})
		return
	}

	// 检查用户名是否已存在
	var existingUser models.User
	if err := h.db.Where("username = ?", user.Username).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":  400,
			"error": "用户名已存在",
		})
		return
	}

	// 加密密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"error":   "密码加密失败",
			"details": err.Error(),
		})
		return
	}
	user.Password = string(hashedPassword)

	// 设置默认角色
	user.Role = "user"

	// 创建用户
	if err := h.db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"error":   "创建用户失败",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "注册成功",
		"data": gin.H{
			"user_id":  user.ID,
			"username": user.Username,
			"role":     user.Role,
		},
	})
}

func (h *UserHandler) Login(c *gin.Context) {
	var loginInfo struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&loginInfo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"error":   "无效的请求参数",
			"details": err.Error(),
		})
		return
	}

	var user models.User
	if err := h.db.Where("username = ? AND deleted_at IS NULL", loginInfo.Username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":  401,
				"error": "用户不存在或已被删除",
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"code":    500,
				"error":   "数据库查询错误",
				"details": err.Error(),
			})
		}
		return
	}

	// 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginInfo.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":  401,
			"error": "密码错误",
		})
		return
	}

	// 生成JWT令牌
	token := generateToken(user.ID, user.Username, user.Role)

	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "登录成功",
		"data": gin.H{
			"token":    token,
			"user_id":  user.ID,
			"username": user.Username,
			"role":     user.Role,
		},
	})
}

func (h *UserHandler) GetUserInfo(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到用户信息"})
		return
	}

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":       user.ID,
		"username": user.Username,
		"role":     user.Role,
		"email":    user.Email,
		"phone":    user.Phone,
	})
}

func (h *UserHandler) UpdateUserInfo(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到用户信息"})
		return
	}

	var updateInfo struct {
		Email string `json:"email"`
		Phone string `json:"phone"`
	}

	if err := c.ShouldBindJSON(&updateInfo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}

	user.Email = updateInfo.Email
	user.Phone = updateInfo.Phone

	if err := h.db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新用户信息失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "更新成功",
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"role":     user.Role,
			"email":    user.Email,
			"phone":    user.Phone,
		},
	})
}

func (h *UserHandler) DeleteUser(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":  401,
			"error": "未找到用户信息",
		})
		return
	}

	// 先查找用户确保存在
	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"code":  404,
			"error": "用户不存在",
		})
		return
	}

	// 使用软删除
	if err := h.db.Delete(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":  500,
			"error": "删除用户失败",
		})
		return
	}

	// 获取当前token并加入黑名单
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && parts[0] == "Bearer" {
			token, err := jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
				return []byte("your-secret-key"), nil
			})
			if err == nil {
				if claims, ok := token.Claims.(jwt.MapClaims); ok {
					exp := time.Unix(int64(claims["exp"].(float64)), 0)
					blacklistedToken := models.TokenBlacklist{
						Token:     parts[1],
						ExpiredAt: exp,
					}
					h.db.Create(&blacklistedToken)
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "用户已删除",
	})
}

func (h *UserHandler) Logout(c *gin.Context) {
	// 从请求头中获取token
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未提供token"})
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == "Bearer") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token格式错误"})
		return
	}

	tokenString := parts[1]

	// 解析token以获取过期时间
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("your-secret-key"), nil
	})

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的token claims"})
		return
	}

	// 获取token的过期时间
	exp := time.Unix(int64(claims["exp"].(float64)), 0)

	// 将token加入黑名单
	blacklistedToken := models.TokenBlacklist{
		Token:     tokenString,
		ExpiredAt: exp,
	}

	if err := h.db.Create(&blacklistedToken).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "登出失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "登出成功",
	})
}

func generateToken(userID uint64, username string, role string) string {
	token, err := middleware.GenerateNewToken(userID, username, role)
	if err != nil {
		return ""
	}
	return token
}
