package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"gorm.io/gorm"

	"qaqmall/models"
)

// GenerateNewToken 生成新的JWT
func GenerateNewToken(userID uint64, username, role string) (string, error) {
	claims := jwt.MapClaims{
		"user_id":  userID,
		"username": username,
		"role":     role,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	secretKey := []byte("your-secret-key")
	return token.SignedString(secretKey)
}

func Auth(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从请求头中获取token
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未提供认证信息"})
			c.Abort()
			return
		}

		// 检查token格式
		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "认证格式错误"})
			c.Abort()
			return
		}

		// 检查token是否在黑名单中
		tokenString := parts[1]
		var blacklistedToken models.TokenBlacklist
		if err := db.Where("token = ? AND expired_at > ?", tokenString, time.Now()).First(&blacklistedToken).Error; err == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "token已失效"})
			c.Abort()
			return
		}

		// 解析token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// 验证签名算法
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte("your-secret-key"), nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的token"})
			c.Abort()
			return
		}

		// 验证token并获取claims
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// 将用户信息存储到上下文中
			userID := uint64(claims["user_id"].(float64))
			username := claims["username"].(string)
			role := claims["role"].(string)
			c.Set("user_id", userID)
			c.Set("username", username)
			c.Set("role", role)

			if exp, exists := claims["exp"]; exists {
				expTime := time.Unix(int64(exp.(float64)), 0)
				remainingTime := expTime.Sub(time.Now())
				fmt.Printf("Token剩余有效期: %v\n", remainingTime)

				// 剩余时间小于12小时，进行续期
				if remainingTime < 12*time.Hour {
					newToken, err := GenerateNewToken(userID, username, role)
					if err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": "续期token失败"})
						c.Abort()
						return
					}
					c.Header("Authorization", "Bearer "+newToken)
					fmt.Printf("续期token成功，新token: %s\n", newToken)
				}
			}
			c.Next()
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的token"})
			c.Abort()
			return
		}
	}
}
