package middleware

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
)

// Logger 日志中间件
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 开始时间
		startTime := time.Now()

		// 处理请求
		c.Next()

		// 结束时间
		endTime := time.Now()

		// 获取用户ID
		userID := "anonymous"
		if value, exists := c.Get("user_id"); exists {
			userID = fmt.Sprintf("%v", value)
		}

		// 计算延迟
		latency := endTime.Sub(startTime)

		// 打印日志
		fmt.Printf("[GIN] %v | %3d | %13v | %15s | %-7s | %-10s | %s\n",
			endTime.Format("2006/01/02 - 15:04:05"),
			c.Writer.Status(),
			latency,
			c.ClientIP(),
			c.Request.Method,
			userID,
			c.Request.URL.Path,
		)

		if len(c.Errors) > 0 {
			fmt.Printf("[GIN] Errors: %v\n", c.Errors)
		}
	}
}
