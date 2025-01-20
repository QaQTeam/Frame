package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type visitor struct {
	lastSeen  time.Time
	count     int
	resetTime time.Time
}

var (
	visitors = make(map[string]*visitor)
	mu       sync.Mutex
)

// RateLimiter 速率限制中间件，默认每分钟60个请求
func RateLimiter() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		mu.Lock()
		v, exists := visitors[ip]
		if !exists {
			visitors[ip] = &visitor{
				lastSeen:  time.Now(),
				count:     1,
				resetTime: time.Now().Add(time.Minute),
			}
			mu.Unlock()
			c.Next()
			return
		}

		// 如果已经过了重置时间，重置计数
		if time.Now().After(v.resetTime) {
			v.count = 1
			v.resetTime = time.Now().Add(time.Minute)
		} else if v.count >= 60 { // 超过限制
			mu.Unlock()
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "请求过于频繁，请稍后再试",
			})
			return
		} else {
			v.count++
		}

		v.lastSeen = time.Now()
		mu.Unlock()
		c.Next()
	}
}
