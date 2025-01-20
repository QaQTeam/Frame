package middleware

import (
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type IPRateLimiter struct {
	sync.Mutex
	requests map[string][]time.Time
	window   time.Duration
	limit    int
}

func NewIPRateLimiter(window time.Duration, limit int) *IPRateLimiter {
	return &IPRateLimiter{
		requests: make(map[string][]time.Time),
		window:   window,
		limit:    limit,
	}
}

func (rl *IPRateLimiter) cleanOld(now time.Time) {
	for ip, times := range rl.requests {
		var valid []time.Time
		for _, t := range times {
			if now.Sub(t) <= rl.window {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.requests, ip)
		} else {
			rl.requests[ip] = valid
		}
	}
}

func (rl *IPRateLimiter) isAllowed(ip string) bool {
	rl.Lock()
	defer rl.Unlock()

	now := time.Now()
	rl.cleanOld(now)

	times := rl.requests[ip]
	if len(times) < rl.limit {
		rl.requests[ip] = append(times, now)
		return true
	}

	return false
}

func RateLimitMiddleware(requestsPerMinute int) gin.HandlerFunc {
	limiter := NewIPRateLimiter(time.Minute, requestsPerMinute)

	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !limiter.isAllowed(ip) {
			c.JSON(429, gin.H{"error": "请求过于频繁，请稍后再试"})
			c.Abort()
			return
		}
		c.Next()
	}
}
