package middleware

import (
	"sync"
	"time"
)

type TokenBlacklist struct {
	blacklist map[string]time.Time
	mu        sync.RWMutex
}

var (
	tokenBlacklist = &TokenBlacklist{
		blacklist: make(map[string]time.Time),
	}
)

// AddToBlacklist 将 token 加入黑名单
func (tb *TokenBlacklist) AddToBlacklist(token string, expiry time.Time) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.blacklist[token] = expiry
}

// IsBlacklisted 检查 token 是否在黑名单中
func (tb *TokenBlacklist) IsBlacklisted(token string) bool {
	tb.mu.RLock()
	defer tb.mu.RUnlock()
	expiry, exists := tb.blacklist[token]
	if !exists {
		return false
	}
	// 如果 token 已过期，从黑名单中移除
	if time.Now().After(expiry) {
		tb.mu.RUnlock()
		tb.mu.Lock()
		delete(tb.blacklist, token)
		tb.mu.Unlock()
		tb.mu.RLock()
		return false
	}
	return true
}

// CleanupExpired 清理过期的 token
func (tb *TokenBlacklist) CleanupExpired() {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	now := time.Now()
	for token, expiry := range tb.blacklist {
		if now.After(expiry) {
			delete(tb.blacklist, token)
		}
	}
}

// GetTokenBlacklist 获取 token 黑名单实例
func GetTokenBlacklist() *TokenBlacklist {
	return tokenBlacklist
}
