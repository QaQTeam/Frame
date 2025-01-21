package jwts

import (
	"time"

	"github.com/golang-jwt/jwt"
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
