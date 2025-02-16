package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Secret key untuk signing JWT
// var jwtSecret = []byte("your-secret-key")

// Secret key untuk signing JWT
var (
	jwtAccessSecret  = []byte("access-secret-key")
	jwtRefreshSecret = []byte("refresh-secret-key")
)

// Contoh data user
var users = map[string]string{
	"user@example.com": "password123",
}

// Claim JWT
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Storage untuk refresh token
var refreshTokens = make(map[string]string)
var refreshMutex = &sync.RWMutex{}

// Claims JWT
type AccessClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type RefreshClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func main() {
	r := gin.Default()

	// Routes
	r.POST("/login", loginHandler)
	r.POST("/refresh", refreshHandler)

	authRoutes := r.Group("/")
	authRoutes.Use(authMiddleware())
	{
		authRoutes.GET("/protected", protectedHandler)
	}

	r.Run(":8090")
}

// [LOGIN HANDLER - Tetap sama sampai...]

func loginHandler(c *gin.Context) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&credentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Validasi credentials
	storedPassword, ok := users[credentials.Email]
	if !ok || storedPassword != credentials.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate Access Token
	accessExpiration := time.Now().Add(10 * time.Second)
	accessClaims := &AccessClaims{
		Username: credentials.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(accessExpiration),
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(jwtAccessSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating access token"})
		return
	}

	// Generate Refresh Token (7 hari)
	refreshExpiration := time.Now().Add(24 * 7 * time.Hour)
	refreshClaims := &RefreshClaims{
		Username: credentials.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshExpiration),
		},
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(jwtRefreshSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating refresh token"})
		return
	}

	// Simpan refresh token
	refreshMutex.Lock()
	refreshTokens[credentials.Email] = refreshTokenString
	refreshMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessTokenString,
		"refresh_token": refreshTokenString,
		"expires_in":    accessExpiration.Unix(),
	})
}

// Handler untuk refresh token
func refreshHandler(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Parse refresh token
	refreshToken, err := jwt.ParseWithClaims(
		req.RefreshToken,
		&RefreshClaims{},
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtRefreshSecret, nil
		},
	)

	if err != nil || !refreshToken.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	// Ekstrak claims
	claims, ok := refreshToken.Claims.(*RefreshClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		return
	}

	// Cek apakah refresh token valid di storage
	refreshMutex.RLock()
	storedToken, exists := refreshTokens[claims.Username]
	refreshMutex.RUnlock()

	if !exists || storedToken != req.RefreshToken {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token revoked"})
		return
	}

	// Generate access token baru
	newAccessExpiration := time.Now().Add(15 * time.Second)
	newAccessClaims := &AccessClaims{
		Username: claims.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(newAccessExpiration),
		},
	}
	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newAccessClaims)
	newAccessTokenString, err := newAccessToken.SignedString(jwtAccessSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating new access token"})
		return
	}

	// Generate refresh token baru (opsional)
	// Untuk keamanan lebih baik, generate refresh token baru setiap kali
	newRefreshExpiration := time.Now().Add(24 * 7 * time.Hour)
	newRefreshClaims := &RefreshClaims{
		Username: claims.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(newRefreshExpiration),
		},
	}
	newRefreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newRefreshClaims)
	newRefreshTokenString, err := newRefreshToken.SignedString(jwtRefreshSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating new refresh token"})
		return
	}

	// Update storage dengan refresh token baru
	refreshMutex.Lock()
	refreshTokens[claims.Username] = newRefreshTokenString
	refreshMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"access_token":  newAccessTokenString,
		"refresh_token": newRefreshTokenString,
		"expires_in":    newAccessExpiration.Unix(),
	})
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		// remove bearer if exist
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Ekstrak token dari header
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtAccessSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Set claims ke context
		if claims, ok := token.Claims.(*Claims); ok && token.Valid {
			c.Set("username", claims.Username)
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func protectedHandler(c *gin.Context) {
	username, _ := c.Get("username")
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Hello %s! You're authorized!", username),
	})
}
