package middleware

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Zheol/microservicio-parking-users/db"
	"github.com/Zheol/microservicio-parking-users/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func RequireAuth(c *gin.Context) {
    tokenString, err := c.Cookie("Authorization")
    if err != nil || tokenString == "" {
        fmt.Println("Authorization cookie missing or empty")
        c.AbortWithStatus(http.StatusUnauthorized)
        return
    }

    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            fmt.Println("Unexpected signing method:", token.Header["alg"])
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(os.Getenv("SECRET")), nil
    })
    if err != nil {
        fmt.Println("Failed to parse token:", err)
        c.AbortWithStatus(http.StatusUnauthorized)
        return
    }

    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        if exp, ok := claims["exp"].(float64); ok && float64(time.Now().Unix()) > exp {
            fmt.Println("Token has expired")
            c.AbortWithStatus(http.StatusUnauthorized)
            return
        }

        if sub, ok := claims["sub"].(float64); ok {
            var user models.User
            db.DB.First(&user, sub)
            if user.ID == 0 {
                fmt.Println("User not found in database")
                c.AbortWithStatus(http.StatusUnauthorized)
                return
            }

            c.Set("user", user)
            c.Next()
        } else {
            fmt.Println("Invalid 'sub' claim in token")
            c.AbortWithStatus(http.StatusUnauthorized)
        }
    } else {
        fmt.Println("Invalid token claims or token is not valid")
        c.AbortWithStatus(http.StatusUnauthorized)
    }
}
