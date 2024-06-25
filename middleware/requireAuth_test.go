package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Zheol/microservicio-parking-users/database"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func setupRouter() *gin.Engine {
	r := gin.Default()
	r.Use(RequireAuth)
	r.GET("/test", func(c *gin.Context) {
		user, _ := c.Get("user")
		c.JSON(http.StatusOK, gin.H{
			"user": user,
		})
	})
	return r
}

func generateToken(secret string, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func TestRequireAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	secret := "mysecret"
	os.Setenv("SECRET", secret)

	// Crear la conexión de base de datos mock
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	// Configurar Gorm para usar la conexión de base de datos mock
	dialector := postgres.New(postgres.Config{
		Conn: db,
	})
	gormDB, err := gorm.Open(dialector, &gorm.Config{})
	assert.NoError(t, err)

	// Asignar la instancia de Gorm a la variable global de base de datos
	database.DB = gormDB

	r := setupRouter()

	tests := []struct {
		name           string
		token          string
		mockDB         func()
		expectedStatus int
	}{
		{
			name:           "No Authorization Cookie",
			token:          "",
			mockDB:         func() {},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Invalid Token",
			token: func() string {
				token, _ := generateToken(secret, jwt.MapClaims{
					"sub": int64(1),
					"exp": float64(time.Now().Add(time.Hour).Unix()),
				})
				return token + "invalid"
			}(),
			mockDB:         func() {},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Expired Token",
			token: func() string {
				token, _ := generateToken(secret, jwt.MapClaims{
					"sub": int64(1),
					"exp": float64(time.Now().Add(-time.Hour).Unix()),
				})
				return token
			}(),
			mockDB:         func() {},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Valid Token, User Not Found",
			token: func() string {
				token, _ := generateToken(secret, jwt.MapClaims{
					"sub": int64(1),
					"exp": float64(time.Now().Add(time.Hour).Unix()),
				})
				return token
			}(),
			mockDB: func() {
				mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"\."id" = \$1 AND "users"\."deleted_at" IS NULL ORDER BY "users"\."id" LIMIT \$2`).
					WithArgs(1, 1).
					WillReturnRows(sqlmock.NewRows([]string{"id", "name", "email", "password"}))
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Valid Token, User Found",
			token: func() string {
				token, _ := generateToken(secret, jwt.MapClaims{
					"sub": int64(1),
					"exp": float64(time.Now().Add(time.Hour).Unix()),
				})
				return token
			}(),
			mockDB: func() {
				rows := sqlmock.NewRows([]string{"id", "name", "email", "password"}).
					AddRow(1, "User One", "userone@example.com", "password")
				mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"\."id" = \$1 AND "users"\."deleted_at" IS NULL ORDER BY "users"\."id" LIMIT \$2`).
					WithArgs(1, 1).
					WillReturnRows(rows)
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockDB()

			req, _ := http.NewRequest(http.MethodGet, "/test", nil)
			if tt.token != "" {
				req.AddCookie(&http.Cookie{
					Name:  "Authorization",
					Value: tt.token,
				})
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("there were unfulfilled expectations: %s", err)
			}
		})
	}
}
