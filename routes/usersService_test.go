package routes

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Zheol/microservicio-parking-users/database"
	userpb "github.com/Zheol/microservicio-parking-users/user"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type UserTest struct {

    ID      uint
	Name     string 
	Email    string 
	Password string 
	TipoUser bool
}

// Mock database connection
func SetupMockDB() (*gorm.DB, sqlmock.Sqlmock, error) {
    db, mock, err := sqlmock.New()
    if err != nil {
        return nil, nil, err
    }
    dialector := postgres.New(postgres.Config{
        DSN:                  "sqlmock_db_0",
        DriverName:           "postgres",
        Conn:                 db,
        PreferSimpleProtocol: true,
    })
    gormDB, err := gorm.Open(dialector, &gorm.Config{})
    return gormDB, mock, err
}

func TestGetUsers(t *testing.T) {
    db, mock, err := SetupMockDB()
    if err != nil {
        t.Fatalf("Failed to setup mock db: %v", err)
    }

    // Mock data
    mockUsers := []UserTest{
        {ID: 1, Name: "User One", Email: "userone@example.com", Password: "password1", TipoUser: false},
        {ID: 2, Name: "User Two", Email: "usertwo@example.com", Password: "password2", TipoUser: true},
    }

    rows := sqlmock.NewRows([]string{"id", "name", "email", "password", "tipo_user"}).
        AddRow(mockUsers[0].ID, mockUsers[0].Name, mockUsers[0].Email, mockUsers[0].Password, mockUsers[0].TipoUser).
        AddRow(mockUsers[1].ID, mockUsers[1].Name, mockUsers[1].Email, mockUsers[1].Password, mockUsers[1].TipoUser)

    mock.ExpectQuery(`SELECT \* FROM "users"`).WillReturnRows(rows)

    // Assign the mock DB to your actual DB
    database.DB = db

    // Create the service server
    server := &UserServiceServer{}

    // Call the method to test
    req := &userpb.GetUsersRequest{}
    res, err := server.GetUsers(context.Background(), req)

    // Assertions
    assert.NoError(t, err)
    assert.NotNil(t, res)
    assert.Len(t, res.Users, 2)

    assert.Equal(t, uint64(1), res.Users[0].Id)
    assert.Equal(t, "User One", res.Users[0].Name)
    assert.Equal(t, "userone@example.com", res.Users[0].Email)
    assert.Equal(t, "password1", res.Users[0].Password)
    assert.Equal(t, false, res.Users[0].TipoUser)

    assert.Equal(t, uint64(2), res.Users[1].Id)
    assert.Equal(t, "User Two", res.Users[1].Name)
    assert.Equal(t, "usertwo@example.com", res.Users[1].Email)
    assert.Equal(t, "password2", res.Users[1].Password)
    assert.Equal(t, true, res.Users[1].TipoUser)

    // Ensure all expectations are met
    if err := mock.ExpectationsWereMet(); err != nil {
        t.Errorf("there were unfulfilled expectations: %s", err)
    }
}

func TestGetUser(t *testing.T) {
    db, mock, err := SetupMockDB()
    if err != nil {
        t.Fatalf("Failed to setup mock db: %v", err)
    }

    // Assign the mock DB to your actual DB
    database.DB = db

    // Create the service server
    server := &UserServiceServer{}

    t.Run("User found", func(t *testing.T) {
        // Mock data
        mockUser := UserTest{
            ID:       1,
            Name:     "User One",
            Email:    "userone@example.com",
            Password: "password1",
            TipoUser: false,
        }

        rows := sqlmock.NewRows([]string{"id", "name", "email", "password", "tipo_user"}).
            AddRow(mockUser.ID, mockUser.Name, mockUser.Email, mockUser.Password, mockUser.TipoUser)

        mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"."id" = \$1 AND "users"."deleted_at" IS NULL ORDER BY "users"."id" LIMIT \$2`).
            WithArgs(1, 1). // Incluimos el parámetro del límite
            WillReturnRows(rows)

        // Call the method to test
        req := &userpb.GetUserRequest{Id: 1}
        res, err := server.GetUser(context.Background(), req)

        // Assertions
        assert.NoError(t, err)
        assert.NotNil(t, res)
        assert.Equal(t, uint64(1), res.User.Id)
        assert.Equal(t, "User One", res.User.Name)
        assert.Equal(t, "userone@example.com", res.User.Email)
        assert.Equal(t, "password1", res.User.Password)
        assert.Equal(t, false, res.User.TipoUser)
    })

    t.Run("User not found", func(t *testing.T) {
        rows := sqlmock.NewRows([]string{"id", "name", "email", "password", "tipo_user"})

        mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"."id" = \$1 AND "users"."deleted_at" IS NULL ORDER BY "users"."id" LIMIT \$2`).
            WithArgs(2, 1). // Incluimos el parámetro del límite
            WillReturnRows(rows)

        // Call the method to test
        req := &userpb.GetUserRequest{Id: 2}
        res, err := server.GetUser(context.Background(), req)

        // Assertions
        assert.Nil(t, res)
        assert.Error(t, err)
        assert.Equal(t, codes.NotFound, status.Code(err))
        assert.Equal(t, "User not found", status.Convert(err).Message())
    })

    // Ensure all expectations are met
    if err := mock.ExpectationsWereMet(); err != nil {
        t.Errorf("there were unfulfilled expectations: %s", err)
    }
}

func TestValidate(t *testing.T) {
	db, mock, err := SetupMockDB()
	if err != nil {
		t.Fatalf("Failed to setup mock db: %v", err)
	}

	// Assign the mock DB to your actual DB
	database.DB = db

	// Create the service server
	server := &UserServiceServer{}

	t.Run("Valid token", func(t *testing.T) {
		// Mock data
		mockUser := UserTest{
			ID:       1,
			Name:     "User One",
			Email:    "userone@example.com",
			Password: "password1",
			TipoUser: false,
		}

		rows := sqlmock.NewRows([]string{"id", "name", "email", "password", "tipo_user"}).
			AddRow(mockUser.ID, mockUser.Name, mockUser.Email, mockUser.Password, mockUser.TipoUser)

		mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"."id" = \$1 AND "users"."deleted_at" IS NULL ORDER BY "users"."id" LIMIT \$2`).
			WithArgs(mockUser.ID, 1).
			WillReturnRows(rows)

		// Create a valid token
		secret := "mysecret"
		os.Setenv("SECRET", secret)
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": int64(mockUser.ID), // Asegúrate de que sea int64
			"exp": time.Now().Add(time.Hour * 24).Unix(),
		})
		tokenString, err := token.SignedString([]byte(secret))
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		// Call the method to test
		req := &userpb.ValidateRequest{Token: tokenString}
		res, err := server.Validate(context.Background(), req)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, res)
		assert.Equal(t, uint64(mockUser.ID), res.User.Id)
		assert.Equal(t, mockUser.Name, res.User.Name)
		assert.Equal(t, mockUser.Email, res.User.Email)
		assert.Equal(t, mockUser.Password, res.User.Password)
		assert.Equal(t, mockUser.TipoUser, res.User.TipoUser)
	})

	t.Run("Invalid token", func(t *testing.T) {
		// Create an invalid token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": int64(1), // Asegúrate de que sea int64
			"exp": time.Now().Add(time.Hour * 24).Unix(),
		})
		tokenString, err := token.SignedString([]byte("wrongsecret"))
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		// Call the method to test
		req := &userpb.ValidateRequest{Token: tokenString}
		res, err := server.Validate(context.Background(), req)

		// Assertions
		assert.Nil(t, res)
		assert.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
		assert.Equal(t, "Invalid token", status.Convert(err).Message())
	})

	t.Run("User not found", func(t *testing.T) {
		// Create a valid token
		secret := "mysecret"
		os.Setenv("SECRET", secret)
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": int64(2), // Asegúrate de que sea int64
			"exp": time.Now().Add(time.Hour * 24).Unix(),
		})
		tokenString, err := token.SignedString([]byte(secret))
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		rows := sqlmock.NewRows([]string{"id", "name", "email", "password", "tipo_user"})

		mock.ExpectQuery(`SELECT \* FROM "users" WHERE "users"."id" = \$1 AND "users"."deleted_at" IS NULL ORDER BY "users"."id" LIMIT \$2`).
			WithArgs(int64(2), 1). // Usar int64 aquí también
			WillReturnRows(rows)

		// Call the method to test
		req := &userpb.ValidateRequest{Token: tokenString}
		res, err := server.Validate(context.Background(), req)

		// Assertions
		assert.Nil(t, res)
		assert.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err))
		assert.Equal(t, "User not found", status.Convert(err).Message())
	})

	// Ensure all expectations are met
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestLogin(t *testing.T) {
    db, mock, err := SetupMockDB()
    if err != nil {
        t.Fatalf("Failed to setup mock db: %v", err)
    }

    // Assign the mock DB to your actual DB
    database.DB = db

    // Create the service server
    server := &UserServiceServer{}

    t.Run("Successful login", func(t *testing.T) {
        // Mock data
        mockUser := UserTest{
            ID:       1,
            Name:     "User One",
            Email:    "userone@example.com",
            Password: "$2a$10$QnweLEC1OhG53OmNvplvy.FlrCDHT0vgSxKQ0EDNGO5A9LKA2VJZy", // bcrypt hash for "password1"
            TipoUser: false,
        }

        rows := sqlmock.NewRows([]string{"id", "name", "email", "password", "tipo_user"}).
            AddRow(mockUser.ID, mockUser.Name, mockUser.Email, mockUser.Password, mockUser.TipoUser)

        mock.ExpectQuery(`SELECT \* FROM "users" WHERE email = \$1 AND "users"\."deleted_at" IS NULL ORDER BY "users"\."id" LIMIT \$2`).
            WithArgs(mockUser.Email, 1).
            WillReturnRows(rows)

        // Set the secret for JWT
        secret := "mysecret"
        os.Setenv("SECRET", secret)

        // Call the method to test
        req := &userpb.LoginRequest{Email: mockUser.Email, Password: "password1"}
        res, err := server.Login(context.Background(), req)

        // Assertions
        if err != nil {
            t.Fatalf("Expected no error, got %v", err)
        }
        if res == nil {
            t.Fatalf("Expected non-nil response")
        }
        if res.Token == "" {
            t.Fatalf("Expected non-empty token")
        }

        // Validate the token
        token, err := jwt.Parse(res.Token, func(token *jwt.Token) (interface{}, error) {
            return []byte(secret), nil
        })

        if err != nil {
            t.Fatalf("Failed to parse token: %v", err)
        }
        if !token.Valid {
            t.Fatalf("Token is not valid")
        }

        claims, ok := token.Claims.(jwt.MapClaims)
        if !ok {
            t.Fatalf("Failed to parse claims")
        }
        if claims["sub"].(float64) != float64(mockUser.ID) {
            t.Fatalf("Expected user ID %v, got %v", mockUser.ID, claims["sub"])
        }
        if claims["name"].(string) != mockUser.Name {
            t.Fatalf("Expected name %v, got %v", mockUser.Name, claims["name"])
        }
    })

    t.Run("Invalid email or password", func(t *testing.T) {
        // Mock data
        mockUser := UserTest{
            ID:       1,
            Name:     "User One",
            Email:    "userone@example.com",
            Password: "$2a$10$7b/6.jqG5F/NzI1HE1XUke5tOysHVtptHvECuGZd/C7X8U8V.Q1Gy", // bcrypt hash for "password1"
            TipoUser: false,
        }

        rows := sqlmock.NewRows([]string{"id", "name", "email", "password", "tipo_user"}).
            AddRow(mockUser.ID, mockUser.Name, mockUser.Email, mockUser.Password, mockUser.TipoUser)

        mock.ExpectQuery(`SELECT \* FROM "users" WHERE email = \$1 AND "users"\."deleted_at" IS NULL ORDER BY "users"\."id" LIMIT \$2`).
            WithArgs(mockUser.Email, 1).
            WillReturnRows(rows)

        // Call the method to test with wrong password
        req := &userpb.LoginRequest{Email: mockUser.Email, Password: "wrongpassword"}
        res, err := server.Login(context.Background(), req)

        // Assertions
        if res != nil {
            t.Fatalf("Expected nil response")
        }
        if err == nil {
            t.Fatalf("Expected error")
        }
        if status.Code(err) != codes.NotFound {
            t.Fatalf("Expected NotFound error, got %v", status.Code(err))
        }
        if status.Convert(err).Message() != "Invalid email or password" {
            t.Fatalf("Expected 'Invalid email or password', got %v", status.Convert(err).Message())
        }
    })

    t.Run("User not found", func(t *testing.T) {
        // Mock no user found
        rows := sqlmock.NewRows([]string{"id", "name", "email", "password", "tipo_user"})

        mock.ExpectQuery(`SELECT \* FROM "users" WHERE email = \$1 AND "users"\."deleted_at" IS NULL ORDER BY "users"\."id" LIMIT \$2`).
            WithArgs("nonexistent@example.com", 1).
            WillReturnRows(rows)

        // Call the method to test with non-existent email
        req := &userpb.LoginRequest{Email: "nonexistent@example.com", Password: "password"}
        res, err := server.Login(context.Background(), req)

        // Assertions
        if res != nil {
            t.Fatalf("Expected nil response")
        }
        if err == nil {
            t.Fatalf("Expected error")
        }
        if status.Code(err) != codes.NotFound {
            t.Fatalf("Expected NotFound error, got %v", status.Code(err))
        }
        if status.Convert(err).Message() != "Invalid email or password" {
            t.Fatalf("Expected 'Invalid email or password', got %v", status.Convert(err).Message())
        }
    })

    // Ensure all expectations are met
    if err := mock.ExpectationsWereMet(); err != nil {
        t.Errorf("there were unfulfilled expectations: %s", err)
    }
}


