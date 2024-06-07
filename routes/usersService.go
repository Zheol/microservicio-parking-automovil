package routes

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/Zheol/microservicio-parking-users/db"
	"github.com/Zheol/microservicio-parking-users/models"
	userpb "github.com/Zheol/microservicio-parking-users/user"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type UserServiceServer struct {
    userpb.UnimplementedUserServiceServer
}

func (s *UserServiceServer) GetUsers(ctx context.Context, req *userpb.GetUsersRequest) (*userpb.GetUsersResponse, error) {
    var users []models.User
    db.DB.Find(&users)

    var pbUsers []*userpb.User
    for _, user := range users {
        pbUsers = append(pbUsers, &userpb.User{
            Id:       uint64(user.ID),
            Name:     user.Name,
            Email:    user.Email,
            Password: user.Password,
            TipoUser: user.TipoUser,
        })
    }
    return &userpb.GetUsersResponse{Users: pbUsers}, nil
}


func (s *UserServiceServer) GetUser(ctx context.Context, req *userpb.GetUserRequest) (*userpb.GetUserResponse, error) {
    var user models.User
    db.DB.First(&user, req.Id)

    if user.ID == 0 {
        return nil, status.Errorf(codes.NotFound, "User not found")
    }

    return &userpb.GetUserResponse{
        User: &userpb.User{
            Id:       uint64(user.ID),
            Name:     user.Name,
            Email:    user.Email,
            Password: user.Password,
            TipoUser: user.TipoUser,
        },
    }, nil
}

func (s *UserServiceServer) CreateUser(ctx context.Context, req *userpb.CreateUserRequest) (*userpb.CreateUserResponse, error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        return nil, status.Errorf(codes.Internal, "Failed to hash password: %v", err)
    }

    user := models.User{
        Name:     req.Name,
        Email:    req.Email,
        Password: string(hash),
        TipoUser: req.TipoUser,
    }

    createdUser := db.DB.Create(&user)
    if createdUser.Error != nil {
        return nil, status.Errorf(codes.Internal, "Failed to create user: %v", createdUser.Error)
    }

    return &userpb.CreateUserResponse{
        User: &userpb.User{
            Id:       uint64(user.ID),
            Name:     user.Name,
            Email:    user.Email,
            Password: user.Password,
            TipoUser: user.TipoUser,
        },
    }, nil
}

func (s *UserServiceServer) DeleteUser(ctx context.Context, req *userpb.DeleteUserRequest) (*userpb.DeleteUserResponse, error) {
    var user models.User
    db.DB.First(&user, req.Id)

    if user.ID == 0 {
        return nil, status.Errorf(codes.NotFound, "User not found")
    }

    db.DB.Delete(&user)
    return &userpb.DeleteUserResponse{}, nil
}

func (s *UserServiceServer) Login(ctx context.Context, req *userpb.LoginRequest) (*userpb.LoginResponse, error) {
    var user models.User
    db.DB.First(&user, "email = ?", req.Email)

    if user.ID == 0 {
        return nil, status.Errorf(codes.NotFound, "Invalid email or password")
    }

    err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
    if err != nil {
        return nil, status.Errorf(codes.NotFound, "Invalid email or password")
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "sub": user.ID,
        "exp": time.Now().Add(time.Hour * 24).Unix(),
    })

    secret := os.Getenv("SECRET")
    if secret == "" {
        log.Println("SECRET environment variable is not set")
        return nil, status.Errorf(codes.Internal, "Internal server error")
    }

    tokenString, err := token.SignedString([]byte(secret))
    if err != nil {
        return nil, status.Errorf(codes.Internal, "Failed to create token: %v", err)
    }

    return &userpb.LoginResponse{Token: tokenString}, nil
}

func (s *UserServiceServer) Validate(ctx context.Context, req *userpb.ValidateRequest) (*userpb.ValidateResponse, error) {
    token, err := jwt.Parse(req.Token, func(token *jwt.Token) (interface{}, error) {
        return []byte(os.Getenv("SECRET")), nil
    })

    if err != nil || !token.Valid {
        return nil, status.Errorf(codes.Unauthenticated, "Invalid token")
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return nil, status.Errorf(codes.Internal, "Invalid token claims")
    }

    var user models.User
    db.DB.First(&user, claims["sub"])

    if user.ID == 0 {
        return nil, status.Errorf(codes.NotFound, "User not found")
    }

    return &userpb.ValidateResponse{
        User: &userpb.User{
            Id:       uint64(user.ID),
            Name:     user.Name,
            Email:    user.Email,
            Password: user.Password,
            TipoUser: user.TipoUser,
        },
    }, nil
}