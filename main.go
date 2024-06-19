package main

import (
	"log"
	"net"

	"github.com/joho/godotenv"
	"google.golang.org/grpc"

	"github.com/Zheol/microservicio-parking-users/db"
	"github.com/Zheol/microservicio-parking-users/models"
	"github.com/Zheol/microservicio-parking-users/routes"
	userpb "github.com/Zheol/microservicio-parking-users/user"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}
}

func main() {

	db.DBConnection()

	db.DB.AutoMigrate(models.User{})

	lis, err := net.Listen("tcp", ":8089")

	if err != nil {
		log.Fatalf("failed to listen: %s", err)
	}

	s := grpc.NewServer()
	service := &routes.UserServiceServer{}
	userpb.RegisterUserServiceServer(s, service)
	err = s.Serve(lis)
	if err != nil {
		log.Fatalf("failed to serve: %v", err)
	}

}
