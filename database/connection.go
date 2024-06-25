package database

import (
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DSN = "host=judicially-brilliant-armadillo.data-1.use1.tembo.io user=postgres password=76crJrXSXAzHnzCx dbname=postgres port=5432"

var DB *gorm.DB

func DBConnection() {
	var error error
	DB, error = gorm.Open(postgres.Open(DSN), &gorm.Config{})
	if error != nil {
		log.Fatal(error)
	}else {
		log.Println("DB Connected")
	}
}