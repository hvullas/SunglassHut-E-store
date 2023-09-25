package db

import (
	"database/sql"
	"fmt"
	"log"
)

const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "postgres.123"
	dbname   = "sunglass_ecom"
)

var DB *sql.DB

func ConnectDB() {
	psqlinfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)
	var err error
	DB, err = sql.Open("postgres", psqlinfo)
	if err != nil {
		log.Fatalln(err)
	}
	// defer DB.Close()

}
