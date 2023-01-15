package db

import (
	"database/sql"
	"log"
)

func ConfigDb() {
	var db *sql.DB
	var errConnect error
	db, errConnect = sql.Open("mysql", "root:94647177_Mc@tcp(localhost:3306)/functionarys")
	if errConnect != nil {
		log.Fatalln("Erro ao conectar com o banco: ", errConnect.Error())
		return
	}

	errPing := db.Ping()
	if errPing != nil {
		log.Fatalln("Erro ao pingar DB", errPing.Error())
	}
}
