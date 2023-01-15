package main

import (
	"API_functionary/src/commun"
	"API_functionary/src/controller/routes"
	"database/sql"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
)

func ConfigDb() {
	var errConnect error
	commun.Db, errConnect = sql.Open("mysql", "root:94647177_Mc@tcp(localhost:3306)/model.functionarys")
	if errConnect != nil {
		log.Fatalln("Erro ao conectar com o banco: ", errConnect.Error())
		return
	}

	errPing := commun.Db.Ping()
	if errPing != nil {
		log.Fatalln("Erro ao pingar DB", errPing.Error())
	}
}

func main() {
	ConfigDb()
	Router := mux.NewRouter().StrictSlash(true)

	routes.SetRoutes(Router)

	log.Fatal(http.ListenAndServe(":8080", Router))
}
