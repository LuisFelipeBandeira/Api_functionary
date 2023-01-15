package routes

import (
	"API_functionary/src/controller/users"
	"net/http"

	"github.com/gorilla/mux"
)

func SetRoutes(mux *mux.Router) {
	mux.Use(jsonMiddleware)

	mux.HandleFunc("/funcs", users.ListAllFuncs).Methods("GET")

	mux.HandleFunc("/user", users.User).Methods("GET")

	mux.HandleFunc("/logout", users.LogOut).Methods("POST")

	mux.HandleFunc("/funcs/{FuncId}", users.ListOneFunc).Methods("GET")

	mux.HandleFunc("/funcs", users.InsertNewFunc).Methods("POST")

	mux.HandleFunc("/login", users.Login).Methods("POST")

	mux.HandleFunc("/funcs/{FuncId}", users.DeleteFunc).Methods("DELETE")

	mux.HandleFunc("/funcs/{FuncId}", users.UpdateUser).Methods("PUT")
}

func jsonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}
