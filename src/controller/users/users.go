package users

import (
	"API_functionary/src/commun"
	"API_functionary/src/model"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

func PasswordHash(s string) string {
	str := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", str)
}

func UpdateUser(w http.ResponseWriter, r *http.Request) {
	cookie, errGetCookie := r.Cookie("jwt")
	if errGetCookie != nil {
		log.Println("UpdateUser: Error to get cookie")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("User not loged"))
		return
	}

	token, errGetToken := jwt.ParseWithClaims(cookie.Value, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(commun.SecretKey), nil
	})

	if errGetToken != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("User not loged"))
		return
	}

	claims := token.Claims.(*jwt.StandardClaims)

	result := commun.Db.QueryRow("SELECT AdmPermission FROM funcs WHERE Id = ?", claims.Issuer)

	var userDB model.Functionary

	errScan := result.Scan(&userDB.Permission)
	if errScan != nil {
		log.Println("User: Error ao realizar scan: ", errScan.Error())
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode("User not found")
		return
	}

	if userDB.Permission != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Usuário não tem permissão"))
		return
	}

	vars := mux.Vars(r)
	id, errConv := strconv.Atoi(vars["FuncId"])
	if errConv != nil {
		log.Println("UpdateUser: Error ao realizar converção: ", errConv.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	body, errBody := io.ReadAll(r.Body)
	if errBody != nil {
		log.Println("UpdateUser: Error ao pegar body: ", errBody.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var userUpdated model.Functionary

	json.Unmarshal(body, &userUpdated)

	userUpdated.Senha = PasswordHash(userUpdated.Senha)

	row, errSelectContent := commun.Db.Query("SELECT COUNT(*) FROM funcs WHERE Id = ?", id)
	if errSelectContent != nil {
		log.Println("UpdateUser: Error ao buscar funcionário para ser atualizado: ", errSelectContent.Error())
		w.WriteHeader(http.StatusNotFound)
	}

	var count int

	for row.Next() {
		errScan := row.Scan(&count)
		if errScan != nil {
			log.Println("UpdateUser: Error ao realizar Scan: ", errScan.Error())
			return
		}
	}

	if count == 1 {
		if userUpdated.Nome != "" {
			updateName, _ := commun.Db.Prepare("UPDATE funcs SET Name = ? WHERE Id = ?")
			updateName.Exec(userUpdated.Nome, id)
		}
		if userUpdated.Setor != "" {
			updateSetor, _ := commun.Db.Prepare("UPDATE funcs SET Sector = ? WHERE Id = ?")
			updateSetor.Exec(userUpdated.Setor, id)
		}
		if userUpdated.Email != "" {
			updateEmail, _ := commun.Db.Prepare("UPDATE funcs SET Email = ? WHERE Id = ?")
			updateEmail.Exec(userUpdated.Email, id)
		}
		if userUpdated.Senha != "" {
			updatePassword, _ := commun.Db.Prepare("UPDATE funcs SET Password = ? WHERE Id = ?")
			updatePassword.Exec(userUpdated.Senha, id)
		}
		json.NewEncoder(w).Encode("Funcionário atualizado com sucesso!")
		w.WriteHeader(http.StatusOK)
		return
	} else {
		w.WriteHeader(http.StatusNotFound)
		return
	}
}

func DeleteFunc(w http.ResponseWriter, r *http.Request) {
	cookie, errGetCookie := r.Cookie("jwt")
	if errGetCookie != nil {
		log.Println("UpdateUser: Error to get cookie")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("User not loged"))
		return
	}

	token, errGetToken := jwt.ParseWithClaims(cookie.Value, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(commun.SecretKey), nil
	})

	if errGetToken != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("User not loged"))
		return
	}

	claims := token.Claims.(*jwt.StandardClaims)

	result := commun.Db.QueryRow("SELECT AdmPermission FROM funcs WHERE Id = ?", claims.Issuer)

	var userDB model.Functionary

	errScan := result.Scan(&userDB.Permission)
	if errScan != nil {
		log.Println("User: Error ao realizar scan: ", errScan.Error())
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode("User not found")
		return
	}

	if userDB.Permission != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Usuário não tem permissão"))
		return
	}

	vars := mux.Vars(r)
	id, errConv := strconv.Atoi(vars["FuncId"])
	if errConv != nil {
		log.Println("DeleteFunc: Error ao realizar converção: ", errConv.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	delete, _ := commun.Db.Prepare("DELETE FROM funcs WHERE Id = ?")
	_, errDelete := delete.Exec(id)
	if errDelete != nil {
		log.Println("DeleteFunc: Error ao realizar DELETE: ", errDelete.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode("Funcionário deletado com sucesso!")
	w.WriteHeader(http.StatusOK)
}

func Login(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Fatalln("Error to get body of request")
	}

	var usrLogin model.Functionary

	json.Unmarshal(body, &usrLogin)

	var count int

	row, errSelect := commun.Db.Query("SELECT COUNT(*) FROM funcs WHERE Email = ?", usrLogin.Email)
	if errSelect != nil {
		log.Println("Login: Error ao buscar funcionário para login: ", errSelect.Error())
		w.WriteHeader(http.StatusNotFound)
		return
	}

	for row.Next() {
		errScan := row.Scan(&count)
		if errScan != nil {
			log.Println("Login: Error ao realizar Scan: ", errScan.Error())
			return
		}
	}

	result := commun.Db.QueryRow("SELECT Id, Name, Sector, Email, Password FROM funcs WHERE Email = ?", usrLogin.Email)

	var FuncDB model.Functionary

	errScan := result.Scan(&FuncDB.Id, &FuncDB.Nome, &FuncDB.Setor, &FuncDB.Email, &FuncDB.Senha)
	if errScan != nil {
		log.Println("Login: Error ao realizar scan: ", errScan.Error())
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("User not found"))
		return
	}

	if count == 1 {
		if FuncDB.Senha != PasswordHash(usrLogin.Senha) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Password invalid"))
		} else {
			claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
				Issuer:    strconv.Itoa(int(FuncDB.Id)),
				ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
			})

			token, err := claims.SignedString([]byte(commun.SecretKey))
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Não foi possível fazer o login"))
				return
			}

			Cookie := http.Cookie{
				Name:     "jwt",
				Value:    token,
				Expires:  time.Now().Add(time.Hour * 24),
				HttpOnly: true,
			}
			http.SetCookie(w, &Cookie)

			w.Write([]byte("Sucess"))
		}
	}
}

func InsertNewFunc(w http.ResponseWriter, r *http.Request) {
	cookie, errGetCookie := r.Cookie("jwt")
	if errGetCookie != nil {
		log.Println("UpdateUser: Error to get cookie")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("User not loged"))
		return
	}

	token, errGetToken := jwt.ParseWithClaims(cookie.Value, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(commun.SecretKey), nil
	})

	if errGetToken != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("User not loged"))
		return
	}

	claims := token.Claims.(*jwt.StandardClaims)

	result := commun.Db.QueryRow("SELECT AdmPermission FROM funcs WHERE Id = ?", claims.Issuer)

	var userDB model.Functionary

	errScan := result.Scan(&userDB.Permission)
	if errScan != nil {
		log.Println("User: Error ao realizar scan: ", errScan.Error())
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode("User not found")
		return
	}

	if userDB.Permission != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Usuário não tem permissão"))
		return
	}

	body, errBody := io.ReadAll(r.Body)
	if errBody != nil {
		log.Println("InsertNewFunc: Error ao pegar body: ", errBody.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var newUser model.Functionary

	errUnmarshal := json.Unmarshal(body, &newUser)
	if errUnmarshal != nil {
		log.Fatalln("Erro ao realizar Unmarshal do body para a struct")
	}

	newUser.Senha = PasswordHash(newUser.Senha)

	post, errPrep := commun.Db.Prepare("INSERT INTO funcs (Name, Sector, Email, Password, AdmPermission) VALUES (?, ?, ?, ?, ?)")
	if errPrep != nil {
		log.Fatalln("Erro prepare insert")
		w.WriteHeader(http.StatusInternalServerError)
	}

	_, errInsert := post.Exec(newUser.Nome, newUser.Setor, newUser.Email, newUser.Senha, newUser.Permission)

	if errInsert != nil {
		log.Println("InsertNewFunc: Error ao realizar Insert: ", errInsert.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Funcionário cadastrado com sucesso!"))
	w.WriteHeader(http.StatusOK)
}

func ListOneFunc(w http.ResponseWriter, r *http.Request) {
	cookie, errGetCookie := r.Cookie("jwt")
	if errGetCookie != nil {
		log.Println("UpdateUser: Error to get cookie")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("User not loged"))
		return
	}

	_, errGetToken := jwt.ParseWithClaims(cookie.Value, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(commun.SecretKey), nil
	})

	if errGetToken != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("User not loged"))
		return
	}

	vars := mux.Vars(r)
	id, errConv := strconv.Atoi(vars["FuncId"])
	if errConv != nil {
		log.Println("ListOneFunc: Error ao realizar converção: ", errConv.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	result := commun.Db.QueryRow("SELECT Id, Name, Sector, Email, AdmPermission FROM funcs WHERE Id = ?", id)

	var funct model.Functionary

	errScan := result.Scan(&funct.Id, &funct.Nome, &funct.Setor, &funct.Email, &funct.Permission)
	if errScan != nil {
		log.Println("ListOneFunc: Error ao realizar scan: ", errScan.Error())
		w.Write([]byte("User not found"))
		w.WriteHeader(http.StatusNotFound)
		return
	}

	errEnconde := json.NewEncoder(w).Encode(funct)
	if errEnconde != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println("ListOneFunc: Encode: ", errEnconde.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

func ListAllFuncs(w http.ResponseWriter, r *http.Request) {
	cookie, errGetCookie := r.Cookie("jwt")
	if errGetCookie != nil {
		log.Println("UpdateUser: Error to get cookie")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("User not loged"))
		return
	}

	_, errGetToken := jwt.ParseWithClaims(cookie.Value, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(commun.SecretKey), nil
	})

	if errGetToken != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("User not loged"))
		return
	}

	result, errSelect := commun.Db.Query("SELECT Id, Name, Sector, Email, AdmPermission Email FROM funcs")
	if errSelect != nil {
		log.Println("ListAllFuncs: Error ao realizar select: ", errSelect.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var Funcs []model.Functionary = make([]model.Functionary, 0)

	for result.Next() {
		var funct model.Functionary
		errScan := result.Scan(&funct.Id, &funct.Nome, &funct.Setor, &funct.Email, &funct.Permission)
		if errScan != nil {
			log.Println("ListAllFuncs: Error ao realizar scan: ", errScan.Error())
			continue
		}

		Funcs = append(Funcs, funct)
	}

	errClose := result.Close()
	if errSelect != nil {
		log.Println("ListAllFuncs: Error ao realizar close: ", errClose.Error())
		return
	}

	errEnconde := json.NewEncoder(w).Encode(Funcs)
	if errEnconde != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println("ListAllFuncs: Encode: ", errEnconde.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

func User(w http.ResponseWriter, r *http.Request) {
	cookie, errGetCookie := r.Cookie("jwt")
	if errGetCookie != nil {
		log.Println("User: Error to get cookie")
	}

	token, errGetToken := jwt.ParseWithClaims(cookie.Value, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(commun.SecretKey), nil
	})

	if errGetToken != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("User not loged"))
		return
	}

	claims := token.Claims.(*jwt.StandardClaims)

	result := commun.Db.QueryRow("SELECT Id, Name, Sector, Email, Password FROM funcs WHERE Id = ?", claims.Issuer)

	var userDB model.Functionary

	errScan := result.Scan(&userDB.Id, &userDB.Nome, &userDB.Setor, &userDB.Email, &userDB.Senha)
	if errScan != nil {
		log.Println("User: Error ao realizar scan: ", errScan.Error())
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode("User not found")
		return
	}

	json.NewEncoder(w).Encode(userDB)
}

func LogOut(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)

	json.NewEncoder(w).Encode("message: sucess")
}
