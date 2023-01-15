package model

type Functionary struct {
	Id         int    `json:"id"`
	Nome       string `json:"name"`
	Setor      string `json:"sector"`
	Email      string `json:"email"`
	Senha      string
	Permission int `json:"permission"`
}
