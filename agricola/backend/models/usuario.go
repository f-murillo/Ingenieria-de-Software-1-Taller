package models

type Usuario struct {
	ID            int    `json:"id"`
	Usuario       string `json:"usuario"`
	Cedula        string `json:"cedula"`
	Nombre        string `json:"nombre"`
	Apellido      string `json:"apellido"`
	Rol           string `json:"rol"`
	Proyecto      string `json:"proyecto"`
	Contraseña    string `json:"contraseña,omitempty"`
	Administrador bool   `json:"administrador"`
	Creador       string `json:"creador"`
}
