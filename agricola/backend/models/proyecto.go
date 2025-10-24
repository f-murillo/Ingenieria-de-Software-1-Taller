package models

type Proyecto struct {
	ID          int    `json:"id"`
	Descripcion string `json:"descripcion"`
	FechaInicio string `json:"fecha_inicio"`
	FechaCierre string `json:"fecha_cierre"`
	Habilitado  bool   `json:"habilitado"`
}
