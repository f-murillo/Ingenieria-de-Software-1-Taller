package models

type LoggerEvento struct {
	ID     int    `json:"id"`
	Evento string `json:"evento"`
	Modulo string `json:"modulo"`
	Fecha  string `json:"fecha"`
	Hora   string `json:"hora"`
}
