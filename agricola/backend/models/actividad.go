package models

type ActividadPorProyecto struct {
	ID            int     `json:"id"`
	Proyecto      string  `json:"proyecto"`
	Actividad     string  `json:"actividad"`
	Implemento    string  `json:"implemento"`
	Usuario       string  `json:"usuario"`
	RecursoHumano string  `json:"recurso_humano"`
	Observaciones string  `json:"observaciones"`
	Costo         float64 `json:"costo"`
}
