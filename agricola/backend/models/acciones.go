package models

// Tabla principal: actividades_periodo
type ActividadPeriodo struct {
	ID            int     `json:"id"`
	Actividad     string  `json:"actividad"`
	Accion        string  `json:"accion"`
	FechaInicio   string  `json:"fecha_inicio"`
	FechaCierre   string  `json:"fecha_cierre"`
	CantidadHoras int     `json:"cantidad_horas"`
	Responsable   string  `json:"responsable"`
	Monto         float64 `json:"monto"`
}

// Tabla secundaria: actividades_cantidad
type ActividadCantidad struct {
	ID        int     `json:"id"`
	PeriodoID int     `json:"periodo_id"` // referencia a ActividadPeriodo
	Cantidad  int     `json:"cantidad"`
	Costo     float64 `json:"costo"`
	Monto     float64 `json:"monto"`
}

// Tabla secundaria: actividades_categoria
type ActividadCategoria struct {
	ID          int     `json:"id"`
	PeriodoID   int     `json:"periodo_id"` // referencia a ActividadPeriodo
	Categoria   string  `json:"categoria"`
	Descripcion string  `json:"descripcion"`
	Cantidad    int     `json:"cantidad"`
	Medida      string  `json:"medida"`
	Monto       float64 `json:"monto"`
}
