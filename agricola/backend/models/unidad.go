package models

type UnidadMedida struct {
	ID        int     `json:"id"`
	Dimension float64 `json:"dimension"`
	Unidad    string  `json:"unidad"`
}
