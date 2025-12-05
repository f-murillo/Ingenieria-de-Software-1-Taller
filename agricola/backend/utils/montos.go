package utils

import (
	"agricola/db"
)

func RecalcularMontosActividad(periodoID int) error {
	var totalRH float64
	var totalCat float64

	// Recursos humanos
	err := db.DB.QueryRow("SELECT COALESCE(SUM(monto),0) FROM actividades_cantidad WHERE periodo_id = ?", periodoID).Scan(&totalRH)
	if err != nil {
		return err
	}

	// Insumos y materiales
	err = db.DB.QueryRow("SELECT COALESCE(SUM(monto),0) FROM actividades_categoria WHERE periodo_id = ?", periodoID).Scan(&totalCat)
	if err != nil {
		return err
	}

	total := totalRH + totalCat

	// Actualizar monto en la tabla principal
	_, err = db.DB.Exec("UPDATE actividades_periodo SET monto = ? WHERE id = ?", total, periodoID)
	return err
}
