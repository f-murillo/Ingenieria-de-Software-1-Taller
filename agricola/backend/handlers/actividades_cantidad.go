package handlers

import (
	"agricola/db"
	"agricola/models"
	"encoding/json"
	"net/http"
)

func CrearActividadCantidad(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	var cantidad models.ActividadCantidad
	if err := json.NewDecoder(r.Body).Decode(&cantidad); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	_, err := db.DB.Exec(`
        INSERT INTO actividades_cantidad (periodo_id, cantidad, costo, monto)
        VALUES (?, ?, ?, ?)`,
		cantidad.PeriodoID, cantidad.Cantidad, cantidad.Costo, cantidad.Monto,
	)
	if err != nil {
		http.Error(w, "Error al insertar actividad cantidad", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"mensaje": "Actividad cantidad creada"})
}
