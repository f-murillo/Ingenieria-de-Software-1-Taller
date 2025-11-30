package handlers

import (
	"agricola/db"
	"agricola/models"
	"encoding/json"
	"net/http"
)

func CrearActividadCategoria(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	var categoria models.ActividadCategoria
	if err := json.NewDecoder(r.Body).Decode(&categoria); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	_, err := db.DB.Exec(`
        INSERT INTO actividades_categoria (periodo_id, categoria, descripcion, cantidad, medida, monto)
        VALUES (?, ?, ?, ?, ?, ?)`,
		categoria.PeriodoID, categoria.Categoria, categoria.Descripcion,
		categoria.Cantidad, categoria.Medida, categoria.Monto,
	)
	if err != nil {
		http.Error(w, "Error al insertar actividad categoria", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"mensaje": "Actividad categoria creada"})
}
