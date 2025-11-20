package handlers

import (
	"agricola/db"
	"agricola/models"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// Obtener todas las unidades de medida
func ObtenerUnidades(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	rows, err := db.DB.Query("SELECT id, dimension, unidad FROM unidades_medidas")
	if err != nil {
		http.Error(w, "Error al consultar unidades", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var unidades []models.UnidadMedida
	for rows.Next() {
		var u models.UnidadMedida
		if err := rows.Scan(&u.ID, &u.Dimension, &u.Unidad); err != nil {
			http.Error(w, "Error al leer datos", http.StatusInternalServerError)
			return
		}
		unidades = append(unidades, u)
	}

	json.NewEncoder(w).Encode(unidades)
}

// Crear una nueva unidad de medida
func CrearUnidad(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	var u models.UnidadMedida
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	stmt, err := db.DB.Prepare("INSERT INTO unidades_medidas (dimension, unidad) VALUES (?, ?)")
	if err != nil {
		http.Error(w, "Error al preparar consulta", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(u.Dimension, u.Unidad)
	if err != nil {
		http.Error(w, "Error al insertar unidad", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	u.ID = int(id)
	json.NewEncoder(w).Encode(u)
}

// Actualizar una unidad de medida existente
func ActualizarUnidad(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	// Extraemos el ID desde la URL: /api/unidades/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/unidades/")
	id, err := strconv.Atoi(path)
	if err != nil {
		http.Error(w, "ID inválido", http.StatusBadRequest)
		return
	}

	var u models.UnidadMedida
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	_, err = db.DB.Exec("UPDATE unidades_medidas SET dimension = ?, unidad = ? WHERE id = ?", u.Dimension, u.Unidad, id)
	if err != nil {
		http.Error(w, "Error al actualizar unidad", http.StatusInternalServerError)
		return
	}

	u.ID = id
	json.NewEncoder(w).Encode(u)
}

// Eliminar una unidad de medida
func EliminarUnidad(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	// Extraer ID desde la URL: /api/unidades/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/unidades/")
	id, err := strconv.Atoi(path)
	if err != nil {
		http.Error(w, "ID inválido", http.StatusBadRequest)
		return
	}

	_, err = db.DB.Exec("DELETE FROM unidades_medidas WHERE id = ?", id)
	if err != nil {
		http.Error(w, "Error al eliminar unidad", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"mensaje": "Unidad eliminada correctamente"})
}
