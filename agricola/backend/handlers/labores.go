package handlers

import (
	"agricola/db"
	"agricola/models"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

func ObtenerLabores(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	rows, err := db.DB.Query("SELECT id, titulo FROM labores_agronomicas")
	if err != nil {
		http.Error(w, "Error al consultar labores", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var labores []models.LaborAgronomica
	for rows.Next() {
		var l models.LaborAgronomica
		if err := rows.Scan(&l.ID, &l.Titulo); err != nil {
			http.Error(w, "Error al leer datos", http.StatusInternalServerError)
			return
		}
		labores = append(labores, l)
	}

	json.NewEncoder(w).Encode(labores)
}

func CrearLabor(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	var l models.LaborAgronomica
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	stmt, err := db.DB.Prepare("INSERT INTO labores_agronomicas (titulo) VALUES (?)")
	if err != nil {
		http.Error(w, "Error al preparar consulta", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(l.Titulo)
	if err != nil {
		http.Error(w, "Error al insertar labor", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	l.ID = int(id)
	json.NewEncoder(w).Encode(l)
	_ = LogEvento("Crear labor", "labores")
}

func ActualizarLabor(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	// Extraer ID desde la URL
	path := strings.TrimPrefix(r.URL.Path, "/api/labores/")
	id, err := strconv.Atoi(path)
	if err != nil {
		http.Error(w, "ID inválido", http.StatusBadRequest)
		return
	}

	var l models.LaborAgronomica
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	_, err = db.DB.Exec("UPDATE labores_agronomicas SET titulo = ? WHERE id = ?", l.Titulo, id)
	if err != nil {
		http.Error(w, "Error al actualizar labor", http.StatusInternalServerError)
		return
	}
	l.ID = id
	json.NewEncoder(w).Encode(l)
	_ = LogEvento("Editar labor", "labores")
}

func EliminarLabor(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	// Extraer ID desde la URL
	path := strings.TrimPrefix(r.URL.Path, "/api/labores/")
	id, err := strconv.Atoi(path)
	if err != nil {
		http.Error(w, "ID inválido", http.StatusBadRequest)
		return
	}

	_, err = db.DB.Exec("DELETE FROM labores_agronomicas WHERE id = ?", id)
	if err != nil {
		http.Error(w, "Error al eliminar labor", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"mensaje": "Labor eliminada correctamente"})
	_ = LogEvento("Eliminar labor", "labores")
}
