package handlers

import (
	"agricola/db"
	"agricola/models"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

func ObtenerEquipos(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	rows, err := db.DB.Query("SELECT id, titulo FROM equipos_implementos")
	if err != nil {
		http.Error(w, "Error al consultar equipos", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var equipos []models.EquipoImplemento
	for rows.Next() {
		var e models.EquipoImplemento
		if err := rows.Scan(&e.ID, &e.Titulo); err != nil {
			http.Error(w, "Error al leer datos", http.StatusInternalServerError)
			return
		}
		equipos = append(equipos, e)
	}

	json.NewEncoder(w).Encode(equipos)
}

func CrearEquipo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	var e models.EquipoImplemento
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	stmt, err := db.DB.Prepare("INSERT INTO equipos_implementos (titulo) VALUES (?)")
	if err != nil {
		http.Error(w, "Error al preparar consulta", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(e.Titulo)
	if err != nil {
		http.Error(w, "Error al insertar equipo", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	e.ID = int(id)
	json.NewEncoder(w).Encode(e)
	_ = LogEvento("Crear equipo", "equipos")
}

func ActualizarEquipo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/api/equipos/")
	id, err := strconv.Atoi(path)
	if err != nil {
		http.Error(w, "ID inválido", http.StatusBadRequest)
		return
	}

	var e models.EquipoImplemento
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	_, err = db.DB.Exec("UPDATE equipos_implementos SET titulo = ? WHERE id = ?", e.Titulo, id)
	if err != nil {
		http.Error(w, "Error al actualizar equipo", http.StatusInternalServerError)
		return
	}
	e.ID = id
	json.NewEncoder(w).Encode(e)
	_ = LogEvento("Editar equipo", "equipos")

}

func EliminarEquipo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/api/equipos/")
	id, err := strconv.Atoi(path)
	if err != nil {
		http.Error(w, "ID inválido", http.StatusBadRequest)
		return
	}

	_, err = db.DB.Exec("DELETE FROM equipos_implementos WHERE id = ?", id)
	if err != nil {
		http.Error(w, "Error al eliminar equipo", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"mensaje": "Equipo eliminado correctamente"})
	_ = LogEvento("Eliminar equipo", "equipos")
}
