package handlers

import (
	"agricola/db"
	"agricola/models"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Obtener todos los eventos del logger
func ObtenerEventos(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	rows, err := db.DB.Query("SELECT id, evento, modulo, fecha, hora FROM logger_eventos ORDER BY id DESC")
	if err != nil {
		http.Error(w, "Error al consultar eventos", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var eventos []models.LoggerEvento
	for rows.Next() {
		var e models.LoggerEvento
		if err := rows.Scan(&e.ID, &e.Evento, &e.Modulo, &e.Fecha, &e.Hora); err != nil {
			http.Error(w, "Error al leer datos", http.StatusInternalServerError)
			return
		}
		eventos = append(eventos, e)
	}

	json.NewEncoder(w).Encode(eventos)
}

// Crear un evento en el logger
func CrearEvento(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	var e models.LoggerEvento
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	// Si no viene fecha/hora en el JSON, se asigna automáticamente
	if e.Fecha == "" {
		e.Fecha = time.Now().Format("2006-01-02")
	}
	if e.Hora == "" {
		e.Hora = time.Now().Format("15:04:05")
	}

	stmt, err := db.DB.Prepare("INSERT INTO logger_eventos (evento, modulo, fecha, hora) VALUES (?, ?, ?, ?)")
	if err != nil {
		http.Error(w, "Error al preparar consulta", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(e.Evento, e.Modulo, e.Fecha, e.Hora)
	if err != nil {
		http.Error(w, "Error al insertar evento", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	e.ID = int(id)
	json.NewEncoder(w).Encode(e)
}

// Actualizar un evento del logger
func ActualizarEvento(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/api/eventos/")
	id, err := strconv.Atoi(path)
	if err != nil {
		http.Error(w, "ID inválido", http.StatusBadRequest)
		return
	}

	var e models.LoggerEvento
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	_, err = db.DB.Exec("UPDATE logger_eventos SET evento = ?, modulo = ?, fecha = ?, hora = ? WHERE id = ?", e.Evento, e.Modulo, e.Fecha, e.Hora, id)
	if err != nil {
		http.Error(w, "Error al actualizar evento", http.StatusInternalServerError)
		return
	}
	e.ID = id
	json.NewEncoder(w).Encode(e)
}

// Eliminar un evento del logger
func EliminarEvento(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/api/eventos/")
	id, err := strconv.Atoi(path)
	if err != nil {
		http.Error(w, "ID inválido", http.StatusBadRequest)
		return
	}

	_, err = db.DB.Exec("DELETE FROM logger_eventos WHERE id = ?", id)
	if err != nil {
		http.Error(w, "Error al eliminar evento", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"mensaje": "Evento eliminado correctamente"})
}

func LogEvento(evento, modulo string) error {
	fecha := time.Now().Format("2006-01-02")
	hora := time.Now().Format("15:04:05")

	_, err := db.DB.Exec(
		"INSERT INTO logger_eventos (evento, modulo, fecha, hora) VALUES (?, ?, ?, ?)",
		evento, modulo, fecha, hora,
	)
	return err
}
