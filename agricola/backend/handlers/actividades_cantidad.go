package handlers

import (
	"agricola/db"
	"agricola/models"
	"agricola/utils" // aquí estará RecalcularMontosActividad
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// Crear recurso humano asociado a una actividad
func CrearActividadCantidad(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "Error al insertar recurso humano", http.StatusInternalServerError)
		return
	}

	// Recalcular monto en la actividad principal
	_ = utils.RecalcularMontosActividad(cantidad.PeriodoID)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"mensaje": "Recurso humano agregado"})
}

// Obtener TODOS los recursos humanos de todas las actividades
func ObtenerTodosRecursosHumanos(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`
        SELECT id, periodo_id, cantidad, costo, monto
        FROM actividades_cantidad
        ORDER BY periodo_id DESC, id DESC
    `)
	if err != nil {
		http.Error(w, "Error al consultar recursos humanos", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var lista []models.ActividadCantidad
	for rows.Next() {
		var c models.ActividadCantidad
		rows.Scan(&c.ID, &c.PeriodoID, &c.Cantidad, &c.Costo, &c.Monto)
		lista = append(lista, c)
	}

	json.NewEncoder(w).Encode(lista)
}

// Obtener recursos humanos de una actividad específica
func ObtenerActividadesCantidad(w http.ResponseWriter, r *http.Request) {
	periodoIDStr := strings.TrimPrefix(r.URL.Path, "/api/actividades_cantidad/")
	periodoID, _ := strconv.Atoi(periodoIDStr)

	rows, err := db.DB.Query("SELECT id, periodo_id, cantidad, costo, monto FROM actividades_cantidad WHERE periodo_id = ?", periodoID)
	if err != nil {
		http.Error(w, "Error al consultar recursos humanos", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var lista []models.ActividadCantidad
	for rows.Next() {
		var c models.ActividadCantidad
		rows.Scan(&c.ID, &c.PeriodoID, &c.Cantidad, &c.Costo, &c.Monto)
		lista = append(lista, c)
	}

	json.NewEncoder(w).Encode(lista)
}

// Actualizar recurso humano
func ActualizarActividadCantidad(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/actividades_cantidad/")
	id, _ := strconv.Atoi(idStr)

	var cantidad models.ActividadCantidad
	if err := json.NewDecoder(r.Body).Decode(&cantidad); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	_, err := db.DB.Exec(`
        UPDATE actividades_cantidad
        SET cantidad = ?, costo = ?, monto = ?
        WHERE id = ?`,
		cantidad.Cantidad, cantidad.Costo, cantidad.Monto, id,
	)
	if err != nil {
		http.Error(w, "Error al actualizar recurso humano", http.StatusInternalServerError)
		return
	}

	_ = utils.RecalcularMontosActividad(cantidad.PeriodoID)

	json.NewEncoder(w).Encode(map[string]string{"mensaje": "Recurso humano actualizado"})
}

// Eliminar recurso humano
func EliminarActividadCantidad(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/actividades_cantidad/")
	id, _ := strconv.Atoi(idStr)

	var periodoID int
	if err := db.DB.QueryRow("SELECT periodo_id FROM actividades_cantidad WHERE id = ?", id).Scan(&periodoID); err != nil {
		http.Error(w, "No se encontró recurso humano", http.StatusNotFound)
		return
	}

	// Eliminar recurso humano
	_, err := db.DB.Exec("DELETE FROM actividades_cantidad WHERE id = ?", id)
	if err != nil {
		http.Error(w, "Error al eliminar recurso humano", http.StatusInternalServerError)
		return
	}

	// Verificar si quedan recursos humanos asociados a la actividad
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM actividades_cantidad WHERE periodo_id = ?", periodoID).Scan(&count); err != nil {
		http.Error(w, "Error al verificar recursos humanos restantes", http.StatusInternalServerError)
		return
	}

	if count == 0 {
		// si no quedan recursos humanos, eliminar la actividad completa
		_, err := db.DB.Exec("DELETE FROM actividades_periodo WHERE id = ?", periodoID)
		if err != nil {
			http.Error(w, "Error al eliminar actividad asociada", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"mensaje": "Recurso humano y actividad eliminados"})
		return
	}

	// Si aún quedan recursos humanos, simplemente confirmamos la eliminación
	json.NewEncoder(w).Encode(map[string]string{"mensaje": "Recurso humano eliminado"})
}
