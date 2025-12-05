package handlers

import (
	"agricola/db"
	"agricola/models"
	"agricola/utils"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// Crear nueva actividad periodo
func CrearActividadPeriodo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	var periodo models.ActividadPeriodo
	if err := json.NewDecoder(r.Body).Decode(&periodo); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	result, err := db.DB.Exec(`
        INSERT INTO actividades_periodo (actividad, accion, fecha_inicio, fecha_cierre, cantidad_horas, responsable, monto)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
		periodo.Actividad, periodo.Accion, periodo.FechaInicio, periodo.FechaCierre,
		periodo.CantidadHoras, periodo.Responsable, periodo.Monto,
	)
	if err != nil {
		http.Error(w, "Error al insertar actividad periodo", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"mensaje": "Actividad periodo creada",
		"id":      id,
	})
}

// Obtener todas las actividades periodo
func ObtenerActividadesPeriodo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	rows, err := db.DB.Query(`
        SELECT id, actividad, accion, fecha_inicio, fecha_cierre, cantidad_horas, responsable, monto
        FROM actividades_periodo
        ORDER BY id DESC
    `)
	if err != nil {
		http.Error(w, "Error al consultar actividades periodo", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var actividades []models.ActividadPeriodo
	for rows.Next() {
		var a models.ActividadPeriodo
		if err := rows.Scan(&a.ID, &a.Actividad, &a.Accion, &a.FechaInicio, &a.FechaCierre,
			&a.CantidadHoras, &a.Responsable, &a.Monto); err != nil {
			http.Error(w, "Error al leer actividades periodo", http.StatusInternalServerError)
			return
		}
		actividades = append(actividades, a)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, "Error en filas de actividades periodo", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(actividades)
}

// Actualizar actividad periodo y recalcular recursos humanos asociados
func ActualizarActividadPeriodo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPut {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	// Extraer ID desde la URL
	path := strings.TrimPrefix(r.URL.Path, "/api/actividades_periodo/")
	idStr := strings.Split(path, "/")[0]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "ID inválido", http.StatusBadRequest)
		return
	}

	// Decodificar cuerpo JSON
	var datos struct {
		Actividad     string  `json:"actividad"`
		Accion        string  `json:"accion"`
		FechaInicio   string  `json:"fecha_inicio"`
		FechaCierre   string  `json:"fecha_cierre"`
		Responsable   string  `json:"responsable"`
		Monto         float64 `json:"monto"`
		CantidadHoras int     `json:"cantidad_horas"`
	}
	if err := json.NewDecoder(r.Body).Decode(&datos); err != nil {
		http.Error(w, "Error al decodificar JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Actualizar actividad principal
	_, err = db.DB.Exec(`
        UPDATE actividades_periodo
        SET actividad = ?, accion = ?, fecha_inicio = ?, fecha_cierre = ?,
            responsable = ?, monto = ?, cantidad_horas = ?
        WHERE id = ?
    `,
		datos.Actividad, datos.Accion, datos.FechaInicio, datos.FechaCierre,
		datos.Responsable, datos.Monto, datos.CantidadHoras, id,
	)
	if err != nil {
		http.Error(w, "Error al actualizar actividad periodo: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Recalcular montos de recursos humanos asociados
	_, err = db.DB.Exec(`
        UPDATE actividades_cantidad
        SET monto = cantidad * costo * ?
        WHERE periodo_id = ?
    `, datos.CantidadHoras, id)
	if err != nil {
		http.Error(w, "Error al recalcular montos de recursos humanos: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Recalculamos el monto
	_ = utils.RecalcularMontosActividad(id)

	// Devolver actividad actualizada
	actividad := models.ActividadPeriodo{
		ID:            id,
		Actividad:     datos.Actividad,
		Accion:        datos.Accion,
		FechaInicio:   datos.FechaInicio,
		FechaCierre:   datos.FechaCierre,
		Responsable:   datos.Responsable,
		Monto:         datos.Monto,
		CantidadHoras: datos.CantidadHoras,
	}
	json.NewEncoder(w).Encode(actividad)
}

// Eliminar actividad periodo y dependencias
func EliminarActividadPeriodo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodDelete {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	// Extraer ID desde la URL
	path := strings.TrimPrefix(r.URL.Path, "/api/actividades_periodo/")
	idStr := strings.Split(path, "/")[0]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "ID inválido", http.StatusBadRequest)
		return
	}

	// Borrar dependencias
	if _, err := db.DB.Exec(`DELETE FROM actividades_cantidad WHERE periodo_id = ?`, id); err != nil {
		http.Error(w, "Error al eliminar cantidades", http.StatusInternalServerError)
		return
	}

	if _, err := db.DB.Exec(`DELETE FROM actividades_categoria WHERE periodo_id = ?`, id); err != nil {
		http.Error(w, "Error al eliminar categorías", http.StatusInternalServerError)
		return
	}

	// Borrar actividad principal
	if _, err := db.DB.Exec(`DELETE FROM actividades_periodo WHERE id = ?`, id); err != nil {
		http.Error(w, "Error al eliminar actividad periodo", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
