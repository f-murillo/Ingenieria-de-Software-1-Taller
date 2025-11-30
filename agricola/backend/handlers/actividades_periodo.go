package handlers

import (
	"agricola/db"
	"agricola/models"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

func CrearActividadPeriodo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	var periodo models.ActividadPeriodo
	if err := json.NewDecoder(r.Body).Decode(&periodo); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	// Guardamos el resultado del Exec
	result, err := db.DB.Exec(`
        INSERT INTO actividades_periodo (actividad, accion, fecha_inicio, fecha_cierre, cantidad_horas, responsable, monto)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
		periodo.Actividad, periodo.Accion, periodo.FechaInicio, periodo.FechaCierre, periodo.CantidadHoras, periodo.Responsable, periodo.Monto,
	)
	if err != nil {
		http.Error(w, "Error al insertar actividad periodo", http.StatusInternalServerError)
		return
	}

	// Obtenemos el ID insertado
	id, _ := result.LastInsertId()

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"mensaje": "Actividad periodo creada",
		"id":      id,
	})
}

func ObtenerActividadesPeriodo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")

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
		if err := rows.Scan(&a.ID, &a.Actividad, &a.Accion, &a.FechaInicio, &a.FechaCierre, &a.CantidadHoras, &a.Responsable, &a.Monto); err != nil {
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

// handler.go

func ActualizarActividadPeriodo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPut {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	// Extraer ID desde la URL: /api/actividades_periodo/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/actividades_periodo/")
	idStr := strings.Split(path, "/")[0]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "ID inválido", http.StatusBadRequest)
		return
	}

	// Decodificar cuerpo JSON (ahora incluye cantidad_horas)
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
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	// Ejecutar UPDATE en la base de datos (ahora guarda cantidad_horas)
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
		http.Error(w, "Error al actualizar actividad periodo", http.StatusInternalServerError)
		return
	}

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

func EliminarActividadPeriodo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodDelete {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	// Extraer ID desde la URL: /api/actividades_periodo/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/actividades_periodo/")
	idStr := strings.Split(path, "/")[0]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "ID inválido", http.StatusBadRequest)
		return
	}

	// Primero borrar las dependencias (cantidad y categoría)
	_, err = db.DB.Exec(`DELETE FROM actividades_cantidad WHERE periodo_id = ?`, id)
	if err != nil {
		http.Error(w, "Error al eliminar cantidades", http.StatusInternalServerError)
		return
	}

	_, err = db.DB.Exec(`DELETE FROM actividades_categoria WHERE periodo_id = ?`, id)
	if err != nil {
		http.Error(w, "Error al eliminar categorías", http.StatusInternalServerError)
		return
	}

	// Finalmente borrar el periodo
	_, err = db.DB.Exec(`DELETE FROM actividades_periodo WHERE id = ?`, id)
	if err != nil {
		http.Error(w, "Error al eliminar actividad periodo", http.StatusInternalServerError)
		return
	}

	// Respuesta de éxito
	w.WriteHeader(http.StatusNoContent)
	_ = LogEvento("Eliminar actividad periodo", "actividades_periodo")
}
