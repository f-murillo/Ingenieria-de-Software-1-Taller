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

// Crear insumo/material asociado a una actividad
func CrearActividadCategoria(w http.ResponseWriter, r *http.Request) {
	var cat models.ActividadCategoria
	if err := json.NewDecoder(r.Body).Decode(&cat); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	_, err := db.DB.Exec(`
        INSERT INTO actividades_categoria (periodo_id, categoria, descripcion, cantidad, medida, monto)
        VALUES (?, ?, ?, ?, ?, ?)`,
		cat.PeriodoID, cat.Categoria, cat.Descripcion, cat.Cantidad, cat.Medida, cat.Monto,
	)
	if err != nil {
		http.Error(w, "Error al insertar insumo", http.StatusInternalServerError)
		return
	}

	// Recalcular monto en la actividad principal
	_ = utils.RecalcularMontosActividad(cat.PeriodoID)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"mensaje": "Insumo agregado"})
}

// Obtener todos los insumos de una actividad (por periodo_id)
func ObtenerActividadesCategoria(w http.ResponseWriter, r *http.Request) {
	periodoIDStr := strings.TrimPrefix(r.URL.Path, "/api/actividades_categoria/")
	periodoID, _ := strconv.Atoi(periodoIDStr)

	rows, err := db.DB.Query(`
        SELECT id, periodo_id, categoria, descripcion, cantidad, medida, monto
        FROM actividades_categoria
        WHERE periodo_id = ?`, periodoID)
	if err != nil {
		http.Error(w, "Error al consultar insumos", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var lista []models.ActividadCategoria
	for rows.Next() {
		var c models.ActividadCategoria
		if err := rows.Scan(&c.ID, &c.PeriodoID, &c.Categoria, &c.Descripcion, &c.Cantidad, &c.Medida, &c.Monto); err != nil {
			http.Error(w, "Error al leer insumos", http.StatusInternalServerError)
			return
		}
		lista = append(lista, c)
	}

	json.NewEncoder(w).Encode(lista)
}

// Obtener todos los insumos de todas las actividades
func ObtenerTodosActividadesCategoria(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`
        SELECT id, periodo_id, categoria, descripcion, cantidad, medida, monto
        FROM actividades_categoria
        ORDER BY periodo_id DESC, id DESC
    `)
	if err != nil {
		http.Error(w, "Error al consultar insumos", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var lista []models.ActividadCategoria
	for rows.Next() {
		var c models.ActividadCategoria
		if err := rows.Scan(&c.ID, &c.PeriodoID, &c.Categoria, &c.Descripcion, &c.Cantidad, &c.Medida, &c.Monto); err != nil {
			http.Error(w, "Error al leer insumos", http.StatusInternalServerError)
			return
		}
		lista = append(lista, c)
	}

	json.NewEncoder(w).Encode(lista)
}

// Actualizar insumo/material
func ActualizarActividadCategoria(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/actividades_categoria/")
	id, _ := strconv.Atoi(idStr)

	var cat models.ActividadCategoria
	if err := json.NewDecoder(r.Body).Decode(&cat); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	_, err := db.DB.Exec(`
        UPDATE actividades_categoria
        SET categoria = ?, descripcion = ?, cantidad = ?, medida = ?, monto = ?
        WHERE id = ?`,
		cat.Categoria, cat.Descripcion, cat.Cantidad, cat.Medida, cat.Monto, id,
	)
	if err != nil {
		http.Error(w, "Error al actualizar insumo", http.StatusInternalServerError)
		return
	}

	_ = utils.RecalcularMontosActividad(cat.PeriodoID)

	json.NewEncoder(w).Encode(map[string]string{"mensaje": "Insumo actualizado"})
}

// Eliminar insumo/material
func EliminarActividadCategoria(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/actividades_categoria/")
	id, _ := strconv.Atoi(idStr)

	var periodoID int
	if err := db.DB.QueryRow("SELECT periodo_id FROM actividades_categoria WHERE id = ?", id).Scan(&periodoID); err != nil {
		http.Error(w, "No se encontró insumo", http.StatusNotFound)
		return
	}

	_, err := db.DB.Exec("DELETE FROM actividades_categoria WHERE id = ?", id)
	if err != nil {
		http.Error(w, "Error al eliminar insumo", http.StatusInternalServerError)
		return
	}

	// Verificar si quedan insumos asociados a la actividad
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM actividades_categoria WHERE periodo_id = ?", periodoID).Scan(&count); err != nil {
		http.Error(w, "Error al verificar insumos restantes", http.StatusInternalServerError)
		return
	}

	if count == 0 {
		//  Si no quedan insumos, eliminar la actividad completa
		_, err := db.DB.Exec("DELETE FROM actividades_periodo WHERE id = ?", periodoID)
		if err != nil {
			http.Error(w, "Error al eliminar actividad asociada", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"mensaje": "Insumo y actividad eliminados"})
		return
	}

	// Si aún quedan insumos, recalcular montos
	_ = utils.RecalcularMontosActividad(periodoID)

	json.NewEncoder(w).Encode(map[string]string{"mensaje": "Insumo eliminado"})
}
