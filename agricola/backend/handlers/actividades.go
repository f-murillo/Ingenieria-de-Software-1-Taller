package handlers

import (
	"database/sql" // Asegúrate de importar "database/sql"
	"encoding/json"
	"net/http"
	"strconv" // Importa "strconv"
	"strings" // Importa "strings"

	"agricola/db"
	"agricola/models"
)

// Tu función existente
func ObtenerActividades(w http.ResponseWriter, r *http.Request) {
	// ... (sin cambios)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	rows, err := db.DB.Query(`
        SELECT 
            ap.id,
            p.descripcion AS proyecto,
            la.titulo AS actividad,
            ei.titulo AS implemento,
            u.nombre || ' ' || u.apellido AS usuario,
            ap.recurso_humano,
			ap.observaciones,
			ap.costo
        FROM actividades_por_proyecto ap
        JOIN proyectos p ON ap.proyecto_id = p.id
        JOIN labores_agronomicas la ON ap.actividad_id = la.id
        JOIN equipos_implementos ei ON ap.implemento_id = ei.id
        JOIN usuarios u ON ap.usuario_id = u.id;
    `)
	if err != nil {
		http.Error(w, "Error al consultar actividades", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var actividades []models.ActividadPorProyecto
	for rows.Next() {
		var act models.ActividadPorProyecto
		if err := rows.Scan(&act.ID, &act.Proyecto, &act.Actividad, &act.Implemento, &act.Usuario, &act.RecursoHumano, &act.Observaciones, &act.Costo); err != nil {
			http.Error(w, "Error al leer datos", http.StatusInternalServerError)
			return
		}
		actividades = append(actividades, act)
	}

	json.NewEncoder(w).Encode(actividades)
}

// --- NUEVAS FUNCIONES ---

func CrearActividad(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	var act models.ActividadInput
	if err := json.NewDecoder(r.Body).Decode(&act); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	// --- VALIDACIÓN CLAVE ---
	// Verificar si el usuario está asociado al proyecto
	var existe int
	err := db.DB.QueryRow(`
        SELECT 1 FROM usuarios_proyectos 
        WHERE usuario_id = ? AND proyecto_id = ?
    `, act.UsuarioID, act.ProyectoID).Scan(&existe)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Error: El usuario seleccionado no está asociado a este proyecto.", http.StatusForbidden)
			return
		}
		http.Error(w, "Error al validar usuario-proyecto", http.StatusInternalServerError)
		return
	}
	// --- FIN VALIDACIÓN ---

	// Si la validación pasa, insertamos
	stmt, err := db.DB.Prepare(`
        INSERT INTO actividades_por_proyecto 
        (proyecto_id, actividad_id, implemento_id, usuario_id, recurso_humano, observaciones, costo) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `)
	if err != nil {
		http.Error(w, "Error al preparar consulta", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(act.ProyectoID, act.ActividadID, act.ImplementoID, act.UsuarioID, act.RecursoHumano, act.Observaciones, act.Costo)
	if err != nil {
		http.Error(w, "Error al insertar actividad", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	act.ID = int(id)
	json.NewEncoder(w).Encode(act)
}

func ActualizarActividad(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/api/actividades/")
	id, err := strconv.Atoi(path)
	if err != nil {
		http.Error(w, "ID inválido", http.StatusBadRequest)
		return
	}

	var act models.ActividadInput
	if err := json.NewDecoder(r.Body).Decode(&act); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	// --- VALIDACIÓN CLAVE (igual que en Crear) ---
	var existe int
	err = db.DB.QueryRow(`
        SELECT 1 FROM usuarios_proyectos 
        WHERE usuario_id = ? AND proyecto_id = ?
    `, act.UsuarioID, act.ProyectoID).Scan(&existe)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Error: El usuario seleccionado no está asociado a este proyecto.", http.StatusForbidden)
			return
		}
		http.Error(w, "Error al validar usuario-proyecto", http.StatusInternalServerError)
		return
	}
	// --- FIN VALIDACIÓN ---

	_, err = db.DB.Exec(`
        UPDATE actividades_por_proyecto 
        SET proyecto_id = ?, actividad_id = ?, implemento_id = ?, usuario_id = ?, recurso_humano = ?, observaciones = ?, costo = ?
        WHERE id = ?
    `, act.ProyectoID, act.ActividadID, act.ImplementoID, act.UsuarioID, act.RecursoHumano, act.Observaciones, act.Costo, id)
	if err != nil {
		http.Error(w, "Error al actualizar actividad", http.StatusInternalServerError)
		return
	}
	act.ID = id
	json.NewEncoder(w).Encode(act)
}

func EliminarActividad(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	path := strings.TrimPrefix(r.URL.Path, "/api/actividades/")
	id, err := strconv.Atoi(path)
	if err != nil {
		http.Error(w, "ID inválido", http.StatusBadRequest)
		return
	}

	_, err = db.DB.Exec("DELETE FROM actividades_por_proyecto WHERE id = ?", id)
	if err != nil {
		http.Error(w, "Error al eliminar actividad", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"mensaje": "Actividad eliminada correctamente"})
}
