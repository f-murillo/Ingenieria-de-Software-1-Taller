package handlers

import (
	"encoding/json"
	"net/http"

	"agricola/db"
	"agricola/models"
)

func ObtenerActividades(w http.ResponseWriter, r *http.Request) {
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
            ap.recurso_humano
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
		if err := rows.Scan(&act.ID, &act.Proyecto, &act.Actividad, &act.Implemento, &act.Usuario, &act.RecursoHumano); err != nil {
			http.Error(w, "Error al leer datos", http.StatusInternalServerError)
			return
		}
		actividades = append(actividades, act)
	}

	json.NewEncoder(w).Encode(actividades)
}
