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

type UsuariosAsociacion struct {
	Usuarios []int `json:"usuarios"`
}

func ActualizarEstadoProyecto(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/proyectos/")
	idStr := strings.Split(path, "/")[0]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "ID inválido", http.StatusBadRequest)
		return
	}

	var body struct {
		Habilitado bool `json:"habilitado"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "JSON inválido", http.StatusBadRequest)
		return
	}

	_, err = db.DB.Exec(`UPDATE proyectos SET habilitado = ? WHERE id = ?`, body.Habilitado, id)
	if err != nil {
		http.Error(w, "Error al actualizar estado", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func ObtenerProyectos(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	rows, err := db.DB.Query("SELECT id, descripcion, fecha_inicio, fecha_cierre, habilitado FROM proyectos")
	if err != nil {
		http.Error(w, "Error al consultar proyectos", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var proyectos []models.Proyecto
	for rows.Next() {
		var p models.Proyecto
		if err := rows.Scan(&p.ID, &p.Descripcion, &p.FechaInicio, &p.FechaCierre, &p.Habilitado); err != nil {
			http.Error(w, "Error al leer datos", http.StatusInternalServerError)
			return
		}
		proyectos = append(proyectos, p)
	}

	json.NewEncoder(w).Encode(proyectos)
}

func CrearProyecto(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	var p models.Proyecto
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	stmt, err := db.DB.Prepare("INSERT INTO proyectos (descripcion, fecha_inicio, fecha_cierre) VALUES (?, ?, ?)")
	if err != nil {
		http.Error(w, "Error al preparar consulta", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(p.Descripcion, p.FechaInicio, p.FechaCierre)
	if err != nil {
		http.Error(w, "Error al insertar proyecto", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	p.ID = int(id)
	json.NewEncoder(w).Encode(p)
}

func ObtenerUsuariosPorProyecto(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	// Ruta esperada: /api/proyectos/{id}/usuarios
	path := strings.TrimPrefix(r.URL.Path, "/api/proyectos/")
	partes := strings.Split(path, "/")

	if len(partes) != 2 || partes[1] != "usuarios" {
		http.Error(w, "Ruta inválida", http.StatusBadRequest)
		return
	}

	proyectoID, err := strconv.Atoi(partes[0])
	if err != nil {
		http.Error(w, "ID inválido", http.StatusBadRequest)
		return
	}

	rows, err := db.DB.Query(`
        SELECT u.id, u.usuario, u.nombre, u.apellido, u.rol
        FROM usuarios u
        JOIN usuarios_proyectos up ON u.id = up.usuario_id
        WHERE up.proyecto_id = ?`, proyectoID)
	if err != nil {
		http.Error(w, "Error al consultar usuarios", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var usuarios []models.Usuario
	for rows.Next() {
		var u models.Usuario
		if err := rows.Scan(&u.ID, &u.Usuario, &u.Nombre, &u.Apellido, &u.Rol); err != nil {
			http.Error(w, "Error al leer datos", http.StatusInternalServerError)
			return
		}
		usuarios = append(usuarios, u)
	}

	json.NewEncoder(w).Encode(usuarios)
}

func AsociarUsuariosAProyecto(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	// Extraemos el id del proyecto desde la URL
	path := strings.TrimPrefix(r.URL.Path, "/api/proyectos/")
	partes := strings.Split(path, "/")
	if len(partes) != 2 || partes[1] != "usuarios" {
		http.Error(w, "Ruta inválida", http.StatusBadRequest)
		return
	}

	proyectoID, err := strconv.Atoi(partes[0])
	if err != nil {
		http.Error(w, "ID de proyecto inválido", http.StatusBadRequest)
		return
	}

	// Decodificar json con ids de usuarios
	var datos UsuariosAsociacion
	if err := json.NewDecoder(r.Body).Decode(&datos); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	// Insertamos las asociaciones en la tabla intermedia
	stmt, err := db.DB.Prepare(`
        INSERT OR IGNORE INTO usuarios_proyectos (usuario_id, proyecto_id)
        VALUES (?, ?)
    `)
	if err != nil {
		http.Error(w, "Error al preparar consulta", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	for _, usuarioID := range datos.Usuarios {
		_, err := stmt.Exec(usuarioID, proyectoID)
		if err != nil {
			http.Error(w, "Error al asociar usuario", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"mensaje": "Usuarios asociados correctamente",
	})
}

func ObtenerProyectosPorUsuario(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	// Ruta esperada: /api/usuarios/{id}/proyectos
	path := strings.TrimPrefix(r.URL.Path, "/api/usuarios/")
	partes := strings.Split(path, "/")

	if len(partes) != 2 || partes[1] != "proyectos" {
		http.Error(w, "Ruta inválida", http.StatusBadRequest)
		return
	}

	usuarioID, err := strconv.Atoi(partes[0])
	if err != nil {
		http.Error(w, "ID de usuario inválido", http.StatusBadRequest)
		return
	}

	rows, err := db.DB.Query(`
        SELECT p.id, p.descripcion, p.fecha_inicio, p.fecha_cierre
        FROM proyectos p
        JOIN usuarios_proyectos up ON p.id = up.proyecto_id
        WHERE up.usuario_id = ?`, usuarioID)
	if err != nil {
		http.Error(w, "Error al consultar proyectos del usuario", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var proyectos []models.Proyecto
	for rows.Next() {
		var p models.Proyecto
		if err := rows.Scan(&p.ID, &p.Descripcion, &p.FechaInicio, &p.FechaCierre); err != nil {
			http.Error(w, "Error al leer datos", http.StatusInternalServerError)
			return
		}
		proyectos = append(proyectos, p)
	}

	json.NewEncoder(w).Encode(proyectos)
}

func ActualizarProyecto(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPut {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	// Extraer ID desde la URL
	path := strings.TrimPrefix(r.URL.Path, "/api/proyectos/")
	idStr := strings.Split(path, "/")[0]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "ID inválido", http.StatusBadRequest)
		return
	}

	// Decodificar cuerpo JSON
	var datos struct {
		Descripcion string `json:"descripcion"`
		FechaInicio string `json:"fecha_inicio"`
		FechaCierre string `json:"fecha_cierre"`
	}
	if err := json.NewDecoder(r.Body).Decode(&datos); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	// Validar formato de fechas
	inicio, err := time.Parse("2006-01-02", datos.FechaInicio)
	if err != nil {
		http.Error(w, "Fecha de inicio inválida", http.StatusBadRequest)
		return
	}
	cierre, err := time.Parse("2006-01-02", datos.FechaCierre)
	if err != nil {
		http.Error(w, "Fecha de cierre inválida", http.StatusBadRequest)
		return
	}
	if cierre.Before(inicio) {
		http.Error(w, "La fecha de cierre no puede ser anterior a la de inicio", http.StatusBadRequest)
		return
	}

	// Ejecutar actualización
	_, err = db.DB.Exec(`
        UPDATE proyectos
        SET descripcion = ?, fecha_inicio = ?, fecha_cierre = ?
        WHERE id = ?
    `, datos.Descripcion, datos.FechaInicio, datos.FechaCierre, id)
	if err != nil {
		http.Error(w, "Error al actualizar proyecto", http.StatusInternalServerError)
		return
	}

	// Devolver proyecto actualizado
	proyecto := models.Proyecto{
		ID:          id,
		Descripcion: datos.Descripcion,
		FechaInicio: datos.FechaInicio,
		FechaCierre: datos.FechaCierre,
	}
	json.NewEncoder(w).Encode(proyecto)
}
