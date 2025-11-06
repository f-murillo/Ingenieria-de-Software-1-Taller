package handlers

import (
	"agricola/db"
	"agricola/models"
	"encoding/json"
	"net/http"
	"strconv"
)

func ObtenerUsuarios(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	rows, err := db.DB.Query("SELECT id, usuario, cedula, nombre, apellido, rol, proyecto, administrador FROM usuarios")
	if err != nil {
		http.Error(w, "Error al consultar usuarios", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var usuarios []models.Usuario
	for rows.Next() {
		var u models.Usuario
		if err := rows.Scan(&u.ID, &u.Usuario, &u.Cedula, &u.Nombre, &u.Apellido, &u.Rol, &u.Proyecto, &u.Administrador); err != nil {
			http.Error(w, "Error al leer datos", http.StatusInternalServerError)
			return
		}
		usuarios = append(usuarios, u)
	}

	json.NewEncoder(w).Encode(usuarios)
}

func CrearUsuario(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	var u models.Usuario
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}
	var esAdmin bool
	err := db.DB.QueryRow("SELECT administrador FROM usuarios WHERE usuario = ?", u.Creador).Scan(&esAdmin)
	if err != nil || !esAdmin {
		http.Error(w, "Solo un administrador puede crear usuarios", http.StatusForbidden)
		return
	}

	stmt, err := db.DB.Prepare("INSERT INTO usuarios (usuario, cedula, nombre, apellido, rol, proyecto, contraseña, administrador) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		http.Error(w, "Error al preparar consulta", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(u.Usuario, u.Cedula, u.Nombre, u.Apellido, u.Rol, u.Proyecto, u.Contraseña, u.Administrador)
	if err != nil {
		http.Error(w, "Error al insertar usuario", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	u.ID = int(id)
	json.NewEncoder(w).Encode(u)
}

func Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	var cred models.Usuario
	if err := json.NewDecoder(r.Body).Decode(&cred); err != nil {
		http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
		return
	}

	row := db.DB.QueryRow(`
		SELECT id, usuario, nombre, apellido, rol, proyecto, administrador
		FROM usuarios
		WHERE usuario = ? AND contraseña = ?
	`, cred.Usuario, cred.Contraseña)

	var u models.Usuario
	if err := row.Scan(&u.ID, &u.Usuario, &u.Nombre, &u.Apellido, &u.Rol, &u.Proyecto, &u.Administrador); err != nil {
		http.Error(w, "Credenciales inválidas", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(u)
}

func ActualizarRolUsuario(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPut {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	// Extraer el ID desde la URL
	idStr := r.URL.Path[len("/api/usuarios/"):]
	idStr = idStr[:len(idStr)-len("/rol")] // elimina el sufijo "/rol"
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "ID inválido", http.StatusBadRequest)
		return
	}

	// Leer el nuevo rol desde el cuerpo
	var body struct {
		NuevoRol string `json:"nuevoRol"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "JSON inválido", http.StatusBadRequest)
		return
	}
	if body.NuevoRol == "" {
		http.Error(w, "Rol vacío", http.StatusBadRequest)
		return
	}

	// Actualizar en la base de datos
	_, err = db.DB.Exec("UPDATE usuarios SET rol = ? WHERE id = ?", body.NuevoRol, id)
	if err != nil {
		http.Error(w, "Error al actualizar rol", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"mensaje": "Rol actualizado correctamente"})
}
