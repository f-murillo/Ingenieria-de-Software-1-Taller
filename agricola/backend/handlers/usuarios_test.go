package handlers

import (
	"agricola/db"
	"agricola/models"
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupUsuariosTestDB(t *testing.T) {
	var err error
	db.DB, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Error al abrir base en memoria: %v", err)
	}

	_, err = db.DB.Exec(`
        CREATE TABLE usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT,
            cedula TEXT,
            nombre TEXT,
            apellido TEXT,
            rol TEXT,
            proyecto TEXT,
            contraseña TEXT,
            administrador BOOLEAN DEFAULT FALSE
        );
    `)
	if err != nil {
		t.Fatalf("Error al crear tabla usuarios: %v", err)
	}

	_, err = db.DB.Exec(`
        INSERT INTO usuarios (usuario, cedula, nombre, apellido, rol, proyecto, contraseña, administrador)
        VALUES ('admin', 'V-00000000', 'Admin', 'Root', 'Supervisor', 'Agrícola', 'adminpass', TRUE)
    `)
	if err != nil {
		t.Fatalf("Error al insertar usuario admin: %v", err)
	}
}

func TestObtenerUsuarios(t *testing.T) {
	setupUsuariosTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/api/usuarios", nil)
	w := httptest.NewRecorder()

	ObtenerUsuarios(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("esperado status 200, obtuve %d", resp.StatusCode)
	}

	var usuarios []models.Usuario
	if err := json.NewDecoder(resp.Body).Decode(&usuarios); err != nil {
		t.Errorf("Error al decodificar respuesta: %v", err)
	}

	if len(usuarios) != 1 || usuarios[0].Usuario != "admin" {
		t.Errorf("Se esperaba 1 usuario 'admin', se obtuvo: %+v", usuarios)
	}
}

func TestCrearUsuario(t *testing.T) {
	setupUsuariosTestDB(t)

	body := `{
        "usuario": "jdoe",
        "cedula": "V-12345678",
        "nombre": "John",
        "apellido": "Doe",
        "rol": "Operador",
        "proyecto": "Forestal",
        "contraseña": "1234",
        "administrador": false,
        "creador": "admin"
    }`

	req := httptest.NewRequest(http.MethodPost, "/api/usuarios", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	CrearUsuario(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("esperado status 200, obtuve %d", resp.StatusCode)
	}

	var u models.Usuario
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		t.Errorf("Error al decodificar respuesta: %v", err)
	}

	if u.Usuario != "jdoe" || u.ID == 0 || u.Cedula != "V-12345678" {
		t.Errorf("Usuario creado incorrectamente: %+v", u)
	}
}

func TestLogin(t *testing.T) {
	setupUsuariosTestDB(t)

	body := `{"usuario": "admin", "contraseña": "adminpass"}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	Login(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("esperado status 200, obtuve %d", resp.StatusCode)
	}

	var u models.Usuario
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		t.Errorf("Error al decodificar respuesta: %v", err)
	}

	if u.Usuario != "admin" || !u.Administrador {
		t.Errorf("Login fallido, se obtuvo: %+v", u)
	}
}

func TestActualizarRolUsuario(t *testing.T) {
	setupUsuariosTestDB(t)

	_, err := db.DB.Exec(`
        INSERT INTO usuarios (usuario, cedula, nombre, apellido, rol, proyecto, contraseña, administrador)
        VALUES ('jdoe', 'V-12345678', 'John', 'Doe', 'Operador', 'Forestal', '1234', FALSE)
    `)
	if err != nil {
		t.Fatalf("Error al insertar usuario jdoe: %v", err)
	}

	body := `{"nuevoRol": "Supervisor"}`
	req := httptest.NewRequest(http.MethodPut, "/api/usuarios/2/rol", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	ActualizarRolUsuario(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("esperado status 200, obtuve %d", resp.StatusCode)
	}

	var res map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Errorf("Error al decodificar respuesta: %v", err)
	}

	if res["mensaje"] != "Rol actualizado correctamente" {
		t.Errorf("Mensaje inesperado: %v", res)
	}
}
