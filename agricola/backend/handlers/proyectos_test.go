package handlers

import (
	"agricola/db"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupProyectosTestDB(t *testing.T) {
	var err error
	db.DB, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Error al abrir base en memoria: %v", err)
	}

	_, err = db.DB.Exec(`
        CREATE TABLE proyectos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            descripcion TEXT NOT NULL,
            fecha_inicio TEXT NOT NULL,
            fecha_cierre TEXT,
            costo REAL DEFAULT 0,
            habilitado BOOLEAN NOT NULL DEFAULT 1
        );
    `)
	if err != nil {
		t.Fatalf("Error al crear tabla proyectos: %v", err)
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
        CREATE TABLE usuarios_proyectos (
            usuario_id INTEGER,
            proyecto_id INTEGER,
            PRIMARY KEY (usuario_id, proyecto_id)
        );
    `)
	if err != nil {
		t.Fatalf("Error al crear tabla usuarios_proyectos: %v", err)
	}
}

func TestCrearYObtenerProyecto(t *testing.T) {
	setupProyectosTestDB(t)

	body := `{
        "descripcion": "Proyecto Forestal",
        "fecha_inicio": "2025-01-01",
        "fecha_cierre": "2025-12-31"
    }`

	req := httptest.NewRequest(http.MethodPost, "/api/proyectos", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	CrearProyecto(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("esperado 200, obtuve %d", w.Code)
	}

	var p map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&p); err != nil {
		t.Errorf("Error al decodificar respuesta: %v", err)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/proyectos", nil)
	w = httptest.NewRecorder()
	ObtenerProyectos(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("esperado 200 al obtener proyectos, obtuve %d", w.Code)
	}

	var lista []map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&lista); err != nil {
		t.Errorf("Error al decodificar lista: %v", err)
	}
	if len(lista) != 1 {
		t.Errorf("Se esperaba 1 proyecto, se obtuvo %d", len(lista))
	}
}

func TestActualizarEstadoProyecto(t *testing.T) {
	setupProyectosTestDB(t)

	res, _ := db.DB.Exec(`INSERT INTO proyectos (descripcion, fecha_inicio, fecha_cierre) VALUES ('Test', '2025-01-01', '2025-12-31')`)
	id, _ := res.LastInsertId()

	body := `{"habilitado": false}`
	req := httptest.NewRequest(http.MethodPut, "/api/proyectos/"+strconv.Itoa(int(id)), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	ActualizarEstadoProyecto(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("esperado 200 al actualizar estado, obtuve %d", w.Code)
	}
}

func TestActualizarProyecto(t *testing.T) {
	setupProyectosTestDB(t)

	res, _ := db.DB.Exec(`INSERT INTO proyectos (descripcion, fecha_inicio, fecha_cierre) VALUES ('Antiguo', '2025-01-01', '2025-12-31')`)
	id, _ := res.LastInsertId()

	body := `{
        "descripcion": "Actualizado",
        "fecha_inicio": "2025-02-01",
        "fecha_cierre": "2025-11-30"
    }`
	req := httptest.NewRequest(http.MethodPut, "/api/proyectos/"+strconv.Itoa(int(id)), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	ActualizarProyecto(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("esperado 200 al actualizar proyecto, obtuve %d", w.Code)
	}

	var p map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&p); err != nil {
		t.Errorf("Error al decodificar respuesta: %v", err)
	}
	if p["descripcion"] != "Actualizado" {
		t.Errorf("Descripción incorrecta: %v", p["descripcion"])
	}
}

func TestAsociarYObtenerUsuariosPorProyecto(t *testing.T) {
	setupProyectosTestDB(t)

	db.DB.Exec(`INSERT INTO proyectos (id, descripcion, fecha_inicio, fecha_cierre) VALUES (1, 'Test', '2025-01-01', '2025-12-31')`)
	db.DB.Exec(`INSERT INTO usuarios (id, usuario, cedula, nombre, apellido, rol, proyecto, contraseña, administrador) VALUES (1, 'jdoe', 'V-123', 'John', 'Doe', 'Operador', 'Forestal', '1234', FALSE)`)

	body := `{"usuarios":[1]}`
	req := httptest.NewRequest(http.MethodPost, "/api/proyectos/1/usuarios", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	AsociarUsuariosAProyecto(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("esperado 201 al asociar usuarios, obtuve %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/proyectos/1/usuarios", nil)
	w = httptest.NewRecorder()
	ObtenerUsuariosPorProyecto(w, req)

	var usuarios []map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&usuarios); err != nil {
		t.Errorf("Error al decodificar usuarios: %v", err)
	}
	if len(usuarios) != 1 || usuarios[0]["usuario"] != "jdoe" {
		t.Errorf("Asociación incorrecta: %+v", usuarios)
	}
}

func TestObtenerProyectosPorUsuario(t *testing.T) {
	setupProyectosTestDB(t)

	db.DB.Exec(`INSERT INTO proyectos (id, descripcion, fecha_inicio, fecha_cierre) VALUES (1, 'Test', '2025-01-01', '2025-12-31')`)
	db.DB.Exec(`INSERT INTO usuarios (id, usuario, cedula, nombre, apellido, rol, proyecto, contraseña, administrador) VALUES (1, 'jdoe', 'V-123', 'John', 'Doe', 'Operador', 'Forestal', '1234', FALSE)`)
	db.DB.Exec(`INSERT INTO usuarios_proyectos (usuario_id, proyecto_id) VALUES (1, 1)`)

	req := httptest.NewRequest(http.MethodGet, "/api/usuarios/1/proyectos", nil)
	w := httptest.NewRecorder()
	ObtenerProyectosPorUsuario(w, req)

	var proyectos []map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&proyectos); err != nil {
		t.Errorf("Error al decodificar proyectos: %v", err)
	}
	if len(proyectos) != 1 || proyectos[0]["descripcion"] != "Test" {
		t.Errorf("Proyectos incorrectos: %+v", proyectos)
	}
}
