package handlers

import (
	"agricola/db"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupActividadesTestDB(t *testing.T) {
	var err error
	db.DB, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Error al abrir base en memoria: %v", err)
	}

	queries := []string{
		`CREATE TABLE usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT,
            cedula TEXT,
            nombre TEXT,
            apellido TEXT,
            rol TEXT,
            proyecto TEXT,
            contraseña TEXT,
            administrador BOOLEAN DEFAULT FALSE
        );`,
		`CREATE TABLE proyectos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            descripcion TEXT,
            fecha_inicio TEXT,
            fecha_cierre TEXT,
            costo REAL DEFAULT 0,
            habilitado BOOLEAN DEFAULT TRUE
        );`,
		`CREATE TABLE usuarios_proyectos (
            usuario_id INTEGER,
            proyecto_id INTEGER,
            PRIMARY KEY (usuario_id, proyecto_id)
        );`,
		`CREATE TABLE labores_agronomicas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT
        );`,
		`CREATE TABLE equipos_implementos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT
        );`,
		`CREATE TABLE actividades_por_proyecto (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            proyecto_id INTEGER,
            actividad_id INTEGER,
            implemento_id INTEGER,
            usuario_id INTEGER,
            recurso_humano TEXT,
            observaciones TEXT,
            costo REAL
        );`,
	}

	for _, q := range queries {
		if _, err := db.DB.Exec(q); err != nil {
			t.Fatalf("Error al crear tabla: %v", err)
		}
	}

	// Insertar datos base
	db.DB.Exec(`INSERT INTO usuarios (id, usuario, cedula, nombre, apellido, rol, proyecto, contraseña, administrador) VALUES (1, 'jdoe', 'V-123', 'John', 'Doe', 'Operador', 'Forestal', '1234', FALSE)`)
	db.DB.Exec(`INSERT INTO proyectos (id, descripcion, fecha_inicio, fecha_cierre) VALUES (1, 'Proyecto A', '2025-01-01', '2025-12-31')`)
	db.DB.Exec(`INSERT INTO usuarios_proyectos (usuario_id, proyecto_id) VALUES (1, 1)`)
	db.DB.Exec(`INSERT INTO labores_agronomicas (id, titulo) VALUES (1, 'Siembra')`)
	db.DB.Exec(`INSERT INTO equipos_implementos (id, titulo) VALUES (1, 'Tractor')`)
}

func TestCrearYObtenerActividad(t *testing.T) {
	setupActividadesTestDB(t)

	body := `{
        "proyecto_id": 1,
        "actividad_id": 1,
        "implemento_id": 1,
        "usuario_id": 1,
        "recurso_humano": "3 jornaleros",
        "observaciones": "Sin observaciones",
        "costo": 150.0
    }`

	req := httptest.NewRequest(http.MethodPost, "/api/actividades", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	CrearActividad(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("esperado 200 al crear actividad, obtuve %d", w.Code)
	}

	var act map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&act); err != nil {
		t.Errorf("Error al decodificar actividad: %v", err)
	}
	if act["id"] == nil || act["costo"] != 150.0 {
		t.Errorf("Actividad creada incorrectamente: %+v", act)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/actividades", nil)
	w = httptest.NewRecorder()
	ObtenerActividades(w, req)

	var lista []map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&lista); err != nil {
		t.Errorf("Error al decodificar lista: %v", err)
	}
	if len(lista) != 1 || lista[0]["usuario"] != "John Doe" {
		t.Errorf("Lista incorrecta: %+v", lista)
	}
}

func TestCrearActividadUsuarioNoAsociado(t *testing.T) {
	setupActividadesTestDB(t)

	// Usuario 2 no está asociado al proyecto
	db.DB.Exec(`INSERT INTO usuarios (id, usuario, cedula, nombre, apellido, rol, proyecto, contraseña, administrador) VALUES (2, 'mvera', 'V-456', 'María', 'Vera', 'Supervisor', 'Minería', 'pass', FALSE)`)

	body := `{
        "proyecto_id": 1,
        "actividad_id": 1,
        "implemento_id": 1,
        "usuario_id": 2,
        "recurso_humano": "1 técnico",
        "observaciones": "Sin acceso",
        "costo": 200.0
    }`

	req := httptest.NewRequest(http.MethodPost, "/api/actividades", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	CrearActividad(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("esperado 403 por usuario no asociado, obtuve %d", w.Code)
	}
}

func TestActualizarActividad(t *testing.T) {
	setupActividadesTestDB(t)

	db.DB.Exec(`INSERT INTO actividades_por_proyecto (id, proyecto_id, actividad_id, implemento_id, usuario_id, recurso_humano, observaciones, costo) VALUES (1, 1, 1, 1, 1, '2 jornaleros', 'Inicial', 100.0)`)

	body := `{
        "proyecto_id": 1,
        "actividad_id": 1,
        "implemento_id": 1,
        "usuario_id": 1,
        "recurso_humano": "4 jornaleros",
        "observaciones": "Actualizado",
        "costo": 180.0
    }`

	req := httptest.NewRequest(http.MethodPut, "/api/actividades/1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	ActualizarActividad(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("esperado 200 al actualizar actividad, obtuve %d", w.Code)
	}

	var act map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&act); err != nil {
		t.Errorf("Error al decodificar actividad: %v", err)
	}
	if act["observaciones"] != "Actualizado" {
		t.Errorf("Actualización incorrecta: %+v", act)
	}
}

func TestEliminarActividad(t *testing.T) {
	setupActividadesTestDB(t)

	db.DB.Exec(`INSERT INTO actividades_por_proyecto (id, proyecto_id, actividad_id, implemento_id, usuario_id, recurso_humano, observaciones, costo) VALUES (1, 1, 1, 1, 1, '2 jornaleros', 'Eliminar', 100.0)`)

	req := httptest.NewRequest(http.MethodDelete, "/api/actividades/1", nil)
	w := httptest.NewRecorder()

	EliminarActividad(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("esperado 200 al eliminar actividad, obtuve %d", w.Code)
	}

	var res map[string]string
	if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
		t.Errorf("Error al decodificar respuesta: %v", err)
	}
	if res["mensaje"] != "Actividad eliminada correctamente" {
		t.Errorf("Mensaje inesperado: %v", res)
	}
}
