package handlers

import (
	"agricola/db"
	"agricola/models"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupCantidadTestDB(t *testing.T) {
	var err error
	db.DB, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Error al abrir base en memoria: %v", err)
	}

	queries := []string{
		`CREATE TABLE actividades_periodo (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actividad TEXT,
            accion TEXT,
            fecha_inicio TEXT,
            fecha_cierre TEXT,
            cantidad_horas INTEGER,
            responsable TEXT,
            monto REAL
        );`,
		`CREATE TABLE actividades_cantidad (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            periodo_id INTEGER,
            cantidad INTEGER,
            costo REAL,
            monto REAL
        );`,
	}

	for _, q := range queries {
		if _, err := db.DB.Exec(q); err != nil {
			t.Fatalf("Error al crear tabla: %v", err)
		}
	}
}

// Test CrearActividadCantidad y ObtenerTodosRecursosHumanos
func TestCrearYObtenerCantidad(t *testing.T) {
	setupCantidadTestDB(t)

	// Insertar periodo base para asociar recurso humano
	db.DB.Exec(`INSERT INTO actividades_periodo (actividad, accion, fecha_inicio, fecha_cierre, cantidad_horas, responsable, monto)
        VALUES ('Siembra', 'Labranza', '2025-11-01', '2025-11-05', 20, 'Pedro', 300)`)

	body := `{
        "periodo_id": 1,
        "cantidad": 5,
        "costo": 100,
        "monto": 500
    }`

	req := httptest.NewRequest(http.MethodPost, "/api/actividades_cantidad", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	CrearActividadCantidad(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("esperado 201 al crear recurso humano, obtuve %d", w.Code)
	}

	// Verificar respuesta JSON
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Error al decodificar respuesta: %v", err)
	}
	if resp["mensaje"] != "Recurso humano agregado" {
		t.Errorf("mensaje esperado 'Recurso humano agregado', obtuve %v", resp["mensaje"])
	}

	// Probar obtener todos
	req2 := httptest.NewRequest(http.MethodGet, "/api/actividades_cantidad", nil)
	w2 := httptest.NewRecorder()
	ObtenerTodosRecursosHumanos(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("esperado 200 al obtener recursos humanos, obtuve %d", w2.Code)
	}

	var recursos []models.ActividadCantidad
	if err := json.Unmarshal(w2.Body.Bytes(), &recursos); err != nil {
		t.Fatalf("Error al decodificar recursos: %v", err)
	}
	if len(recursos) != 1 {
		t.Errorf("esperado 1 recurso humano, obtuve %d", len(recursos))
	}
}

// Test ActualizarActividadCantidad
func TestActualizarCantidad(t *testing.T) {
	setupCantidadTestDB(t)

	// Insertar periodo y recurso inicial
	db.DB.Exec(`INSERT INTO actividades_periodo (actividad, accion, fecha_inicio, fecha_cierre, cantidad_horas, responsable, monto)
        VALUES ('Siembra', 'Labranza', '2025-11-01', '2025-11-05', 20, 'Pedro', 300)`)
	db.DB.Exec(`INSERT INTO actividades_cantidad (periodo_id, cantidad, costo, monto)
        VALUES (1, 5, 100, 500)`)

	body := `{
        "periodo_id": 1,
        "cantidad": 10,
        "costo": 200,
        "monto": 2000
    }`

	req := httptest.NewRequest(http.MethodPut, "/api/actividades_cantidad/1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	ActualizarActividadCantidad(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("esperado 200 al actualizar recurso humano, obtuve %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Error al decodificar respuesta: %v", err)
	}
	if resp["mensaje"] != "Recurso humano actualizado" {
		t.Errorf("mensaje esperado 'Recurso humano actualizado', obtuve %v", resp["mensaje"])
	}
}

// Test EliminarActividadCantidad
func TestEliminarCantidad(t *testing.T) {
	setupCantidadTestDB(t)

	// Insertar periodo y recurso inicial
	db.DB.Exec(`INSERT INTO actividades_periodo (actividad, accion, fecha_inicio, fecha_cierre, cantidad_horas, responsable, monto)
        VALUES ('Siembra', 'Labranza', '2025-11-01', '2025-11-05', 20, 'Pedro', 300)`)
	db.DB.Exec(`INSERT INTO actividades_cantidad (periodo_id, cantidad, costo, monto)
        VALUES (1, 5, 100, 500)`)

	req := httptest.NewRequest(http.MethodDelete, "/api/actividades_cantidad/1", nil)
	w := httptest.NewRecorder()

	EliminarActividadCantidad(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("esperado 200 al eliminar recurso humano, obtuve %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Error al decodificar respuesta: %v", err)
	}

	if resp["mensaje"] == nil {
		t.Errorf("esperado mensaje de eliminación, obtuve nil")
	}
}
