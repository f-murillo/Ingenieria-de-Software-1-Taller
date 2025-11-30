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

// Configura base en memoria con tablas necesarias
func setupPeriodosTestDB(t *testing.T) {
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
		`CREATE TABLE actividades_categoria (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            periodo_id INTEGER,
            categoria TEXT,
            descripcion TEXT,
            cantidad INTEGER,
            medida TEXT,
            monto REAL
        );`,
	}

	for _, q := range queries {
		if _, err := db.DB.Exec(q); err != nil {
			t.Fatalf("Error al crear tabla: %v", err)
		}
	}
}

// Test CrearActividadPeriodo y ObtenerActividadesPeriodo
func TestCrearYObtenerPeriodo(t *testing.T) {
	setupPeriodosTestDB(t)

	body := `{
        "actividad": "Siembra de maíz",
        "accion": "Labranza",
        "fecha_inicio": "2025-11-01",
        "fecha_cierre": "2025-11-10",
        "cantidad_horas": 40,
        "responsable": "Juan Pérez",
        "monto": 500
    }`

	req := httptest.NewRequest(http.MethodPost, "/api/actividades_periodo", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	CrearActividadPeriodo(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("esperado 201 al crear periodo, obtuve %d", w.Code)
	}

	// Verificar respuesta JSON
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Error al decodificar respuesta: %v", err)
	}
	if resp["mensaje"] != "Actividad periodo creada" {
		t.Errorf("mensaje esperado 'Actividad periodo creada', obtuve %v", resp["mensaje"])
	}

	// Probar obtener periodos
	req2 := httptest.NewRequest(http.MethodGet, "/api/actividades_periodo", nil)
	w2 := httptest.NewRecorder()
	ObtenerActividadesPeriodo(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("esperado 200 al obtener periodos, obtuve %d", w2.Code)
	}

	var periodos []models.ActividadPeriodo
	if err := json.Unmarshal(w2.Body.Bytes(), &periodos); err != nil {
		t.Fatalf("Error al decodificar periodos: %v", err)
	}
	if len(periodos) != 1 {
		t.Errorf("esperado 1 periodo, obtuve %d", len(periodos))
	}
}

// Test ActualizarActividadPeriodo
func TestActualizarPeriodo(t *testing.T) {
	setupPeriodosTestDB(t)

	// Insertar periodo inicial
	db.DB.Exec(`INSERT INTO actividades_periodo (actividad, accion, fecha_inicio, fecha_cierre, cantidad_horas, responsable, monto)
        VALUES ('Siembra', 'Labranza', '2025-11-01', '2025-11-05', 20, 'Pedro', 300)`)

	body := `{
        "actividad": "Siembra de arroz",
        "accion": "Riego",
        "fecha_inicio": "2025-11-02",
        "fecha_cierre": "2025-11-06",
        "responsable": "Maria",
        "monto": 400,
        "cantidad_horas": 25
    }`

	req := httptest.NewRequest(http.MethodPut, "/api/actividades_periodo/1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	ActualizarActividadPeriodo(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("esperado 200 al actualizar periodo, obtuve %d", w.Code)
	}

	var actualizado models.ActividadPeriodo
	if err := json.Unmarshal(w.Body.Bytes(), &actualizado); err != nil {
		t.Fatalf("Error al decodificar periodo actualizado: %v", err)
	}
	if actualizado.Actividad != "Siembra de arroz" {
		t.Errorf("esperado 'Siembra de arroz', obtuve %s", actualizado.Actividad)
	}
}

// Test EliminarActividadPeriodo
func TestEliminarPeriodo(t *testing.T) {
	setupPeriodosTestDB(t)

	// Insertar periodo inicial
	db.DB.Exec(`INSERT INTO actividades_periodo (actividad, accion, fecha_inicio, fecha_cierre, cantidad_horas, responsable, monto)
        VALUES ('Siembra', 'Labranza', '2025-11-01', '2025-11-05', 20, 'Pedro', 300)`)

	req := httptest.NewRequest(http.MethodDelete, "/api/actividades_periodo/1", nil)
	w := httptest.NewRecorder()

	EliminarActividadPeriodo(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("esperado 204 al eliminar periodo, obtuve %d", w.Code)
	}

	// Verificar que ya no exista
	rows, _ := db.DB.Query(`SELECT * FROM actividades_periodo WHERE id = 1`)
	defer rows.Close()
	if rows.Next() {
		t.Errorf("esperado que el periodo fuera eliminado")
	}
}
