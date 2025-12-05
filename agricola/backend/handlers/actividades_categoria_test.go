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

func setupCategoriaTestDB(t *testing.T) {
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

// Test CrearActividadCategoria y ObtenerTodosActividadesCategoria
func TestCrearYObtenerCategoria(t *testing.T) {
	setupCategoriaTestDB(t)

	// Insertar periodo base para asociar insumo
	db.DB.Exec(`INSERT INTO actividades_periodo (actividad, accion, fecha_inicio, fecha_cierre, cantidad_horas, responsable, monto)
        VALUES ('Siembra', 'Labranza', '2025-11-01', '2025-11-05', 20, 'Pedro', 300)`)

	body := `{
        "periodo_id": 1,
        "categoria": "Semillas",
        "descripcion": "Semillas de maíz",
        "cantidad": 10,
        "medida": "kg",
        "monto": 500
    }`

	req := httptest.NewRequest(http.MethodPost, "/api/actividades_categoria", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	CrearActividadCategoria(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("esperado 201 al crear insumo, obtuve %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Error al decodificar respuesta: %v", err)
	}
	if resp["mensaje"] != "Insumo agregado" {
		t.Errorf("mensaje esperado 'Insumo agregado', obtuve %v", resp["mensaje"])
	}

	// Probar obtener todos
	req2 := httptest.NewRequest(http.MethodGet, "/api/actividades_categoria", nil)
	w2 := httptest.NewRecorder()
	ObtenerTodosActividadesCategoria(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("esperado 200 al obtener insumos, obtuve %d", w2.Code)
	}

	var insumos []models.ActividadCategoria
	if err := json.Unmarshal(w2.Body.Bytes(), &insumos); err != nil {
		t.Fatalf("Error al decodificar insumos: %v", err)
	}
	if len(insumos) != 1 {
		t.Errorf("esperado 1 insumo, obtuve %d", len(insumos))
	}
}

// Test ActualizarActividadCategoria
func TestActualizarCategoria(t *testing.T) {
	setupCategoriaTestDB(t)

	// Insertar periodo e insumo inicial
	db.DB.Exec(`INSERT INTO actividades_periodo (actividad, accion, fecha_inicio, fecha_cierre, cantidad_horas, responsable, monto)
        VALUES ('Siembra', 'Labranza', '2025-11-01', '2025-11-05', 20, 'Pedro', 300)`)
	db.DB.Exec(`INSERT INTO actividades_categoria (periodo_id, categoria, descripcion, cantidad, medida, monto)
        VALUES (1, 'Semillas', 'Semillas de maíz', 10, 'kg', 500)`)

	body := `{
        "periodo_id": 1,
        "categoria": "Fertilizante",
        "descripcion": "NPK 20-20-20",
        "cantidad": 5,
        "medida": "kg",
        "monto": 750
    }`

	req := httptest.NewRequest(http.MethodPut, "/api/actividades_categoria/1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	ActualizarActividadCategoria(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("esperado 200 al actualizar insumo, obtuve %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Error al decodificar respuesta: %v", err)
	}
	if resp["mensaje"] != "Insumo actualizado" {
		t.Errorf("mensaje esperado 'Insumo actualizado', obtuve %v", resp["mensaje"])
	}
}

// Test EliminarActividadCategoria
func TestEliminarCategoria(t *testing.T) {
	setupCategoriaTestDB(t)

	// Insertar periodo e insumo inicial
	db.DB.Exec(`INSERT INTO actividades_periodo (actividad, accion, fecha_inicio, fecha_cierre, cantidad_horas, responsable, monto)
        VALUES ('Siembra', 'Labranza', '2025-11-01', '2025-11-05', 20, 'Pedro', 300)`)
	db.DB.Exec(`INSERT INTO actividades_categoria (periodo_id, categoria, descripcion, cantidad, medida, monto)
        VALUES (1, 'Semillas', 'Semillas de maíz', 10, 'kg', 500)`)

	req := httptest.NewRequest(http.MethodDelete, "/api/actividades_categoria/1", nil)
	w := httptest.NewRecorder()

	EliminarActividadCategoria(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("esperado 200 al eliminar insumo, obtuve %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Error al decodificar respuesta: %v", err)
	}

	if resp["mensaje"] == nil {
		t.Errorf("esperado mensaje de eliminación, obtuve nil")
	}
}
