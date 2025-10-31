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

func setupProyectosTestDB(t *testing.T) {
	var err error
	db.DB, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Error al abrir base en memoria: %v", err)
	}

	// Crear tabla de proyectos
	_, err = db.DB.Exec(`
        CREATE TABLE proyectos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            descripcion TEXT NOT NULL,
            fecha_inicio TEXT NOT NULL,
            fecha_cierre TEXT,
            habilitado BOOLEAN NOT NULL DEFAULT 1
        );
    `)
	if err != nil {
		t.Fatalf("Error al crear tabla proyectos: %v", err)
	}
}

func TestCrearProyecto(t *testing.T) {
	setupProyectosTestDB(t)

	body := `{
        "descripcion": "Proyecto Test",
        "fecha_inicio": "2025-11-01",
        "fecha_cierre": "2025-12-01"
    }`

	req := httptest.NewRequest(http.MethodPost, "/api/proyectos", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	CrearProyecto(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("esperado status 200, obtuve %d", resp.StatusCode)
	}

	var p models.Proyecto
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		t.Errorf("Error al decodificar respuesta: %v", err)
	}

	if p.ID == 0 || p.Descripcion != "Proyecto Test" {
		t.Errorf("Proyecto creado incorrectamente: %+v", p)
	}
}

func TestObtenerProyectos(t *testing.T) {
	setupProyectosTestDB(t)

	// Insertar proyecto de prueba
	_, err := db.DB.Exec(`
        INSERT INTO proyectos (descripcion, fecha_inicio, fecha_cierre, habilitado)
        VALUES ('Proyecto Demo', '2025-11-01', '2025-12-01', 1)
    `)
	if err != nil {
		t.Fatalf("Error al insertar proyecto: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/proyectos", nil)
	w := httptest.NewRecorder()

	ObtenerProyectos(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("esperado status 200, obtuve %d", resp.StatusCode)
	}

	var proyectos []models.Proyecto
	if err := json.NewDecoder(resp.Body).Decode(&proyectos); err != nil {
		t.Errorf("Error al decodificar respuesta: %v", err)
	}

	if len(proyectos) != 1 || proyectos[0].Descripcion != "Proyecto Demo" {
		t.Errorf("Se esperaba 1 proyecto 'Proyecto Demo', se obtuvo: %+v", proyectos)
	}
}

func TestActualizarEstadoProyecto(t *testing.T) {
	setupProyectosTestDB(t)

	// Insertar proyecto habilitado
	_, err := db.DB.Exec(`
        INSERT INTO proyectos (descripcion, fecha_inicio, fecha_cierre, habilitado)
        VALUES ('Proyecto Estado', '2025-11-01', '2025-12-01', 1)
    `)
	if err != nil {
		t.Fatalf("Error al insertar proyecto: %v", err)
	}

	body := `{"habilitado": false}`
	req := httptest.NewRequest(http.MethodPut, "/api/proyectos/1/estado", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	ActualizarEstadoProyecto(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("esperado status 200, obtuve %d", resp.StatusCode)
	}

	// Verificar que se actualizó
	var estado bool
	err = db.DB.QueryRow("SELECT habilitado FROM proyectos WHERE id = 1").Scan(&estado)
	if err != nil {
		t.Fatalf("Error al consultar estado actualizado: %v", err)
	}
	if estado {
		t.Errorf("Se esperaba habilitado = false, pero se obtuvo true")
	}
}
