package handlers

import (
	"agricola/db"
	"agricola/models"
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupEquiposTestDB(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Error al abrir base en memoria: %v", err)
	}
	db.DB = testDB

	_, err = db.DB.Exec(`CREATE TABLE equipos_implementos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        titulo TEXT NOT NULL
    );`)
	if err != nil {
		t.Fatalf("Error al crear tabla equipos: %v", err)
	}
}

func TestCrearYObtenerEquipo(t *testing.T) {
	setupEquiposTestDB(t)

	// Crear equipo
	body := bytes.NewBufferString(`{"titulo":"Sembradora neumática"}`)
	req := httptest.NewRequest("POST", "/api/equipos", body)
	w := httptest.NewRecorder()
	CrearEquipo(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Se esperaba 200 al crear equipo, pero se obtuvo %d", w.Code)
	}

	var equipo models.EquipoImplemento
	if err := json.NewDecoder(w.Body).Decode(&equipo); err != nil {
		t.Errorf("Error al decodificar respuesta de creación: %v", err)
	}
	if equipo.ID == 0 || equipo.Titulo != "Sembradora neumática" {
		t.Errorf("Equipo creado incorrectamente: %+v", equipo)
	}

	// Obtener equipos
	req = httptest.NewRequest("GET", "/api/equipos", nil)
	w = httptest.NewRecorder()
	ObtenerEquipos(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Se esperaba 200 al obtener equipos, pero se obtuvo %d", w.Code)
	}

	var lista []models.EquipoImplemento
	if err := json.NewDecoder(w.Body).Decode(&lista); err != nil {
		t.Errorf("Error al decodificar lista de equipos: %v", err)
	}
	if len(lista) != 1 || lista[0].Titulo != "Sembradora neumática" {
		t.Errorf("Lista de equipos incorrecta: %+v", lista)
	}
}

func TestActualizarEquipo(t *testing.T) {
	setupEquiposTestDB(t)

	// Insertar equipo manualmente
	res, err := db.DB.Exec(`INSERT INTO equipos_implementos (titulo) VALUES ('Pulverizador manual')`)
	if err != nil {
		t.Fatalf("Error al insertar equipo: %v", err)
	}
	id, _ := res.LastInsertId()

	// Actualizar equipo
	body := bytes.NewBufferString(`{"titulo":"Pulverizador motorizado"}`)
	req := httptest.NewRequest("PUT", "/api/equipos/"+strconv.Itoa(int(id)), body)
	w := httptest.NewRecorder()
	ActualizarEquipo(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Se esperaba 200 al actualizar equipo, pero se obtuvo %d", w.Code)
	}

	var equipo models.EquipoImplemento
	if err := json.NewDecoder(w.Body).Decode(&equipo); err != nil {
		t.Errorf("Error al decodificar respuesta de actualización: %v", err)
	}
	if equipo.ID != int(id) || equipo.Titulo != "Pulverizador motorizado" {
		t.Errorf("Actualización incorrecta: %+v", equipo)
	}
}

func TestEliminarEquipo(t *testing.T) {
	setupEquiposTestDB(t)

	// Insertar equipo manualmente
	res, err := db.DB.Exec(`INSERT INTO equipos_implementos (titulo) VALUES ('Tractor agrícola')`)
	if err != nil {
		t.Fatalf("Error al insertar equipo: %v", err)
	}
	id, _ := res.LastInsertId()

	// Eliminar equipo
	req := httptest.NewRequest("DELETE", "/api/equipos/"+strconv.Itoa(int(id)), nil)
	w := httptest.NewRecorder()
	EliminarEquipo(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Se esperaba 200 al eliminar equipo, pero se obtuvo %d", w.Code)
	}

	// Verificar que fue eliminado
	var count int
	err = db.DB.QueryRow("SELECT COUNT(*) FROM equipos_implementos WHERE id = ?", id).Scan(&count)
	if err != nil {
		t.Errorf("Error al verificar eliminación: %v", err)
	}
	if count != 0 {
		t.Errorf("El equipo no fue eliminado correctamente")
	}
}
