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

// Setup de base en memoria para pruebas de eventos
func setupEventosTestDB(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Error al abrir base en memoria: %v", err)
	}
	db.DB = testDB

	_, err = db.DB.Exec(`CREATE TABLE logger_eventos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evento TEXT NOT NULL,
        modulo TEXT NOT NULL,
        fecha TEXT NOT NULL,
        hora TEXT NOT NULL
    );`)
	if err != nil {
		t.Fatalf("Error al crear tabla logger_eventos: %v", err)
	}
}

func TestCrearYObtenerEvento(t *testing.T) {
	setupEventosTestDB(t)

	// Crear evento
	body := bytes.NewBufferString(`{"evento":"crear equipo","modulo":"equipos"}`)
	req := httptest.NewRequest("POST", "/api/eventos", body)
	w := httptest.NewRecorder()
	CrearEvento(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Se esperaba 200 al crear evento, pero se obtuvo %d", w.Code)
	}

	var evento models.LoggerEvento
	if err := json.NewDecoder(w.Body).Decode(&evento); err != nil {
		t.Errorf("Error al decodificar respuesta de creación: %v", err)
	}
	if evento.ID == 0 || evento.Evento != "crear equipo" || evento.Modulo != "equipos" {
		t.Errorf("Evento creado incorrectamente: %+v", evento)
	}

	// Obtener eventos
	req = httptest.NewRequest("GET", "/api/eventos", nil)
	w = httptest.NewRecorder()
	ObtenerEventos(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Se esperaba 200 al obtener eventos, pero se obtuvo %d", w.Code)
	}

	var lista []models.LoggerEvento
	if err := json.NewDecoder(w.Body).Decode(&lista); err != nil {
		t.Errorf("Error al decodificar lista de eventos: %v", err)
	}
	if len(lista) != 1 || lista[0].Evento != "crear equipo" {
		t.Errorf("Lista de eventos incorrecta: %+v", lista)
	}
}

func TestActualizarEvento(t *testing.T) {
	setupEventosTestDB(t)

	// Insertar evento manualmente
	res, err := db.DB.Exec(`INSERT INTO logger_eventos (evento, modulo, fecha, hora) VALUES ('crear proyecto','proyectos','2025-11-18','10:00:00')`)
	if err != nil {
		t.Fatalf("Error al insertar evento: %v", err)
	}
	id, _ := res.LastInsertId()

	// Actualizar evento
	body := bytes.NewBufferString(`{"evento":"actualizar proyecto","modulo":"proyectos","fecha":"2025-11-18","hora":"11:00:00"}`)
	req := httptest.NewRequest("PUT", "/api/eventos/"+strconv.Itoa(int(id)), body)
	w := httptest.NewRecorder()
	ActualizarEvento(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Se esperaba 200 al actualizar evento, pero se obtuvo %d", w.Code)
	}

	var evento models.LoggerEvento
	if err := json.NewDecoder(w.Body).Decode(&evento); err != nil {
		t.Errorf("Error al decodificar respuesta de actualización: %v", err)
	}
	if evento.ID != int(id) || evento.Evento != "actualizar proyecto" {
		t.Errorf("Actualización incorrecta: %+v", evento)
	}
}

func TestEliminarEvento(t *testing.T) {
	setupEventosTestDB(t)

	// Insertar evento manualmente
	res, err := db.DB.Exec(`INSERT INTO logger_eventos (evento, modulo, fecha, hora) VALUES ('eliminar labor','labores','2025-11-18','12:00:00')`)
	if err != nil {
		t.Fatalf("Error al insertar evento: %v", err)
	}
	id, _ := res.LastInsertId()

	// Eliminar evento
	req := httptest.NewRequest("DELETE", "/api/eventos/"+strconv.Itoa(int(id)), nil)
	w := httptest.NewRecorder()
	EliminarEvento(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Se esperaba 200 al eliminar evento, pero se obtuvo %d", w.Code)
	}

	// Verificar que fue eliminado
	var count int
	err = db.DB.QueryRow("SELECT COUNT(*) FROM logger_eventos WHERE id = ?", id).Scan(&count)
	if err != nil {
		t.Errorf("Error al verificar eliminación: %v", err)
	}
	if count != 0 {
		t.Errorf("El evento no fue eliminado correctamente")
	}
}

func TestLogEvento(t *testing.T) {
	setupEventosTestDB(t)

	// Usar directamente la función LogEvento
	err := LogEvento("crear usuario", "usuarios")
	if err != nil {
		t.Fatalf("Error al registrar evento con LogEvento: %v", err)
	}

	// Verificar que se insertó
	var count int
	err = db.DB.QueryRow("SELECT COUNT(*) FROM logger_eventos WHERE evento = 'crear usuario' AND modulo = 'usuarios'").Scan(&count)
	if err != nil {
		t.Errorf("Error al verificar inserción: %v", err)
	}
	if count != 1 {
		t.Errorf("Se esperaba 1 evento registrado, se obtuvo %d", count)
	}
}
