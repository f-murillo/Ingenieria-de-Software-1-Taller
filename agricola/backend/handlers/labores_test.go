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

func setupLaboresTestDB(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Error al abrir base en memoria: %v", err)
	}
	db.DB = testDB

	_, err = db.DB.Exec(`CREATE TABLE labores_agronomicas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        titulo TEXT NOT NULL
    );`)
	if err != nil {
		t.Fatalf("Error al crear tabla labores: %v", err)
	}
}

func TestCrearYObtenerLabor(t *testing.T) {
	setupLaboresTestDB(t)

	// Crear labor
	body := bytes.NewBufferString(`{"titulo":"Riego por goteo"}`)
	req := httptest.NewRequest("POST", "/api/labores", body)
	w := httptest.NewRecorder()
	CrearLabor(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Se esperaba 200 al crear labor, pero se obtuvo %d", w.Code)
	}

	var labor models.LaborAgronomica
	if err := json.NewDecoder(w.Body).Decode(&labor); err != nil {
		t.Errorf("Error al decodificar respuesta de creación: %v", err)
	}
	if labor.ID == 0 || labor.Titulo != "Riego por goteo" {
		t.Errorf("Labor creada incorrectamente: %+v", labor)
	}

	// Obtener labores
	req = httptest.NewRequest("GET", "/api/labores", nil)
	w = httptest.NewRecorder()
	ObtenerLabores(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Se esperaba 200 al obtener labores, pero se obtuvo %d", w.Code)
	}

	var lista []models.LaborAgronomica
	if err := json.NewDecoder(w.Body).Decode(&lista); err != nil {
		t.Errorf("Error al decodificar lista de labores: %v", err)
	}
	if len(lista) != 1 || lista[0].Titulo != "Riego por goteo" {
		t.Errorf("Lista de labores incorrecta: %+v", lista)
	}
}

func TestActualizarLabor(t *testing.T) {
	setupLaboresTestDB(t)

	// Insertar labor manualmente
	res, err := db.DB.Exec(`INSERT INTO labores_agronomicas (titulo) VALUES ('Siembra manual')`)
	if err != nil {
		t.Fatalf("Error al insertar labor: %v", err)
	}
	id, _ := res.LastInsertId()

	// Actualizar labor
	body := bytes.NewBufferString(`{"titulo":"Siembra mecanizada"}`)
	req := httptest.NewRequest("PUT", "/api/labores/"+strconv.Itoa(int(id)), body)
	w := httptest.NewRecorder()
	ActualizarLabor(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Se esperaba 200 al actualizar labor, pero se obtuvo %d", w.Code)
	}

	var labor models.LaborAgronomica
	if err := json.NewDecoder(w.Body).Decode(&labor); err != nil {
		t.Errorf("Error al decodificar respuesta de actualización: %v", err)
	}
	if labor.ID != int(id) || labor.Titulo != "Siembra mecanizada" {
		t.Errorf("Actualización incorrecta: %+v", labor)
	}
}

func TestEliminarLabor(t *testing.T) {
	setupLaboresTestDB(t)

	// Insertar labor manualmente
	res, err := db.DB.Exec(`INSERT INTO labores_agronomicas (titulo) VALUES ('Fertilización')`)
	if err != nil {
		t.Fatalf("Error al insertar labor: %v", err)
	}
	id, _ := res.LastInsertId()

	// Eliminar labor
	req := httptest.NewRequest("DELETE", "/api/labores/"+strconv.Itoa(int(id)), nil)
	w := httptest.NewRecorder()
	EliminarLabor(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Se esperaba 200 al eliminar labor, pero se obtuvo %d", w.Code)
	}

	// Verificar que fue eliminada
	var count int
	err = db.DB.QueryRow("SELECT COUNT(*) FROM labores_agronomicas WHERE id = ?", id).Scan(&count)
	if err != nil {
		t.Errorf("Error al verificar eliminación: %v", err)
	}
	if count != 0 {
		t.Errorf("La labor no fue eliminada correctamente")
	}
}
