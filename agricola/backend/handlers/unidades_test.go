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
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupTestDB(t *testing.T) {
	var err error
	db.DB, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Error al abrir base en memoria: %v", err)
	}
	db.Inicializar()
}

func TestCrearYObtenerUnidad(t *testing.T) {
	setupTestDB(t)

	// Crear unidad
	body := `{"dimension": 8.5, "unidad": "Pulgadas"}`
	req := httptest.NewRequest(http.MethodPost, "/api/unidades", strings.NewReader(body))
	w := httptest.NewRecorder()
	CrearUnidad(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Código inesperado al crear unidad: %d", w.Code)
	}

	var creada models.UnidadMedida
	if err := json.NewDecoder(w.Body).Decode(&creada); err != nil {
		t.Fatalf("Error al decodificar respuesta: %v", err)
	}
	if creada.ID == 0 || creada.Unidad != "Pulgadas" {
		t.Errorf("Unidad creada incorrectamente: %+v", creada)
	}

	// Obtener unidades
	req = httptest.NewRequest(http.MethodGet, "/api/unidades", nil)
	w = httptest.NewRecorder()
	ObtenerUnidades(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Código inesperado al obtener unidades: %d", w.Code)
	}

	var lista []models.UnidadMedida
	if err := json.NewDecoder(w.Body).Decode(&lista); err != nil {
		t.Fatalf("Error al decodificar lista: %v", err)
	}
	if len(lista) != 1 || lista[0].Unidad != "Pulgadas" {
		t.Errorf("Lista inesperada: %+v", lista)
	}
}

func TestActualizarUnidad(t *testing.T) {
	setupTestDB(t)

	// Insertar unidad manualmente
	res, err := db.DB.Exec("INSERT INTO unidades_medidas (dimension, unidad) VALUES (?, ?)", 5.0, "Litros")
	if err != nil {
		t.Fatalf("Error al insertar unidad: %v", err)
	}
	id, _ := res.LastInsertId()

	// Actualizar unidad
	u := models.UnidadMedida{Dimension: 10.0, Unidad: "Galones"}
	jsonBody, _ := json.Marshal(u)
	req := httptest.NewRequest(http.MethodPut, "/api/unidades/"+strconv.Itoa(int(id)), bytes.NewReader(jsonBody))
	w := httptest.NewRecorder()
	ActualizarUnidad(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Código inesperado al actualizar: %d", w.Code)
	}

	var actualizada models.UnidadMedida
	json.NewDecoder(w.Body).Decode(&actualizada)
	if actualizada.Dimension != 10.0 || actualizada.Unidad != "Galones" {
		t.Errorf("Unidad no actualizada correctamente: %+v", actualizada)
	}
}

func TestEliminarUnidad(t *testing.T) {
	setupTestDB(t)

	// Insertar unidad
	res, err := db.DB.Exec("INSERT INTO unidades_medidas (dimension, unidad) VALUES (?, ?)", 3.0, "Kg")
	if err != nil {
		t.Fatalf("Error al insertar unidad: %v", err)
	}
	id, _ := res.LastInsertId()

	// Eliminar unidad
	req := httptest.NewRequest(http.MethodDelete, "/api/unidades/"+strconv.Itoa(int(id)), nil)
	w := httptest.NewRecorder()
	EliminarUnidad(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Código inesperado al eliminar: %d", w.Code)
	}

	// Verificar que ya no existe
	var count int
	err = db.DB.QueryRow("SELECT COUNT(*) FROM unidades_medidas WHERE id = ?", id).Scan(&count)
	if err != nil {
		t.Fatalf("Error al verificar eliminación: %v", err)
	}
	if count != 0 {
		t.Errorf("La unidad no fue eliminada")
	}
}
