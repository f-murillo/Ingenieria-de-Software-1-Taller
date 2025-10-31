package db

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestInicializarEnMemoria(t *testing.T) {
	// Usamos una base en memoria para no tocar usuarios.db
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Error al abrir base en memoria: %v", err)
	}
	defer testDB.Close()

	// Reemplazamos la variable global DB por la de prueba
	DB = testDB

	// Ejecutamos la lógica de inicialización
	Inicializar()

	// Verificamos que las tablas existen
	tablas := []string{"usuarios", "proyectos", "usuarios_proyectos"}
	for _, tabla := range tablas {
		_, err := DB.Query("SELECT * FROM " + tabla + " LIMIT 1")
		if err != nil {
			t.Errorf("La tabla %s no existe o no se puede consultar: %v", tabla, err)
		}
	}

	// Verificamos que se insertaron usuarios de ejemplo
	var count int
	err = DB.QueryRow("SELECT COUNT(*) FROM usuarios").Scan(&count)
	if err != nil {
		t.Errorf("Error al contar usuarios: %v", err)
	}
	if count != 3 {
		t.Errorf("Se esperaban 3 usuarios de ejemplo, pero hay %d", count)
	}
}
