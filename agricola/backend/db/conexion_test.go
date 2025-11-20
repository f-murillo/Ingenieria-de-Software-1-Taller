package db

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestInicializarEnMemoria(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Error al abrir base en memoria: %v", err)
	}
	defer testDB.Close()

	DB = testDB
	Inicializar()

	// Verificamos que todas las tablas existan
	tablas := []string{
		"usuarios",
		"proyectos",
		"usuarios_proyectos",
		"equipos_implementos",
		"labores_agronomicas",
		"actividades_por_proyecto",
		"unidades_medidas",
	}
	for _, tabla := range tablas {
		_, err := DB.Query("SELECT * FROM " + tabla + " LIMIT 1")
		if err != nil {
			t.Errorf("La tabla %s no existe o no se puede consultar: %v", tabla, err)
		}
	}

	// Verificamos datos de ejemplo
	casos := []struct {
		tabla    string
		esperado int
	}{
		{"usuarios", 3},
		{"equipos_implementos", 2},
		{"labores_agronomicas", 2},
	}

	for _, caso := range casos {
		var count int
		err := DB.QueryRow("SELECT COUNT(*) FROM " + caso.tabla).Scan(&count)
		if err != nil {
			t.Errorf("Error al contar en %s: %v", caso.tabla, err)
		}
		if count != caso.esperado {
			t.Errorf("Se esperaban %d registros en %s, pero hay %d", caso.esperado, caso.tabla, count)
		}
	}
}
