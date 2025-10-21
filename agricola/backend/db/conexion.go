package db

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

func Inicializar() {
	var err error
	DB, err = sql.Open("sqlite3", "./usuarios.db")
	if err != nil {
		log.Fatal(err)
	}

	_, err = DB.Exec(`
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT,
            nombre TEXT,
            apellido TEXT,
            rol TEXT,
            proyecto TEXT,
			contraseña TEXT,
			administrador BOOLEAN DEFAULT FALSE
    );
    `)
	if err != nil {
		log.Fatal(err)
	}

	var count int
	DB.QueryRow("SELECT COUNT(*) FROM usuarios").Scan(&count)
	if count == 0 {
		_, err = DB.Exec(`
            INSERT INTO usuarios (usuario, nombre, apellido, rol, proyecto, contraseña, administrador) VALUES
            ('akoto', 'Ana', 'Koto', 'Supervisor', 'Agrícola', 'pass123', TRUE),
            ('lrojas', 'Luis', 'Rojas', 'Operador', 'Forestal', 'pass456', FALSE),
            ('mvera', 'María', 'Vera', 'Supervisor', 'Minería', 'pass789', FALSE);
        `)
		if err != nil {
			log.Fatal(err)
		}
	}
}
