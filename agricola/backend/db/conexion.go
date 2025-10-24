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

	// Tabla de usuarios
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

	// Tabla de proyectos
	_, err = DB.Exec(`
        CREATE TABLE IF NOT EXISTS proyectos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            descripcion TEXT NOT NULL,
            fecha_inicio TEXT NOT NULL,
            fecha_cierre TEXT,
            habilitado BOOLEAN NOT NULL DEFAULT 1
        );
    `)
	if err != nil {
		log.Fatal(err)
	}

	// Tabla intermedia usuarios_proyectos
	_, err = DB.Exec(`
        CREATE TABLE IF NOT EXISTS usuarios_proyectos (
            usuario_id INTEGER,
            proyecto_id INTEGER,
            PRIMARY KEY (usuario_id, proyecto_id),
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id),
            FOREIGN KEY (proyecto_id) REFERENCES proyectos(id)
        );
    `)
	if err != nil {
		log.Fatal(err)
	}

	// Usuarios de ejemplo (si la tabla esta vacia)
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
