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

	// Tabla de equipos e implementos
	_, err = DB.Exec(`
    	CREATE TABLE IF NOT EXISTS equipos_implementos (
        	id INTEGER PRIMARY KEY AUTOINCREMENT,
        	titulo TEXT NOT NULL
    	);
	`)
	if err != nil {
		log.Fatal(err)
	}

	// Tabla de labores agronómicas
	_, err = DB.Exec(`
    	CREATE TABLE IF NOT EXISTS labores_agronomicas (
        	id INTEGER PRIMARY KEY AUTOINCREMENT,
        	titulo TEXT NOT NULL
    	);
	`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = DB.Exec(`
    CREATE TABLE IF NOT EXISTS actividades_por_proyecto (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        proyecto_id INTEGER,
        actividad_id INTEGER,
        implemento_id INTEGER,
        usuario_id INTEGER,
        recurso_humano TEXT,
        FOREIGN KEY (proyecto_id) REFERENCES proyectos(id),
        FOREIGN KEY (actividad_id) REFERENCES labores_agronomicas(id),
        FOREIGN KEY (implemento_id) REFERENCES equipos_implementos(id),
        FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
    );
`)
	if err != nil {
		log.Fatal(err)
	}

	// Equipos e implementos de ejemplo (si la tabla está vacía)
	var countEquipos int
	DB.QueryRow("SELECT COUNT(*) FROM equipos_implementos").Scan(&countEquipos)
	if countEquipos == 0 {
		_, err = DB.Exec(`
        	INSERT INTO equipos_implementos (titulo) VALUES
        	('Tractor agrícola'),
        	('Pulverizador de mochila');
    	`)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Labores agronómicas de ejemplo (si la tabla está vacía)

	var countLabores int
	DB.QueryRow("SELECT COUNT(*) FROM labores_agronomicas").Scan(&countLabores)
	if countLabores == 0 {
		_, err = DB.Exec(`
        	INSERT INTO labores_agronomicas (titulo) VALUES
        	('Siembra directa'),
        	('Aplicación de fertilizantes');
    	`)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Actividad de ejemplo (si la tabla está vacía)
	var countActividades int
	DB.QueryRow("SELECT COUNT(*) FROM actividades_por_proyecto").Scan(&countActividades)
	if countActividades == 0 {
		_, err = DB.Exec(`
        INSERT INTO actividades_por_proyecto (proyecto_id, actividad_id, implemento_id, usuario_id, recurso_humano)
        VALUES (1, 1, 1, 1, '3 jornaleros');
    `)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Usuarios de ejemplo (si la tabla esta vacia)
	var countUsuarios int
	DB.QueryRow("SELECT COUNT(*) FROM usuarios").Scan(&countUsuarios)
	if countUsuarios == 0 {
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
