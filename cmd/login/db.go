package main

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

/*
initDB opens (or creates) the SQLite file at path and ensures the users table exists.
Use an absolute path or environment-driven path in different environments.
For production deployments consider migrating to a client-server DB.
*/
func initDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	// Schema: minimal users table with nullable tokens and timestamps.
	// session_token and csrf_token are nullable so we can NULL them on logout.
	schema := `
    CREATE TABLE IF NOT EXISTS users (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        username         TEXT NOT NULL UNIQUE,
        hashed_password  TEXT NOT NULL,
        session_token    TEXT,
        csrf_token       TEXT,
        role             TEXT DEFAULT 'user',
        created_at       DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    `

	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}

	log.Println("Base de datos inicializada exitosamente")
	return db, nil
}
