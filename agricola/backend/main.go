package main

import (
	"log"
	"net/http"

	"agricola/db"
	"agricola/handlers"
)

func main() {
	db.Inicializar()

	http.HandleFunc("/api/usuarios", func(w http.ResponseWriter, r *http.Request) {
		// Permitir solicitudes desde otros orígenes (como React)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		// Si el navegador envía una solicitud OPTIONS (preflight), respondemos sin procesar
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Procesar solicitudes reales
		switch r.Method {
		case http.MethodGet:
			handlers.ObtenerUsuarios(w, r)
		case http.MethodPost:
			handlers.CrearUsuario(w, r)
		default:
			http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method == http.MethodPost {
			handlers.Login(w, r)
		} else {
			http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		}
	})

	log.Println("Servidor escuchando en http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
