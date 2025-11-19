package main

import (
	"agricola/db"
	"agricola/handlers"
	"log"
	"net/http"
	"strings"
)

// Funcion para habilitar CORS
func habilitarCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func main() {
	db.Inicializar()

	// Usuarios
	http.HandleFunc("/api/usuarios", func(w http.ResponseWriter, r *http.Request) {
		habilitarCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		switch r.Method {
		case http.MethodGet:
			handlers.ObtenerUsuarios(w, r)
		case http.MethodPost:
			handlers.CrearUsuario(w, r)
		default:
			http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		}
	})
	http.HandleFunc("/api/usuarios/", func(w http.ResponseWriter, r *http.Request) {
		habilitarCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/proyectos") {
			handlers.ObtenerProyectosPorUsuario(w, r)
			return
		}
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/rol") {
			handlers.ActualizarRolUsuario(w, r)
			return
		}
		http.Error(w, "Ruta o método no válido", http.StatusNotFound)
	})

	// Proyectos
	http.HandleFunc("/api/proyectos", func(w http.ResponseWriter, r *http.Request) {
		habilitarCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		switch r.Method {
		case http.MethodGet:
			handlers.ObtenerProyectos(w, r)
		case http.MethodPost:
			handlers.CrearProyecto(w, r)
		default:
			http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		}
	})
	http.HandleFunc("/api/proyectos/", func(w http.ResponseWriter, r *http.Request) {
		habilitarCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/usuarios") {
			switch r.Method {
			case http.MethodGet:
				handlers.ObtenerUsuariosPorProyecto(w, r)
				return
			case http.MethodPost:
				handlers.AsociarUsuariosAProyecto(w, r)
				return
			default:
				http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
				return
			}
		}
		if strings.HasSuffix(r.URL.Path, "/estado") && r.Method == http.MethodPut {
			handlers.ActualizarEstadoProyecto(w, r)
			return
		}
		if r.Method == http.MethodPut {
			handlers.ActualizarProyecto(w, r)
			return
		}
		http.Error(w, "Ruta o método no válido", http.StatusNotFound)
	})

	// Login
	http.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		habilitarCORS(w)
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

	// Actividades
	http.HandleFunc("/api/actividades", func(w http.ResponseWriter, r *http.Request) {
		habilitarCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		switch r.Method {
		case http.MethodGet:
			handlers.ObtenerActividades(w, r)
		case http.MethodPost:
			handlers.CrearActividad(w, r) // Nueva
		default:
			http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		}
	})

	// Actividades por id
	http.HandleFunc("/api/actividades/", func(w http.ResponseWriter, r *http.Request) {
		habilitarCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		switch r.Method {
		case http.MethodPut:
			handlers.ActualizarActividad(w, r)
		case http.MethodDelete:
			handlers.EliminarActividad(w, r)
		default:
			http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		}
	})

	// Labores
	http.HandleFunc("/api/labores", func(w http.ResponseWriter, r *http.Request) {
		habilitarCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		switch r.Method {
		case http.MethodGet:
			handlers.ObtenerLabores(w, r)
		case http.MethodPost:
			handlers.CrearLabor(w, r)
		default:
			http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/api/labores/", func(w http.ResponseWriter, r *http.Request) {
		habilitarCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		switch r.Method {
		case http.MethodPut:
			handlers.ActualizarLabor(w, r)
		case http.MethodDelete:
			handlers.EliminarLabor(w, r)
		default:
			http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		}
	})

	// Equipos
	http.HandleFunc("/api/equipos", func(w http.ResponseWriter, r *http.Request) {
		habilitarCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		switch r.Method {
		case http.MethodGet:
			handlers.ObtenerEquipos(w, r)
		case http.MethodPost:
			handlers.CrearEquipo(w, r)
		default:
			http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/api/equipos/", func(w http.ResponseWriter, r *http.Request) {
		habilitarCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		switch r.Method {
		case http.MethodPut:
			handlers.ActualizarEquipo(w, r)
		case http.MethodDelete:
			handlers.EliminarEquipo(w, r)
		default:
			http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		}
	})

	// Logger de eventos

	// Logger de eventos
	http.HandleFunc("/api/eventos", func(w http.ResponseWriter, r *http.Request) {
		habilitarCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodGet {
			handlers.ObtenerEventos(w, r)
		} else {
			http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/api/eventos/", func(w http.ResponseWriter, r *http.Request) {
		habilitarCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		switch r.Method {
		case http.MethodPost:
			handlers.CrearEvento(w, r)
		case http.MethodPut:
			handlers.ActualizarEvento(w, r)
		case http.MethodDelete:
			handlers.EliminarEvento(w, r)
		default:
			http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		}
	})

	//Iniciar servidor
	log.Println("Servidor escuchando en http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
