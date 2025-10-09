package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestRegister verifica que la función register registre correctamente a un nuevo usuario
func TestRegister(t *testing.T) {
	// 🔧 Inicializamos la base de datos para pruebas
	// Usamos un archivo separado para no afectar la base real
	var err error
	db, err = initDB("./test_register.db")
	if err != nil {
		// Si falla la inicialización, detenemos el test
		t.Fatalf("Error al inicializar la base de datos: %v", err)
	}

	// 🧹 Limpiamos el archivo de base de datos al final del test
	defer os.Remove("./test_register.db")

	// 🧪 Simulamos una solicitud HTTP POST como si viniera de un formulario web
	// Enviamos los datos del nuevo usuario en formato x-www-form-urlencoded
	req := httptest.NewRequest("POST", "/register", strings.NewReader("username=testuser&password=testpass&role=user"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// 🧾 Creamos un ResponseRecorder para capturar la respuesta del servidor
	w := httptest.NewRecorder()

	// 🚪 Llamamos directamente a la función register como si fuera una ruta real
	register(w, req)

	// 📥 Obtenemos la respuesta simulada
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	// ✅ Verificamos que el código de estado sea 201 (Created)
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("esperado 201 Created, recibido %d", resp.StatusCode)
	}

	// ✅ Verificamos que el cuerpo de la respuesta contenga el mensaje esperado
	if !strings.Contains(string(body), "User registered successfully") {
		t.Errorf("respuesta inesperada: %s", body)
	}
}
