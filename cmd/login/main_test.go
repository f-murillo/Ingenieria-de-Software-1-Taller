package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// Para crear una base de datos temporal para las pruebas
func setupTestDB(t *testing.T) {
	var err error
	db, err = initDB("./test_temp.db")
	if err != nil {
		t.Fatalf("Error al inicializar la base de datos: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
		os.Remove("./test_temp.db")
	})
}

func TestRegister(t *testing.T) {
	setupTestDB(t)

	// Simulamos una solicitud HTTP POST como si viniera de un formulario web
	req := httptest.NewRequest("POST", "/register", strings.NewReader("username=testuser&password=testpass&role=user"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Capturamos la respuesta
	w := httptest.NewRecorder()
	register(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Se esperaba 201 Created, se recibio %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "User registered successfully") {
		t.Errorf("respuesta inesperada: %s", body)
	}
}

func TestLogin(t *testing.T) {
	setupTestDB(t)

	hashed, _ := hashPassword("testpass")
	err := createUser("testuser", hashed, "user")
	if err != nil {
		t.Fatalf("Error al crear usuario: %v", err)
	}

	req := httptest.NewRequest("POST", "/login", strings.NewReader("username=testuser&password=testpass"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	login(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Se esperaba 200 OK, se recibio %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Login Successful") {
		t.Errorf("Respuesta inesperada: %s", body)
	}
}

func TestCheckAdmin(t *testing.T) {
	setupTestDB(t)

	hashed, _ := hashPassword("adminpass")
	err := createUser("adminuser", hashed, "admin")
	if err != nil {
		t.Fatalf("Error al crear usuario: %v", err)
	}

	session := generateToken(32)
	csrf := generateToken(32)
	err = updateTokens("adminuser", session, csrf)
	if err != nil {
		t.Fatalf("Error al guardar tokens: %v", err)
	}

	req := httptest.NewRequest("GET", "/check-admin", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: session})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()

	checkRole(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Se esperaba 200 OK, se recibio %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "rol de administrador") {
		t.Errorf("Respuesta inesperada: %s", body)
	}
}

func TestLogout(t *testing.T) {
	setupTestDB(t)

	hashed, _ := hashPassword("logoutpass")
	err := createUser("logoutuser", hashed, "user")
	if err != nil {
		t.Fatalf("Error al crear usuario: %v", err)
	}
	session := generateToken(32)
	csrf := generateToken(32)
	err = updateTokens("logoutuser", session, csrf)
	if err != nil {
		t.Fatalf("Error al guardar tokens: %v", err)
	}

	req := httptest.NewRequest("POST", "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: session})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()

	logout(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Se esperaba 200 OK, se recibio %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Logged out successfully") {
		t.Errorf("Respuesta inesperada: %s", body)
	}

	user, err := getUserByUsername("logoutuser")
	if err != nil {
		t.Fatalf("Error al obtener usuario: %v", err)
	}
	if user.SessionToken.Valid || user.CSRFToken.Valid {
		t.Errorf("Los tokens no fueron eliminados correctamente")
	}
}
