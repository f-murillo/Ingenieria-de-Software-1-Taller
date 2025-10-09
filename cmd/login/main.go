package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"
)

/*
Login represents the fields we need from the users table.
sql.NullString is used for nullable DB columns so we can
distinguish empty string from NULL.
*/
type Login struct {
	Username       string
	HashedPassword string
	SessionToken   sql.NullString
	CSRFToken      sql.NullString
	Role           sql.NullString
}

/*
db is a package-global database handle initialized in main.
Keeping it global simplifies examples and small services.
For larger systems prefer explicit dependency injection.
*/
var db *sql.DB

func main() {
	var err error

	// Initialize the DB file. Path is relative to the working directory.
	// In production read this path from configuration or an environment variable.
	db, err = initDB("./users.db")
	if err != nil {
		// Fatal here because the app cannot operate without persistent storage.
		log.Fatalf("db init: %v", err)
	}
	// Ensure DB is closed when the process exits.
	defer db.Close()

	// Register HTTP handlers; each handler is responsible for method checks
	// and minimal validation so the server returns appropriate status codes.
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)
	http.HandleFunc("/check-admin", checkRole)

	log.Println("Server listening on :8080")

	// Start the HTTP server. In examples we use ListenAndServe.
	// In production consider graceful shutdown, TLS, timeouts, and reverse proxy.
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("server: %v", err)
	}
}

/* Repository helpers */

/*
createUser inserts a new user row. The caller must provide a bcrypt-hashed
password. The function returns an error if the username already exists
or if the DB operation fails.
*/
func createUser(username, hashedPassword, role string) error {
	_, err := db.Exec(
		`INSERT INTO users (username, hashed_password, role) VALUES (?, ?, ?)`,
		username, hashedPassword, role,
	)
	return err
}

/*
getUserByUsername returns a Login populated from the DB for the given username.
It reads nullable columns into sql.NullString so callers can inspect validity.
*/
func getUserByUsername(username string) (Login, error) {
	var u Login
	var sToken, cToken, role sql.NullString
	err := db.QueryRow(
		`SELECT username, hashed_password, session_token, csrf_token, role FROM users WHERE username = ?`,
		username,
	).Scan(&u.Username, &u.HashedPassword, &sToken, &cToken, &role)
	if err != nil {
		return Login{}, err
	}
	u.SessionToken = sToken
	u.CSRFToken = cToken
	u.Role = role
	return u, nil
}

/*
getUserBySessionToken looks up the user that currently holds the given
session token. This is used by Authorize so the server does not trust
any username supplied by the client.
*/
func getUserBySessionToken(sessionToken string) (Login, error) {
	var u Login
	var sToken, cToken, role sql.NullString
	err := db.QueryRow(
		`SELECT username, hashed_password, session_token, csrf_token, role FROM users WHERE session_token = ?`,
		sessionToken,
	).Scan(&u.Username, &u.HashedPassword, &sToken, &cToken, &role)
	if err != nil {
		return Login{}, err
	}
	u.SessionToken = sToken
	u.CSRFToken = cToken
	u.Role = role
	return u, nil
}

/*
updateTokens writes the session & CSRF tokens for the provided username.
Use this on successful login to persist session state.
*/
func updateTokens(username, sessionToken, csrfToken string) error {
	_, err := db.Exec(
		`UPDATE users SET session_token = ?, csrf_token = ? WHERE username = ?`,
		sessionToken, csrfToken, username,
	)
	return err
}

/*
clearTokens invalidates the user's session by setting session_token and
csrf_token to NULL. This supports logout and session invalidation.
*/
func clearTokens(username string) error {
	_, err := db.Exec(
		`UPDATE users SET session_token = NULL, csrf_token = NULL WHERE username = ?`,
		username,
	)
	return err
}

/* Handlers */

/*
register handles POST /register.
- Validates HTTP method and form parsing.
- Enforces minimal length rules for username and password.
- Rejects existing usernames (unique constraint also protects DB).
- Hashes the password using bcrypt before persisting.
*/
func register(w http.ResponseWriter, r *http.Request) {
	// Only accept POST for registration.
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data (application/x-www-form-urlencoded).
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	role := r.FormValue("role")

	// Validacion del Role
	if role != "user" && role != "admin" {
		http.Error(w, "Rol inválido", http.StatusBadRequest)
		return
	}
	// Basic input validation. Adjust rules to your policy.
	if len(username) < 8 || len(password) < 8 {
		http.Error(w, "Invalid username/password", http.StatusNotAcceptable)
		return
	}

	// If user already exists, reject with 409 Conflict.
	if _, err := getUserByUsername(username); err == nil {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	// Hash the password (bcrypt) before storing.
	hashedPassword, err := hashPassword(password)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Persist the new user row.
	if err := createUser(username, hashedPassword, role); err != nil {
		http.Error(w, "User creation failed", http.StatusInternalServerError)
		return
	}

	// Successful creation.
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, "User registered successfully")
}

/*
login handles POST /login.
- Validates credentials against the stored bcrypt hash.
- Generates a session token and a CSRF token on success.
- Sets three cookies:
 1. session_token: HttpOnly (not accessible by JS)
 2. csrf_token: accessible by JS so client code can read it and send it in headers
 3. username: accessible by JS so UI can show the logged user

- Persists tokens to the DB for server-side validation.
*/
func login(w http.ResponseWriter, r *http.Request) {
	// Only accept POST for login.
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Parse form body.
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// Fetch user and verify password.
	user, err := getUserByUsername(username)
	if err != nil || !checkPasswordHash(password, user.HashedPassword) {
		// Use generic message so attackers cannot distinguish existence vs wrong password.
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Generate cryptographically-random tokens.
	sessionToken := generateToken(32)
	csrfToken := generateToken(32)

	// Set session cookie: HttpOnly to prevent JS access; Secure=true in prod.
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   false, // Change to true in production when serving over HTTPS
		SameSite: http.SameSiteLaxMode,
	})

	// Set csrf cookie: accessible by JS so SPA frontends can read it and set X-CSRF-Token header.
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	// Set username cookie for UI only. Never trust it on the server for auth.
	http.SetCookie(w, &http.Cookie{
		Name:     "username",
		Value:    username,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false, // must be readable by JS for client UI
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	// Persist session and CSRF tokens.
	if err := updateTokens(username, sessionToken, csrfToken); err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Login Successful")
}

/*
protected handles POST /protected.
- Demonstrates using Authorize to derive the username from the session cookie.
- Rejects any request that is not properly authorized.
*/
func protected(w http.ResponseWriter, r *http.Request) {
	// Only accept POST for this protected action.
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Authorize returns the username associated with the session token.
	username, err := Authorize(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Business logic would go here; we simply return a success message.
	fmt.Fprintf(w, "CSRF validation successful! Welcome, %s", username)
}

/*
logout handles POST /logout.
- Uses Authorize to ensure the request is authenticated.
- Clears cookies client-side by setting expired cookies with the same names.
- Clears tokens server-side (DB) to invalidate the session immediately.
*/
func logout(w http.ResponseWriter, r *http.Request) {
	// Authorize ensures the caller is an authenticated user.
	username, err := Authorize(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Clear cookies by setting an expired cookie with the same name.
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: false,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "username",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: false,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	// Clear session tokens in DB so that stolen cookies are invalid.
	_ = clearTokens(username)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Logged out successfully")
}

func checkRole(w http.ResponseWriter, r *http.Request) {
	// Solo aceptar GET
	if r.Method != http.MethodGet {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	// Verificar autenticación y obtener el nombre de usuario
	username, err := Authorize(r)
	if err != nil {
		http.Error(w, "No autenticado o CSRF inválido", http.StatusUnauthorized)
		return
	}

	// Buscar al usuario en la base de datos
	user, err := getUserByUsername(username)
	if err != nil {
		http.Error(w, "Usuario no encontrado", http.StatusInternalServerError)
		return
	}

	// Verificar el rol
	switch user.Role.String {
	case "admin":
		fmt.Fprintln(w, "✅ El usuario tiene rol de administrador")
	case "user":
		fmt.Fprintln(w, "👤 El usuario tiene rol de usuario")
	default:
		fmt.Fprintf(w, "❓ Rol desconocido: %s\n", user.Role.String)
	}
}
