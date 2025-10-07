# Taller de Ingeniería de Software 1 — Autenticación

Esta parte implementa un sistema básico de autenticación web utilizando Go, SQLite y cookies seguras. Incluye registro, login, validación de sesión con tokens, protección CSRF y logout

---

## Estructura del Proyecto

Ingenieria-de-Software-1-Taller  
├── go.mod              &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;# Módulo Go: define dependencias y nombre del proyecto  
├── go.sum              &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;# Suma de verificación de dependencias  
├── login               &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;# Ejecutable compilado (opcional, generado por go build)  
└── cmd/  
    └── login/  
        ├── main.go     &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;# Punto de entrada: servidor HTTP, handlers y lógica principal  
        ├── db.go       &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;# Inicialización de la base de datos SQLite y creación de tabla users  
        ├── session.go  &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;# Validación de sesión y protección contra CSRF  
        └── utils.go    &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;# Funciones auxiliares: hashing, comparación de contraseñas, generación de tokens  


---

## Base de Datos

- Motor: SQLite
- Archivo: `users.db` (creado automáticamente en la raíz del proyecto)
- Tabla: `users`
- Campos:
  - `id`: entero autoincremental
  - `username`: texto único
  - `hashed_password`: contraseña cifrada con bcrypt
  - `session_token`: token de sesión (nullable)
  - `csrf_token`: token CSRF (nullable)
  - `role`: rol del usuario (por defecto: "user")
  - `created_at`: fecha de creación

---

##  Seguridad y Autenticación

- Contraseñas cifradas con bcrypt
- Tokens de sesión y CSRF generados aleatoriamente
- Cookies:
  - `session_token`: HttpOnly (no accesible por JavaScript)
  - `csrf_token`: accesible por JavaScript para enviar en headers
  - `username`: accesible por JavaScript para mostrar en la UI
- Validación de sesión y CSRF en endpoints protegidos

---

## Endpoints HTTP

### `POST /register`

Registra un nuevo usuario.

- **Body (form-urlencoded):**
  - `username`: mínimo 8 caracteres
  - `password`: mínimo 8 caracteres
- **Respuestas:**
  - `201 Created`: usuario registrado
  - `409 Conflict`: usuario ya existe
  - `406 Not Acceptable`: datos inválidos

---

### `POST /login`

Autentica al usuario y genera tokens.

- **Body (form-urlencoded):**
  - `username`
  - `password`
- **Respuestas:**
  - `200 OK`: login exitoso, cookies generadas
  - `401 Unauthorized`: credenciales inválidas
- **Cookies generadas:**
  - `session_token` (HttpOnly)
  - `csrf_token` (JS-accessible)
  - `username` (JS-accessible)

---

### `POST /protected`

Endpoint protegido que requiere sesión activa y validación CSRF.

- **Headers:**
  - `X-CSRF-Token`: debe coincidir con la cookie `csrf_token`
- **Cookies requeridas:**
  - `session_token`
- **Respuestas:**
  - `200 OK`: acceso autorizado
  - `401 Unauthorized`: sesión inválida o CSRF incorrecto

---

### `POST /logout`

Cierra la sesión del usuario.

- **Cookies requeridas:**
  - `session_token`
  - `csrf_token`
- **Headers:**
  - `X-CSRF-Token`
- **Acciones:**
  - Elimina tokens en la base de datos
  - Expira cookies en el navegador
- **Respuestas:**
  - `200 OK`: logout exitoso
  - `401 Unauthorized`: sesión inválida

