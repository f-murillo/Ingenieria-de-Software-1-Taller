# Taller de Ingeniería de Software 1  

### Integrantes

- Franco Murillo - murillo.franc@gmail.com  
- Leonardo Dolande - leodolande84@gmail.com   

### Agile Coach

Jean Carlos Guzmán -  jeancguzman2050@gmail.com

### Sobre el proyecto  
- Este proyecto implementa un sistema para la creación y gestión de proyectos agrícolas. Cuenta con autenticación para distintos tipos de usuarios, gestión de actividades, recursos humanos, insumos y costos.    
- Está desarrollado en **Go** para la parte del backend, con **SQLite** como base de datos, y con **React** y **Typescript** para la parte del frontend. Cuenta con pruebas unitarias y de integración tanto para el backend como para el frontend.

---

## Estructura del Proyecto

agrícola      
├── backend/                                        &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp; Carpeta con  todo lo relacionado al backend del sistema 
|&ensp;&ensp;&ensp;&ensp;&ensp;├── db/              &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp; Carpeta con los archivos para manejar la conexión a la base de datos  
|&ensp;&ensp;&ensp;&ensp;&ensp;├── handlers/        &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp; Carpeta con los archivos con todos los endpoints del sistema  
|&ensp;&ensp;&ensp;&ensp;&ensp;├── models/          &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp; Carpeta con los tipos usados en el proyecto  
|&ensp;&ensp;&ensp;&ensp;&ensp;├── utils/           &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp; Carpeta con archivo auxiliar   
|&ensp;&ensp;&ensp;&ensp;&ensp;├── go.mod           &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp; Módulo Go: dependencias y nombre del proyecto     
|&ensp;&ensp;&ensp;&ensp;&ensp;├── go.sum           &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp; Sumario de verificación de dependencias    
|&ensp;&ensp;&ensp;&ensp;&ensp;├─ main.go           &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp; Punto de entrada: servidor HTTP, rutas principales   
├── frontend/                                        &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp; Carpeta con  todo lo relacionado al frontend del sistema    
|&ensp;&ensp;&ensp;&ensp;&ensp;├── cypress/         &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp; Carpeta con pruebas cypress  
|&ensp;&ensp;&ensp;&ensp;&ensp;├── node_modules/    &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp; Carpeta con dependencias de Node  
|&ensp;&ensp;&ensp;&ensp;&ensp;├── src/             &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp; Carpeta con los componentes .ts y .tsx del proyecto
|&ensp;&ensp;&ensp;&ensp;&ensp;├── .env             &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp;&ensp; Configuración de variable de entorno

---

## Base de Datos

- Motor: **SQLite**
- Tablas principales:
  - `users`: usuarios registrados con contraseñas cifradas
  - `actividades_periodo`: actividades planificadas con fechas, horas y responsable
  - `actividades_cantidad`: recursos humanos asociados a cada actividad
  - `actividades_categoria`: insumos/materiales asociados a cada actividad

---

## Pruebas

- **Backend (Go):**  
  - Se usan `httptest` y SQLite en memoria para validar creación, actualización y eliminación de registros.  
- **Frontend (React + Cypress):**  
  - Pruebas end-to-end para login, gestión de insumos y recursos humanos.  
  - Uso de `data-testid` para seleccionar elementos de forma estable.  
---

## Ejecución

1. **Backend (Go): Desde el directorio backend**
   ```bash
   go run .

2. **Frontend: Desde el directorio frontend**
   ```bash
   npm install
   npm run dev
