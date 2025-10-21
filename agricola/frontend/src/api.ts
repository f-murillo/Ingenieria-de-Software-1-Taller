// api.ts

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080';

// Interfaz para tipar los datos de usuario
export interface Usuario {
  id?: number;
  usuario: string;
  nombre?: string;
  apellido?: string;
  rol?: string;
  proyecto?: string;
  contraseña?: string;
  administrador?: boolean;
  creador?: string;
}

// Para el login
export async function login(usuario: string, contraseña: string): Promise<Usuario> {
  const res = await fetch(`${API_URL}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ usuario, contraseña }),
  });
  if (!res.ok) throw new Error('Credenciales inválidas');
  return res.json();
}

// Para obtener lista de usuarios
export async function getUsuarios(): Promise<Usuario[]> {
  const res = await fetch(`${API_URL}/api/usuarios`);
  if (!res.ok) throw new Error('Error al obtener usuarios');
  return res.json();
}

// Para crear un nuevo usuario
export async function crearUsuario(usuario: Usuario): Promise<Usuario> {
  const res = await fetch(`${API_URL}/api/usuarios`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(usuario),
  });
  if (!res.ok) throw new Error('Error al crear usuario');
  return res.json();
}

export async function obtenerUsuarios(): Promise<Usuario[]> {
  const res = await fetch(`${API_URL}/api/usuarios`);
  if (!res.ok) {
    throw new Error('Error al obtener usuarios');
  }
  return res.json();
}

