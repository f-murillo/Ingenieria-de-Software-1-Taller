const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080';

// Interfaces
export interface Usuario {
  id: number;
  usuario: string;
  nombre?: string;
  apellido?: string;
  rol?: string;
  proyecto?: string;
  contraseña?: string;
  administrador?: boolean;
  creador?: string;
}

export interface Proyecto {
  id: number;
  descripcion: string;
  fecha_inicio: string;
  fecha_cierre: string;
}

export type ProyectoSinID = Omit<Proyecto, 'id'>;

// Login
export async function login(usuario: string, contraseña: string): Promise<Usuario> {
  const res = await fetch(`${API_URL}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ usuario, contraseña }),
  });
  if (!res.ok) throw new Error('Credenciales inválidas');
  return res.json();
}

// Usuarios
export async function obtenerUsuarios(): Promise<Usuario[]> {
  const res = await fetch(`${API_URL}/api/usuarios`);
  if (!res.ok) throw new Error('Error al obtener usuarios');
  const data = await res.json();
  return Array.isArray(data) ? data : [];
}

export async function crearUsuario(usuario: Usuario): Promise<Usuario> {
  const res = await fetch(`${API_URL}/api/usuarios`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(usuario),
  });
  if (!res.ok) throw new Error('Error al crear usuario');
  return res.json();
}

// Proyectos
export async function obtenerProyectos(): Promise<Proyecto[]> {
  const res = await fetch(`${API_URL}/api/proyectos`);
  if (!res.ok) throw new Error('Error al obtener proyectos');
  const data = await res.json();
  return Array.isArray(data) ? data : [];
}

export async function crearProyecto(proyecto: ProyectoSinID): Promise<Proyecto> {
  const res = await fetch(`${API_URL}/api/proyectos`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(proyecto),
  });
  if (!res.ok) throw new Error('Error al crear proyecto');
  return res.json();
}

export async function actualizarProyecto(id: number, proyecto: ProyectoSinID): Promise<Proyecto> {
  const res = await fetch(`${API_URL}/api/proyectos/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(proyecto),
  });
  if (!res.ok) throw new Error('Error al actualizar proyecto');
  return res.json();
}

export async function eliminarProyecto(id: number): Promise<void> {
  const res = await fetch(`${API_URL}/api/proyectos/${id}`, {
    method: 'DELETE',
  });
  if (!res.ok) throw new Error('Error al eliminar proyecto');
}

export async function actualizarRolUsuario(id: number, nuevoRol: string): Promise<void> {
  const res = await fetch(`${API_URL}/api/usuarios/${id}/rol`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ nuevoRol }),
  });

  if (!res.ok) throw new Error('Error al actualizar rol');
}


// Relaciones
export async function obtenerProyectosPorUsuario(usuarioId: number): Promise<Proyecto[]> {
  const res = await fetch(`${API_URL}/api/usuarios/${usuarioId}/proyectos`);
  if (!res.ok) throw new Error('Error al obtener proyectos del usuario');
  const data = await res.json();
  return Array.isArray(data) ? data : [];
}


export async function obtenerUsuariosPorProyecto(proyectoId: number): Promise<Usuario[]> {
  const res = await fetch(`${API_URL}/api/proyectos/${proyectoId}/usuarios`);
  if (!res.ok) throw new Error('Error al obtener usuarios del proyecto');
  const data = await res.json();
  return Array.isArray(data) ? data : [];
}

export async function asociarUsuariosAProyecto(proyectoId: number, usuarios: number[]) {
  const res = await fetch(`${API_URL}/api/proyectos/${proyectoId}/usuarios`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ usuarios }),
  });
  if (!res.ok) throw new Error('Error al asociar usuarios');
}
