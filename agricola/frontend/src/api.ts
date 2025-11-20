const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080';

export interface LoggerEvento {
  id: number;
  evento: string;
  modulo: string;
  fecha: string;
  hora: string;
}

// Eventos (Logger)
export async function obtenerEventos(): Promise<LoggerEvento[]> {
  const res = await fetch(`${API_URL}/api/eventos`);
  if (!res.ok) throw new Error('Error al obtener eventos');
  return res.json();
}

export async function crearEvento(evento: Omit<LoggerEvento, "id">): Promise<LoggerEvento> {
  const res = await fetch(`${API_URL}/api/eventos`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(evento),
  });
  if (!res.ok) throw new Error('Error al crear evento');
  return res.json();
}

export async function actualizarEvento(id: number, evento: LoggerEvento): Promise<LoggerEvento> {
  const res = await fetch(`${API_URL}/api/eventos/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(evento),
  });
  if (!res.ok) throw new Error('Error al actualizar evento');
  return res.json();
}

export async function eliminarEvento(id: number): Promise<void> {
  const res = await fetch(`${API_URL}/api/eventos/${id}`, {
    method: 'DELETE',
  });
  if (!res.ok) throw new Error('Error al eliminar evento');
}

// Interfaz para las unidades
export interface UnidadMedida {
  id: number;
  dimension: number;
  unidad: string;
}

export async function obtenerUnidades(): Promise<UnidadMedida[]> {
  const res = await fetch(`${API_URL}/api/unidades`);
  if (!res.ok) throw new Error("Error al obtener unidades");
  return res.json();
}

export async function crearUnidad(unidad: Omit<UnidadMedida, "id">): Promise<UnidadMedida> {
  const res = await fetch(`${API_URL}/api/unidades`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(unidad),
  });
  if (!res.ok) throw new Error("Error al crear unidad");
  return res.json();
}

export async function actualizarUnidad(id: number, unidad: Omit<UnidadMedida, "id">): Promise<UnidadMedida> {
  const res = await fetch(`${API_URL}/api/unidades/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(unidad),
  });
  if (!res.ok) throw new Error("Error al actualizar unidad");
  return res.json();
}

export async function eliminarUnidad(id: number): Promise<void> {
  const res = await fetch(`${API_URL}/api/unidades/${id}`, {
    method: "DELETE",
  });
  if (!res.ok) throw new Error("Error al eliminar unidad");
}



// Interfaces
export interface Usuario {
  id: number;
  usuario: string;
  cedula: string;
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
  habilitado: boolean;
  costo?: number;
}

export interface ProyectoSinID extends Omit<Proyecto, 'id'> {}

export interface ActividadPorProyecto {
  id: number;
  proyecto: string;
  actividad: string;
  implemento: string;
  usuario: string;
  recurso_humano: string;
  observaciones: string;
  costo: number;
}

export interface ActividadInput {
  id?: number;
  proyecto_id: number;
  actividad_id: number;
  implemento_id: number;
  usuario_id: number;
  recurso_humano: string;
  observaciones: string;
  costo: number;
}

export interface LaborAgronomica {
  id: number;
  titulo: string;
}

export interface EquipoImplemento {
  id: number;
  titulo: string;
}

// Actividades
export async function obtenerActividades(): Promise<ActividadPorProyecto[]> {
  const res = await fetch(`${API_URL}/api/actividades`);
  if (!res.ok) throw new Error('Error al obtener actividades');
  return res.json();
}

export async function crearActividad(input: ActividadInput): Promise<ActividadInput> {
  const res = await fetch(`${API_URL}/api/actividades`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  if (!res.ok) throw new Error('Error al crear actividad');
  return res.json();
}

export async function actualizarActividad(id: number, input: ActividadInput): Promise<ActividadInput> {
  const res = await fetch(`${API_URL}/api/actividades/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  if (!res.ok) throw new Error('Error al actualizar actividad');
  return res.json();
}

export async function eliminarActividad(id: number): Promise<void> {
  const res = await fetch(`${API_URL}/api/actividades/${id}`, {
    method: 'DELETE',
  });
  if (!res.ok) throw new Error('Error al eliminar actividad');
}

// Labores
export async function obtenerLabores(): Promise<LaborAgronomica[]> {
  const res = await fetch(`${API_URL}/api/labores`);
  if (!res.ok) throw new Error('Error al obtener labores');
  return res.json();
}

export async function crearLabor(titulo: string): Promise<LaborAgronomica> {
  const res = await fetch(`${API_URL}/api/labores`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ titulo }),
  });
  if (!res.ok) throw new Error('Error al crear labor');
  return res.json();
}

export async function actualizarLabor(id: number, titulo: string): Promise<LaborAgronomica> {
  const res = await fetch(`${API_URL}/api/labores/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ titulo }),
  });
  if (!res.ok) throw new Error('Error al actualizar labor');
  return res.json();
}

export async function eliminarLabor(id: number): Promise<void> {
  const res = await fetch(`${API_URL}/api/labores/${id}`, {
    method: 'DELETE',
  });
  if (!res.ok) throw new Error('Error al eliminar labor');
}

// Equipos
export async function obtenerEquipos(): Promise<EquipoImplemento[]> {
  const res = await fetch(`${API_URL}/api/equipos`);
  if (!res.ok) throw new Error('Error al obtener equipos');
  return res.json();
}

export async function crearEquipo(titulo: string): Promise<EquipoImplemento> {
  const res = await fetch(`${API_URL}/api/equipos`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ titulo }),
  });
  if (!res.ok) throw new Error('Error al crear equipo');
  return res.json();
}

export async function actualizarEquipo(id: number, titulo: string): Promise<EquipoImplemento> {
  const res = await fetch(`${API_URL}/api/equipos/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ titulo }),
  });
  if (!res.ok) throw new Error('Error al actualizar equipo');
  return res.json();
}

export async function eliminarEquipo(id: number): Promise<void> {
  const res = await fetch(`${API_URL}/api/equipos/${id}`, {
    method: 'DELETE',
  });
  if (!res.ok) throw new Error('Error al eliminar equipo');
}

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
  return res.json();
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

export async function actualizarRolUsuario(id: number, nuevoRol: string): Promise<void> {
  const res = await fetch(`${API_URL}/api/usuarios/${id}/rol`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ nuevoRol }),
  });
  if (!res.ok) throw new Error('Error al actualizar rol');
}

// Proyectos
export async function obtenerProyectos(): Promise<Proyecto[]> {
  const res = await fetch(`${API_URL}/api/proyectos`);
  if (!res.ok) throw new Error('Error al obtener proyectos');
  return res.json();
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

export async function actualizarEstadoProyecto(id: number, habilitado: boolean): Promise<void> {
  const res = await fetch(`${API_URL}/api/proyectos/${id}/estado`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ habilitado }),
  });
  if (!res.ok) throw new Error('Error al actualizar estado');
}

// Relaciones
export async function obtenerProyectosPorUsuario(usuarioId: number): Promise<Proyecto[]> {
  const res = await fetch(`${API_URL}/api/usuarios/${usuarioId}/proyectos`);
  if (!res.ok) throw new Error('Error al obtener proyectos del usuario');
  return res.json();
}

export async function obtenerUsuariosPorProyecto(proyectoId: number): Promise<Usuario[]> {
  const res = await fetch(`${API_URL}/api/proyectos/${proyectoId}/usuarios`);
  if (!res.ok) throw new Error('Error al obtener usuarios del proyecto');
  return res.json();
}

export async function asociarUsuariosAProyecto(proyectoId: number, usuarios: number[]) {
  const res = await fetch(`${API_URL}/api/proyectos/${proyectoId}/usuarios`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ usuarios }),
  });
  if (!res.ok) throw new Error('Error al asociar usuarios');
}
