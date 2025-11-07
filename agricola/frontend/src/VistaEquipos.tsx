import { useEffect, useState } from 'react';
import {
  obtenerEquipos,
  crearEquipo,
  actualizarEquipo,
  eliminarEquipo,
} from './api';
import type { EquipoImplemento } from './api';

interface Props {
  mostrarToast: (texto: string) => void;
}

export default function VistaEquipos({ mostrarToast }: Props) {
  const [equipos, setEquipos] = useState<EquipoImplemento[]>([]);
  const [nuevoEquipo, setNuevoEquipo] = useState('');
  const [editandoId, setEditandoId] = useState<number | null>(null);
  const [tituloEditado, setTituloEditado] = useState('');

  useEffect(() => {
    cargarEquipos();
  }, []);

  async function cargarEquipos() {
    try {
      const data = await obtenerEquipos();
      setEquipos(data);
    } catch (error) {
      console.error('Error al cargar equipos:', error);
      mostrarToast('Error al cargar equipos');
    }
  }

  async function manejarCrear() {
    if (!nuevoEquipo.trim()) return;
    try {
      const equipo = await crearEquipo(nuevoEquipo.trim());
      setEquipos([...equipos, equipo]);
      setNuevoEquipo('');
      mostrarToast('Equipo creado correctamente');
    } catch (error) {
      console.error('Error al crear equipo:', error);
      mostrarToast('Error al crear equipo');
    }
  }

  async function manejarActualizar(id: number) {
    if (!tituloEditado.trim()) return;
    try {
      const equipo = await actualizarEquipo(id, tituloEditado.trim());
      setEquipos(equipos.map(e => (e.id === id ? equipo : e)));
      setEditandoId(null);
      setTituloEditado('');
      mostrarToast('Equipo actualizado correctamente');
    } catch (error) {
      console.error('Error al actualizar equipo:', error);
      mostrarToast('Error al actualizar equipo');
    }
  }

  async function manejarEliminar(id: number) {
    try {
      await eliminarEquipo(id);
      setEquipos(equipos.filter(e => e.id !== id));
      mostrarToast('Equipo eliminado correctamente');
    } catch (error) {
      console.error('Error al eliminar equipo:', error);
      mostrarToast('Error al eliminar equipo');
    }
  }

  return (
    <section>
      <h2 className="text-xl font-semibold text-gray-800 mb-4">Gestión de equipos e implementos</h2>

      <div className="mb-4 flex gap-2">
        <input
          data-testid="input-equipos"
          type="text"
          value={nuevoEquipo}
          onChange={e => setNuevoEquipo(e.target.value)}
          placeholder="Nuevo equipo o implemento"
          className="border px-2 py-1 w-full"
        />
        <button
          data-testid="btn-agregar-equipos"
          onClick={manejarCrear}
          className="bg-green-600 text-white px-4 py-1 rounded hover:bg-green-700"
        >
          Crear
        </button>
      </div>

      <table className="w-full border border-gray-300">
        <thead className="bg-gray-200">
          <tr>
            <th className="px-4 py-2">ID</th>
            <th className="px-4 py-2">Título</th>
            <th className="px-4 py-2">Acciones</th>
          </tr>
        </thead>
        <tbody>
          {equipos.map(e => (
            <tr key={e.id} className="border-t">
              <td className="px-4 py-2">{e.id}</td>
              <td className="px-4 py-2">
                {editandoId === e.id ? (
                  <input
                    data-testid={`input-titulo-equipos-${e.id}`}
                    type="text"
                    value={tituloEditado}
                    onChange={ev => setTituloEditado(ev.target.value)}
                    className="border px-2 py-1 w-full"
                  />
                ) : (
                  e.titulo
                )}
              </td>
              <td className="px-4 py-2 flex gap-2">
                {editandoId === e.id ? (
                  <>
                    <button
                      data-testid={`btn-guardar-equipos-${e.id}`}
                      onClick={() => manejarActualizar(e.id)}
                      className="bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700"
                    >
                      Guardar
                    </button>
                    <button
                      data-testid={`cancelar-equipos-${e.id}`}
                      onClick={() => {
                        setEditandoId(null);
                        setTituloEditado('');
                      }}
                      className="bg-gray-400 text-white px-3 py-1 rounded hover:bg-gray-500"
                    >
                      Cancelar
                    </button>
                  </>
                ) : (
                  <>
                    <button
                      
                      data-testid={`btn-editar-equipos-${e.id}`}
                      onClick={() => {
                        setEditandoId(e.id);
                        setTituloEditado(e.titulo);
                      }}
                      className="bg-yellow-500 text-white px-3 py-1 rounded hover:bg-yellow-600"
                    >
                      Editar
                    </button>
                    <button
                      data-testid={`btn-eliminar-equipos-${e.id}`}
                      onClick={() => manejarEliminar(e.id)}
                      className="bg-red-600 text-white px-3 py-1 rounded hover:bg-red-700"
                    >
                      Eliminar
                    </button>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
