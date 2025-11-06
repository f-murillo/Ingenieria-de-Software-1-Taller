import { useEffect, useState } from 'react';
import {
  obtenerLabores,
  crearLabor,
  actualizarLabor,
  eliminarLabor,
} from './api';
import type { LaborAgronomica } from './api';

interface Props {
  mostrarToast: (texto: string) => void;
}

export default function VistaLabores({ mostrarToast }: Props) {
  const [labores, setLabores] = useState<LaborAgronomica[]>([]);
  const [nuevaLabor, setNuevaLabor] = useState('');
  const [editandoId, setEditandoId] = useState<number | null>(null);
  const [tituloEditado, setTituloEditado] = useState('');

  useEffect(() => {
    cargarLabores();
  }, []);

  async function cargarLabores() {
    try {
      const data = await obtenerLabores();
      setLabores(data);
    } catch (error) {
      console.error('Error al cargar labores:', error);
      mostrarToast('Error al cargar labores');
    }
  }

  async function manejarCrear() {
    if (!nuevaLabor.trim()) return;
    try {
      const labor = await crearLabor(nuevaLabor.trim());
      setLabores([...labores, labor]);
      setNuevaLabor('');
      mostrarToast('Labor creada correctamente');
    } catch (error) {
      console.error('Error al crear labor:', error);
      mostrarToast('Error al crear labor');
    }
  }

  async function manejarActualizar(id: number) {
    if (!tituloEditado.trim()) return;
    try {
      const labor = await actualizarLabor(id, tituloEditado.trim());
      setLabores(labores.map(l => (l.id === id ? labor : l)));
      setEditandoId(null);
      setTituloEditado('');
      mostrarToast('Labor actualizada correctamente');
    } catch (error) {
      console.error('Error al actualizar labor:', error);
      mostrarToast('Error al actualizar labor');
    }
  }

  async function manejarEliminar(id: number) {
    try {
      await eliminarLabor(id);
      setLabores(labores.filter(l => l.id !== id));
      mostrarToast('Labor eliminada correctamente');
    } catch (error) {
      console.error('Error al eliminar labor:', error);
      mostrarToast('Error al eliminar labor');
    }
  }

  return (
    <section>
      <h2 className="text-xl font-semibold text-gray-800 mb-4">Gestión de labores agronómicas</h2>

      <div className="mb-4 flex gap-2">
        <input
          type="text"
          value={nuevaLabor}
          onChange={e => setNuevaLabor(e.target.value)}
          placeholder="Nueva labor"
          className="border px-2 py-1 w-full"
        />
        <button
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
          {labores.map(l => (
            <tr key={l.id} className="border-t">
              <td className="px-4 py-2">{l.id}</td>
              <td className="px-4 py-2">
                {editandoId === l.id ? (
                  <input
                    type="text"
                    value={tituloEditado}
                    onChange={e => setTituloEditado(e.target.value)}
                    className="border px-2 py-1 w-full"
                  />
                ) : (
                  l.titulo
                )}
              </td>
              <td className="px-4 py-2 flex gap-2">
                {editandoId === l.id ? (
                  <>
                    <button
                      onClick={() => manejarActualizar(l.id)}
                      className="bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700"
                    >
                      Guardar
                    </button>
                    <button
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
                      onClick={() => {
                        setEditandoId(l.id);
                        setTituloEditado(l.titulo);
                      }}
                      className="bg-yellow-500 text-white px-3 py-1 rounded hover:bg-yellow-600"
                    >
                      Editar
                    </button>
                    <button
                      onClick={() => manejarEliminar(l.id)}
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
