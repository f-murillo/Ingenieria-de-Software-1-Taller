import { useEffect, useState } from 'react';
import {
  obtenerUnidades,
  crearUnidad,
  actualizarUnidad,
  eliminarUnidad,
  type UnidadMedida,
} from './api';

interface Props {
  mostrarToast: (texto: string) => void;
}

export default function VistaUnidades({ mostrarToast }: Props) {
  const [unidades, setUnidades] = useState<UnidadMedida[]>([]);
  const [dimension, setDimension] = useState('');
  const [unidad, setUnidad] = useState('');
  const [editandoId, setEditandoId] = useState<number | null>(null);

  useEffect(() => {
    cargarUnidades();
  }, []);

  async function cargarUnidades() {
    try {
      const data = await obtenerUnidades();
      setUnidades(data ?? []);
    } catch (error) {
      console.error('Error al cargar unidades:', error);
      mostrarToast('Error al cargar unidades');
    }
  }

  async function manejarCrear() {
    if (!dimension || !unidad.trim()) return;
    try {
      const nueva = await crearUnidad({
        dimension: parseFloat(dimension),
        unidad: unidad.trim(),
      });
      setUnidades([...unidades, nueva]);
      setDimension('');
      setUnidad('');
      mostrarToast('Unidad creada correctamente');
    } catch (error) {
      console.error('Error al crear unidad:', error);
      mostrarToast('Error al crear unidad');
    }
  }

  async function manejarActualizar(id: number) {
    if (!dimension || !unidad.trim()) return;
    try {
      const actualizada = await actualizarUnidad(id, {
        dimension: parseFloat(dimension),
        unidad: unidad.trim(),
      });
      setUnidades(unidades.map(u => (u.id === id ? actualizada : u)));
      setEditandoId(null);
      setDimension('');
      setUnidad('');
      mostrarToast('Unidad actualizada correctamente');
    } catch (error) {
      console.error('Error al actualizar unidad:', error);
      mostrarToast('Error al actualizar unidad');
    }
  }

  async function manejarEliminar(id: number) {
    try {
      await eliminarUnidad(id);
      setUnidades(unidades.filter(u => u.id !== id));
      mostrarToast('Unidad eliminada correctamente');
    } catch (error) {
      console.error('Error al eliminar unidad:', error);
      mostrarToast('Error al eliminar unidad');
    }
  }

  return (
    <section>
      <h2 className="text-xl font-semibold text-gray-800 mb-4">Gestión de unidades de medida</h2>

      <div className="mb-4 flex gap-2">
        <input
          data-testid="input-dimension"
          type="number"
          step="any"
          value={dimension}
          onChange={e => setDimension(e.target.value)}
          placeholder="Dimensión"
          className="border px-2 py-1 w-1/3"
        />
        <input
          data-testid="input-unidad"
          type="text"
          value={unidad}
          onChange={e => setUnidad(e.target.value)}
          placeholder="Unidad (ej. Pulgadas)"
          className="border px-2 py-1 w-1/3"
        />
        {editandoId === null ? (
          <button
            data-testid="btn-agregar-unidad"
            onClick={manejarCrear}
            className="bg-blue-600 text-white px-4 py-1 rounded hover:bg-blue-700"
          >
            Crear
          </button>
        ) : (
          <>
            <button
              data-testid={`btn-guardar-unidad-${editandoId}`}
              onClick={() => manejarActualizar(editandoId)}
              className="bg-blue-600 text-white px-4 py-1 rounded hover:bg-blue-700"
            >
              Guardar
            </button>
            <button
              data-testid={`cancelar-unidad-${editandoId}`}
              onClick={() => {
                setEditandoId(null);
                setDimension('');
                setUnidad('');
              }}
              className="bg-gray-400 text-white px-4 py-1 rounded hover:bg-gray-500"
            >
              Cancelar
            </button>
          </>
        )}
      </div>

      <table className="w-full border border-gray-300">
        <thead className="bg-gray-200">
          <tr>
            <th className="px-4 py-2 text-center">ID</th>
            <th className="px-4 py-2 text-center">Dimensión</th>
            <th className="px-4 py-2 text-center">Unidad</th>
            <th className="px-4 py-2 text-center">Acciones</th>
          </tr>
        </thead>
        <tbody>
          {unidades.length > 0 ? (
            unidades.map(u => (
              <tr key={u.id} className="border-t">
                <td className="px-4 py-2 text-center">{u.id}</td>
                <td className="px-4 py-2 text-center">{u.dimension}</td>
                <td className="px-4 py-2 text-center">{u.unidad}</td>
                <td className="px-4 py-2 text-center">
                  <div className="flex gap-2 justify-center">
                    <button
                      data-testid={`btn-editar-unidad-${u.id}`}
                      onClick={() => {
                        setEditandoId(u.id);
                        setDimension(u.dimension.toString());
                        setUnidad(u.unidad);
                      }}
                      className="bg-[#80aeab] text-white px-3 py-1 rounded hover:bg-[#6b9996]"
                    >
                      Editar
                    </button>
                    <button
                      data-testid={`btn-eliminar-unidad-${u.id}`}
                      onClick={() => manejarEliminar(u.id)}
                      className="bg-[#7a99c7] text-white px-3 py-1 rounded hover:bg-[#6785ac]"
                    >
                      Eliminar
                    </button>
                  </div>
                </td>
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan={4} className="px-4 py-4 text-center text-gray-500">
                No hay unidades registradas.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </section>
  );
}
