import { useEffect, useState } from "react";
import {
  type ActividadCategoria,
  obtenerTodosActividadesCategoria,
  crearActividadCategoria,
  actualizarActividadCategoria,
  eliminarActividadCategoria,
  obtenerActividadesPeriodo,
  type ActividadPeriodo,
} from "./api";

export default function VistaInsumos() {
  const [insumos, setInsumos] = useState<ActividadCategoria[]>([]);
  const [periodos, setPeriodos] = useState<ActividadPeriodo[]>([]);
  const [nuevo, setNuevo] = useState<Omit<ActividadCategoria, "id">>({
    periodo_id: 0,
    categoria: "",
    descripcion: "",
    cantidad: 0,
    medida: "",
    monto: 0,
  });
  const [editandoId, setEditandoId] = useState<number | null>(null);

  // estados para el modal
  const [showModal, setShowModal] = useState(false);
  const [idAEliminar, setIdAEliminar] = useState<number | null>(null);

  useEffect(() => {
    Promise.all([obtenerTodosActividadesCategoria(), obtenerActividadesPeriodo()])
      .then(([insumosData, periodosData]) => {
        setInsumos(insumosData);
        setPeriodos(periodosData);
      })
      .catch(console.error);
  }, []);

  const recargar = async () => {
    const lista = await obtenerTodosActividadesCategoria();
    setInsumos(lista);
  };

  const nombreActividad = (id: number) => {
    const act = periodos.find((p) => p.id === id);
    return act ? act.actividad : "-";
  };

  const handleCrear = async () => {
    try {
      await crearActividadCategoria(nuevo);
      await recargar();
      setNuevo({
        periodo_id: 0,
        categoria: "",
        descripcion: "",
        cantidad: 0,
        medida: "",
        monto: 0,
      });
    } catch (err) {
      console.error(err);
    }
  };

  const handleGuardar = async (insumo: ActividadCategoria) => {
    try {
      await actualizarActividadCategoria(insumo);
      await recargar();
      setEditandoId(null);
    } catch (err) {
      console.error(err);
    }
  };

  const handleEliminar = async (id: number) => {
    try {
      await eliminarActividadCategoria(id);
      await recargar();
    } catch (err) {
      console.error(err);
    }
  };

  // función para confirmar eliminación desde el modal
  const confirmarEliminar = async () => {
    if (idAEliminar !== null) {
      await handleEliminar(idAEliminar);
    }
    setShowModal(false);
    setIdAEliminar(null);
  };

    const totalMontos = insumos.reduce((sum, i) => sum + i.monto, 0);
    return (
    <div>
        <h3 className="text-lg font-semibold mb-4">Insumos / Materiales (todas las actividades)</h3>

        {/* Tabla */}
        <table className="w-full border-collapse border" data-testid="tabla-insumos">
        <thead>
            <tr className="bg-gray-200">
            <th className="border p-2">ID Actividad</th>
            <th className="border p-2">Nombre Actividad</th>
            <th className="border p-2">Categoría</th>
            <th className="border p-2">Descripción</th>
            <th className="border p-2">Cantidad</th>
            <th className="border p-2">Medida</th>
            <th className="border p-2">Monto</th>
            <th className="border p-2">Acciones</th>
            </tr>
        </thead>
          <tbody>
            {insumos.map((i) => (
              <tr key={i.id} data-testid={`fila-insumo-${i.id}`}>
                <td className="border p-2">{i.periodo_id}</td>
                <td className="border p-2">{nombreActividad(i.periodo_id)}</td>

                {/* Columna Categoría */}
                <td className="border p-2">
                  {editandoId === i.id ? (
                    <input
                      type="text"
                      value={i.categoria}
                      onChange={(e) =>
                        setInsumos(
                          insumos.map((item) =>
                            item.id === i.id ? { ...item, categoria: e.target.value } : item
                          )
                        )
                      }
                      className="border p-1 w-24"
                      data-testid={`input-categoria-${i.id}`}
                    />
                  ) : (
                    i.categoria
                  )}
                </td>

                {/* Columna Descripción */}
                <td className="border p-2">
                  {editandoId === i.id ? (
                    <input
                      type="text"
                      value={i.descripcion}
                      onChange={(e) =>
                        setInsumos(
                          insumos.map((item) =>
                            item.id === i.id ? { ...item, descripcion: e.target.value } : item
                          )
                        )
                      }
                      className="border p-1 w-32"
                      data-testid={`input-descripcion-${i.id}`}
                    />
                  ) : (
                    i.descripcion
                  )}
                </td>

                {/* Columna Cantidad */}
                <td className="border p-2">
                  {editandoId === i.id ? (
                    <input
                      type="number"
                      value={i.cantidad}
                      onChange={(e) =>
                        setInsumos(
                          insumos.map((item) =>
                            item.id === i.id ? { ...item, cantidad: Number(e.target.value) } : item
                          )
                        )
                      }
                      className="border p-1 w-20"
                      data-testid={`input-cantidad-${i.id}`}
                    />
                  ) : (
                    i.cantidad
                  )}
                </td>

                {/* Columna Medida */}
                <td className="border p-2">
                  {editandoId === i.id ? (
                    <input
                      type="text"
                      value={i.medida}
                      onChange={(e) =>
                        setInsumos(
                          insumos.map((item) =>
                            item.id === i.id ? { ...item, medida: e.target.value } : item
                          )
                        )
                      }
                      className="border p-1 w-20"
                      data-testid={`input-medida-${i.id}`}
                    />
                  ) : (
                    i.medida
                  )}
                </td>

                {/* Columna Monto */}
                <td className="border p-2" data-testid={`monto-insumo-${i.id}`}>
                  {editandoId === i.id ? (
                    <input
                      type="number"
                      value={i.monto}
                      onChange={(e) =>
                        setInsumos(
                          insumos.map((item) =>
                            item.id === i.id ? { ...item, monto: Number(e.target.value) } : item
                          )
                        )
                      }
                      className="border p-1 w-24"
                      data-testid={`input-monto-${i.id}`}
                    />
                  ) : (
                    `$${i.monto}`
                  )}
                </td>

                {/* Columna Acciones */}
                <td className="border p-2 space-x-2">
                  {editandoId === i.id ? (
                    <button
                      data-testid={`btn-guardar-insumo-${i.id}`}
                      onClick={() => {
                        const insumo = insumos.find((item) => item.id === i.id);
                        if (insumo) handleGuardar(insumo);
                      }}
                      className="bg-blue-600 text-white px-2 py-1 rounded"
                    >
                      Guardar
                    </button>
                  ) : (
                    <button
                      data-testid={`btn-editar-insumo-${i.id}`}
                      onClick={() => setEditandoId(i.id)}
                      className="bg-[#80aeab] text-white px-2 py-1 rounded hover:bg-[#6b9996] hover:cursor-pointer"
                    >
                      Editar
                    </button>
                  )}
                  <button
                    data-testid={`btn-eliminar-insumo-${i.id}`}
                    onClick={() => {
                      setIdAEliminar(i.id);
                      setShowModal(true);
                    }}
                    className="bg-[#7a99c7] text-white px-2 py-1 rounded hover:bg-[#6785ac] hover:cursor-pointer"
                  >
                    Eliminar
                  </button>
                </td>
              </tr>
            ))}

            {/* Fila de totales */}
            <tr className="bg-gray-100 font-semibold" data-testid="fila-total-insumos">
              <td colSpan={6} className="border p-2 text-right">
                Total
              </td>
              <td className="border p-2" data-testid="total-montos-insumos">
                ${totalMontos}
              </td>
              <td className="border p-2"></td>
            </tr>

            {insumos.length === 0 && (
              <tr>
                <td colSpan={8} className="text-center p-4 text-gray-500" data-testid="sin-insumos">
                  No hay insumos registrados
                </td>
              </tr>
            )}
          </tbody>
        </table>


        {/* Modal de confirmación */}
        {showModal && (
          <div
            className="fixed inset-0 flex items-center justify-center bg-opacity-10 backdrop-blur-sm"
            data-testid="modal-eliminar-insumo"
          >
            <div className="bg-white p-6 rounded shadow-lg">
              <h4 className="text-lg font-semibold mb-4">Confirmar eliminación</h4>
              <p className="mb-4">
                Si eliminas este insumo, también se eliminará la actividad asociada.
                ¿Estás seguro de continuar?
              </p>
              <div className="flex justify-end space-x-2">
                <button
                  data-testid="btn-cancelar-eliminar-insumo"
                  onClick={() => setShowModal(false)}
                  className="bg-gray-400 text-white px-4 py-2 rounded"
                >
                  Cancelar
                </button>
                <button
                  data-testid="btn-confirmar-eliminar-insumo"
                  onClick={confirmarEliminar}
                  className="bg-red-600 text-white px-4 py-2 rounded"
                >
                  Eliminar
                </button>
              </div>
            </div>
          </div>
        )}

    </div>
    );
}