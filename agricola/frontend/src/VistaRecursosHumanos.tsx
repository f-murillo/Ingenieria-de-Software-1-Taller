import { useEffect, useState } from "react";
import {
  type ActividadCantidad,
  obtenerTodosRecursosHumanos,
  crearActividadCantidad,
  actualizarActividadCantidad,
  eliminarActividadCantidad,
  obtenerActividadesPeriodo,
  type ActividadPeriodo,
} from "./api";

export default function VistaRecursosHumanos() {
  const [recursos, setRecursos] = useState<ActividadCantidad[]>([]);
  const [periodos, setPeriodos] = useState<ActividadPeriodo[]>([]);
  const [nuevo, setNuevo] = useState<Omit<ActividadCantidad, "id">>({
    periodo_id: 0,
    cantidad: 0,
    costo: 0,
    monto: 0,
  });
  const [editandoId, setEditandoId] = useState<number | null>(null);

  // estados para el modal
  const [showModal, setShowModal] = useState(false);
  const [idAEliminar, setIdAEliminar] = useState<number | null>(null);

  useEffect(() => {
    Promise.all([obtenerTodosRecursosHumanos(), obtenerActividadesPeriodo()])
      .then(([recursosData, periodosData]) => {
        setRecursos(recursosData);
        setPeriodos(periodosData);
      })
      .catch(console.error);
  }, []);

  const recargar = async () => {
    const lista = await obtenerTodosRecursosHumanos();
    setRecursos(lista);
  };

  const nombreActividad = (id: number) => {
    const act = periodos.find((p) => p.id === id);
    return act ? act.actividad : "-";
  };

  const horasActividad = (id: number) => {
    const act = periodos.find((p) => p.id === id);
    return act ? act.cantidad_horas : 0;
  };

  const handleCrear = async () => {
    try {
      const horas = horasActividad(nuevo.periodo_id);
      const montoCalculado = nuevo.cantidad * nuevo.costo * horas;

      await crearActividadCantidad({ ...nuevo, monto: montoCalculado });
      await recargar();
      setNuevo({ periodo_id: 0, cantidad: 0, costo: 0, monto: 0 });
    } catch (err) {
      console.error(err);
    }
  };

  const handleGuardar = async (recurso: ActividadCantidad) => {
    try {
      const horas = horasActividad(recurso.periodo_id);
      const montoCalculado = recurso.cantidad * recurso.costo * horas;

      await actualizarActividadCantidad({ ...recurso, monto: montoCalculado });
      await recargar();
      setEditandoId(null);
    } catch (err) {
      console.error(err);
    }
  };

  const handleEliminar = async (id: number) => {
    try {
      await eliminarActividadCantidad(id);
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

  const totalMontos = recursos.reduce((sum, i) => sum + i.monto, 0);

  return (
    <div>
      <h3 className="text-lg font-semibold mb-4">Recursos Humanos (todas las actividades)</h3>

      {/* Tabla */}
      <table className="w-full border-collapse border" data-testid="tabla-recursos-humanos">
        <thead>
          <tr className="bg-gray-200">
            <th className="border p-2">ID Actividad</th>
            <th className="border p-2">Nombre Actividad</th>
            <th className="border p-2">Horas</th>
            <th className="border p-2">Trabajadores</th>
            <th className="border p-2">Costo por trabajador (hora)</th>
            <th className="border p-2">Monto</th>
            <th className="border p-2">Acciones</th>
          </tr>
        </thead>
        <tbody>
          {recursos.map((r) => {
            const horas = horasActividad(r.periodo_id);
            const montoCalculado = r.cantidad * r.costo * horas;

            return (
              <tr key={r.id} data-testid={`fila-recurso-${r.id}`}>
                <td className="border p-2">{r.periodo_id}</td>
                <td className="border p-2">{nombreActividad(r.periodo_id)}</td>
                <td className="border p-2">{horas}</td>

                {/* Columna Trabajadores */}
                <td className="border p-2">
                  {editandoId === r.id ? (
                    <input
                      type="number"
                      value={r.cantidad}
                      onChange={(e) =>
                        setRecursos(
                          recursos.map((item) =>
                            item.id === r.id
                              ? { ...item, cantidad: Number(e.target.value) }
                              : item
                          )
                        )
                      }
                      className="border p-1 w-20"
                      data-testid={`input-cantidad-${r.id}`}
                    />
                  ) : (
                    r.cantidad
                  )}
                </td>

                {/* Columna Costo */}
                <td className="border p-2">
                  {editandoId === r.id ? (
                    <input
                      type="number"
                      value={r.costo}
                      onChange={(e) =>
                        setRecursos(
                          recursos.map((item) =>
                            item.id === r.id
                              ? { ...item, costo: Number(e.target.value) }
                              : item
                          )
                        )
                      }
                      className="border p-1 w-20"
                      data-testid={`input-costo-${r.id}`}
                    />
                  ) : (
                    r.costo
                  )}
                </td>

                {/* Columna Monto */}
                <td className="border p-2" data-testid={`monto-recurso-${r.id}`}>
                  ${montoCalculado}
                </td>

                {/* Columna Acciones */}
                <td className="border p-2 space-x-2">
                  {editandoId === r.id ? (
                    <button
                      data-testid={`btn-guardar-recurso-${r.id}`}
                      onClick={() => {
                        const recurso = recursos.find((item) => item.id === r.id);
                        if (recurso) handleGuardar(recurso);
                      }}
                      className="bg-blue-600 text-white px-2 py-1 rounded"
                    >
                      Guardar
                    </button>
                  ) : (
                    <button
                      data-testid={`btn-editar-recurso-${r.id}`}
                      onClick={() => setEditandoId(r.id)}
                      className="bg-[#80aeab] text-white px-2 py-1 rounded hover:bg-[#6b9996] hover:cursor-pointer"
                    >
                      Editar
                    </button>
                  )}
                  <button
                    data-testid={`btn-eliminar-recurso-${r.id}`}
                    onClick={() => {
                      setIdAEliminar(r.id);
                      setShowModal(true);
                    }}
                    className="bg-[#7a99c7] text-white px-2 py-1 rounded hover:bg-[#6785ac] hover:cursor-pointer"
                  >
                    Eliminar
                  </button>
                </td>
              </tr>
            );
          })}

          {/* Fila de totales */}
          <tr className="bg-gray-100 font-semibold" data-testid="fila-total-recursos">
            <td colSpan={5} className="border p-2 text-right">
              Total
            </td>
            <td className="border p-2" data-testid="total-montos-recursos">
              ${totalMontos}
            </td>
            <td className="border p-2"></td>
          </tr>

          {recursos.length === 0 && (
            <tr>
              <td colSpan={7} className="text-center p-4 text-gray-500" data-testid="sin-recursos">
                No hay recursos humanos registrados
              </td>
            </tr>
          )}
        </tbody>
      </table>


      {showModal && (
        <div
          className="fixed inset-0 flex items-center justify-center bg-opacity-10 backdrop-blur-sm"
          data-testid="modal-eliminar-recurso"
        >
          <div className="bg-white p-6 rounded shadow-lg">
            <h4 className="text-lg font-semibold mb-4">Confirmar eliminación</h4>
            <p className="mb-4">
              Si eliminas los recursos humanos, también se eliminará la actividad asociada.
              ¿Estás seguro de continuar?
            </p>
            <div className="flex justify-end space-x-2">
              <button
                data-testid="btn-cancelar-eliminar-recurso"
                onClick={() => setShowModal(false)}
                className="bg-gray-400 text-white px-4 py-2 rounded"
              >
                Cancelar
              </button>
              <button
                data-testid="btn-confirmar-eliminar-recurso"
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
