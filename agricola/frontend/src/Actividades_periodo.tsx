import React, { useState, useEffect, act } from "react";
import {
  crearActividadPeriodo,
  crearActividadCantidad,
  crearActividadCategoria,
  obtenerActividadesPeriodo,
  obtenerUsuarios,
  obtenerUnidades,
  obtenerLabores,
  actualizarPeriodo,
  eliminarPeriodo,
} from "./api";
import type { ActividadPeriodo, Usuario, LaborAgronomica, UnidadMedida } from "./api";

export default function FormularioActividades() {
  const [usuarios, setUsuarios] = useState<Usuario[]>([]);
  const [periodos, setPeriodos] = useState<ActividadPeriodo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [periodo, setPeriodo] = useState({
    actividad: "",
    accion: "",
    fecha_inicio: "",
    fecha_cierre: "",
    cantidad_horas: 0,
    responsable: "",
    monto: 0,
  });

  const [cantidad, setCantidad] = useState({
    cantidad: 0,
    costo: 0,
    monto: 0,
  });

  const [categoria, setCategoria] = useState({
    categoria: "",
    descripcion: "",
    cantidad: 0,
    medida: "",
    monto: 0,
  });

  const [periodoId, setPeriodoId] = useState<number | null>(null);
  const [cantidadGuardada, setCantidadGuardada] = useState(false);
  const [categoriaGuardada, setCategoriaGuardada] = useState(false);
  const [mensaje, setMensaje] = useState<string | null>(null);
  const [labores, setLabores] = useState<LaborAgronomica[]>([]);
  const [unidades, setUnidades] = useState<UnidadMedida[]>([]);
  const [periodoEditando, setPeriodoEditando] = useState<number | null>(null);
  const [datosEditados, setDatosEditados] = useState<ActividadPeriodo | null>(null);
  const [busqueda, setBusqueda] = useState("");



  useEffect(() => {
  // recalcular monto cuando cambien los costos de cantidad o categoría
  const total = (cantidad.monto || 0) + (categoria.monto || 0);
  setPeriodo(prev => ({ ...prev, monto: total }));
}, [cantidad.monto, categoria.monto]);

  useEffect(() => {
  const montoCalculado = periodo.cantidad_horas * cantidad.cantidad * cantidad.costo;
  setCantidad(prev => ({ ...prev, monto: montoCalculado }));
}, [cantidad.cantidad, cantidad.costo, periodo.cantidad_horas]);


useEffect(() => {
  const fetchLabores = async () => {
    try {
      const data = await obtenerLabores(); // tu función en api
      setLabores(data);
    } catch {
      setError("No se pudieron cargar las labores");
    }
  };

  const fetchMedidas = async () => {
    try {
      const data = await obtenerUnidades(); // tu función en api
      setUnidades(data);
    } catch {
      setError("No se pudieron cargar las medidas");
    }
  };

  fetchLabores();
  fetchMedidas();
}, []);



    useEffect(() => {
      const fetchUsuarios = async () => {
        try {
          const data = await obtenerUsuarios();
          setUsuarios(data);
        } catch {
          setError("No se pudieron cargar los usuarios");
        }
      };
      fetchUsuarios();
    }, []);

  const fetchPeriodos = async () => {
    try {
      const data = await obtenerActividadesPeriodo();
      setPeriodos(data);
    } catch {
      setError("No se pudieron cargar los periodos");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPeriodos();
  }, []);


const calcularHorasLaborables = (inicio: string, cierre: string): number => {
  if (!inicio || !cierre) return 0;
  const fechaInicio = new Date(inicio);
  const fechaCierre = new Date(cierre);

  // diferencia en milisegundos
  const diffMs = fechaCierre.getTime() - fechaInicio.getTime();
  if (diffMs <= 0) return 0;

  // diferencia en días (redondeando hacia abajo)
  const diffDias = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  // cada día cuenta como 8 horas laborables
  return diffDias * 8;
};


  const guardarTodo = async () => {
  try {
    // 1. Crear periodo
    const periodoResp = await crearActividadPeriodo(periodo);
    const nuevoPeriodoId = periodoResp.id;

    // 2. Crear cantidad
    await crearActividadCantidad({ ...cantidad, periodo_id: nuevoPeriodoId });

    // 3. Crear categoría
    await crearActividadCategoria({ ...categoria, periodo_id: nuevoPeriodoId });

    // 4. Refrescar tabla
    await fetchPeriodos();

    setMensaje(`Accion Guardada Exitosamente (ID: ${nuevoPeriodoId}).`);
    setPeriodoId(nuevoPeriodoId);
    setCantidadGuardada(true);
    setCategoriaGuardada(true);
  } catch {
    setMensaje("Error al guardar el periodo completo");
  }
};

  const totalMontos = periodos.reduce((acc, p) => acc + (p.monto || 0), 0);
  const [mostrarFormulario, setMostrarFormulario] = useState(false);
  const periodosFiltrados = periodos.filter((p) =>
    p.actividad.toLowerCase().includes(busqueda.toLowerCase()) ||
    p.accion.toLowerCase().includes(busqueda.toLowerCase()) ||
    p.responsable.toLowerCase().includes(busqueda.toLowerCase())
);

  const handleActualizar = async () => {
  try {
    await actualizarPeriodo(datosEditados!);
    setPeriodoEditando(null);
    await fetchPeriodos();
    setMensaje("Actividad actualizada correctamente"); // 👈 mensaje de éxito
  } catch (error) {
    console.error(error);
    setMensaje("Error al actualizar actividad");
  }
};

  const handleEliminar = async (id: number) => {
  try {
    await eliminarPeriodo(id);
    await fetchPeriodos();
    setMensaje("Actividad eliminada correctamente"); // 👈 mensaje de éxito
  } catch (error) {
    console.error(error);
    setMensaje("Error al eliminar actividad");
  }
};


  return (
  <div className="p-6">
    <h2 className="text-2xl font-bold mb-4">Plan de Accion</h2>
    <input
      data-testid="input-buscar-acciones"
      type="text"
      placeholder="Buscar por actividad..."
      value={busqueda}
      onChange={e => setBusqueda(e.target.value)}
      className="mb-4 p-2 border border-gray-300 rounded"
    />
    {/* Tabla de periodos */}
    {loading ? (
      <p>Cargando periodos...</p>
    ) : error ? (
      <p className="text-red-600">{error}</p>
    ) : (
      <table className="w-full border-collapse border border-gray-300 mb-6">
        <thead className="bg-gray-200">
          <tr>
            <th className="border p-2">ID</th>
            <th className="border p-2">Actividad</th>
            <th className="border p-2">Acción</th>
            <th className="border p-2">Fecha inicio</th>
            <th className="border p-2">Fecha cierre</th>
            <th className="border p-2">Horas</th>
            <th className="border p-2">Responsable</th>
            <th className="border p-2">Monto</th>
            <th className="border p-2">Acciones</th>
          </tr>
        </thead>
        <tbody>
          {periodosFiltrados.map((p) => (
            <tr key={p.id} className="hover:bg-gray-100">
              <td className="border p-2">{p.id}</td>
              <td className="border p-2">
                {periodoEditando === p.id ? (
                  <input          
                    data-testid={`input-actividad-${p.id}`}
                    type="text"
                    value={datosEditados?.actividad || ""}
                    onChange={e =>
                      setDatosEditados(prev => ({ ...prev!, actividad: e.target.value }))
                    }
                    className="border p-1 w-full"
                  />
                ) : (
                  p.actividad
                )}
              </td>
              <td className="border p-2">
                {periodoEditando === p.id ? (
                  <select
                    data-testid={`select-accion-${p.id}`}
                    value={datosEditados?.accion || ""}
                    onChange={e =>
                      setDatosEditados(prev => ({ ...prev!, accion: e.target.value }))
                    }
                    className="border p-1 w-full"
                  >
                    <option value="">Seleccione una acción</option>
                    {labores.map(l => (
                      <option key={l.id} value={l.titulo}>{l.titulo}</option>
                    ))}
                  </select>
                ) : (
                  p.accion
                )}
              </td>
              <td className="border p-2">
                {periodoEditando === p.id ? (
                  <input
                    data-testid={`input-fecha-inicio-${p.id}`}
                    type="date"
                    value={datosEditados?.fecha_inicio || ""}
                    onChange={e => {
                      const nuevaFecha = e.target.value;
                      setDatosEditados(prev => ({
                        ...prev!,
                        fecha_inicio: nuevaFecha,
                        cantidad_horas: calcularHorasLaborables(nuevaFecha, prev!.fecha_cierre),
                      }));
                    }}
                    className="border p-1 w-full"
                  />
                ) : (
                  p.fecha_inicio
                )}
              </td>
              <td className="border p-2">
                {periodoEditando === p.id ? (
                  <input
                    data-testid={`input-fecha-cierre-${p.id}`}
                    type="date"
                    value={datosEditados?.fecha_cierre || ""}
                    onChange={e => {
                      const nuevaFecha = e.target.value;
                      setDatosEditados(prev => ({
                        ...prev!,
                        fecha_cierre: nuevaFecha,
                        cantidad_horas: calcularHorasLaborables(prev!.fecha_inicio, nuevaFecha),
                      }));
                    }}
                    className="border p-1 w-full"
                  />
                ) : (
                  p.fecha_cierre
                )}
              </td>
              <td className="border p-2">
                {periodoEditando === p.id ? (
                  <strong>{datosEditados?.cantidad_horas}</strong>
                ) : (
                  p.cantidad_horas
                )}
              </td>
              <td className="border p-2">
                {periodoEditando === p.id ? (
                  <select
                    data-testid={`select-responsable-${p.id}`}
                    value={datosEditados?.responsable || ""}
                    onChange={e =>
                      setDatosEditados(prev => ({ ...prev!, responsable: e.target.value }))
                    }
                    className="border p-1 w-full"
                  >
                    <option value="">Seleccione un responsable</option>
                    {usuarios.map(u => (
                      <option key={u.id} value={`${u.nombre} ${u.apellido}`}>
                        {u.nombre} {u.apellido}
                      </option>
                    ))}
                  </select>
                ) : (
                  p.responsable
                )}
              </td>
              <td className="border p-2">${p.monto}</td>
              <td className="border p-2 text-center">
                <div className="flex flex-wrap gap-2 justify-center">
                  {periodoEditando === p.id ? (
                   <button
                    data-testid={`btn-guardar-actividad-${p.id}`}
                    onClick={handleActualizar}
                    className="bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700"
                  >
                    Guardar
                  </button>

                  ) : (
                    <button
                    data-testid={`btn-editar-actividad-${p.id}`}
                      onClick={() => {
                        setPeriodoEditando(p.id);
                        setDatosEditados({ ...p });
                      }}
                      className="bg-[#80aeab] text-white px-3 py-1 rounded hover:bg-[#6b9996] hover:cursor-pointer"
                    >
                      Editar
                    </button>
                  )}
                  <button
                    data-testid={`btn-eliminar-actividad-${p.id}`}
                    onClick={() => handleEliminar(p.id)}   // 👈 ahora usa la función centralizada
                    className="bg-[#7a99c7] text-white px-3 py-1 rounded hover:bg-[#6785ac] hover:cursor-pointer"
                  >
                    Eliminar
                  </button>
                </div>
                </td>
              </tr>
            ))}

          {/* Fila de total */}
          <tr className="bg-gray-100 font-bold">
            <td className="border p-2 text-right" colSpan={7}>Total</td>
            <td className="border p-2">${totalMontos}</td>
            <td className="border p-2"></td>
          </tr>
        </tbody>

      </table>
    )}
    {mensaje && (
      <div className="mb-4 p-2 rounded bg-blue-100 text-blue-800">{mensaje}</div>
    )}

    {/* Botón toggle */}
    <button
      data-testid="btn-nueva-actividad"
      onClick={() => setMostrarFormulario(prev => !prev)}
      className="px-4 py-2 rounded text-white bg-blue-600 hover:bg-blue-700 mb-4"
    >
      {mostrarFormulario ? "Ocultar acción" : "Agregar acción"}
    </button>

    {mostrarFormulario && (
      <div className="border p-4 rounded bg-gray-50">
      <h2 className="text-2xl font-bold mb-4">Ingrese una Accion</h2>

        {mensaje && (
          <div className="mb-4 p-2 rounded bg-blue-100 text-blue-800">{mensaje}</div>
        )}
        {/* Parte 1: Periodo */}
        <div className="mb-6 border p-4 rounded">
          <h3 className="text-xl font-semibold mb-2">Actividades</h3>
          <label className="block text-sm font-medium">Actividad</label>
          <input
            data-testid="input-actividad"
            type="text"
            placeholder="Actividad"
            value={periodo.actividad}
            onChange={e => setPeriodo({ ...periodo, actividad: e.target.value })}
            className="border p-2 w-full mb-2"
          />
          <label className="block text-sm font-medium">Acción</label>
          <select
            data-testid="select-accion"
            value={periodo.accion}
            onChange={e => setPeriodo({ ...periodo, accion: e.target.value })}
            className="border p-2 w-full mb-2"
          >
            <option value="">Seleccione una acción</option>
            {labores.map(l => (
              <option key={l.id} value={l.titulo}>
                {l.titulo}
            </option>
        ))}
        </select>
          <label className="block text-sm font-medium">Fecha de Inicio</label>
          <input
            data-testid="input-fecha-inicio"
            type="date"
            value={periodo.fecha_inicio}
            onChange={e => {
              const nuevaFecha = e.target.value;
              setPeriodo(prev => ({
                ...prev,
                fecha_inicio: nuevaFecha,
                cantidad_horas: calcularHorasLaborables(nuevaFecha, prev.fecha_cierre),
              }));
            }}
            className="border p-2 w-full mb-2"
          />
          <label className="block text-sm font-medium">Fecha de Cierre</label>
          <input
            data-testid="input-fecha-cierre"
            type="date"
            value={periodo.fecha_cierre}
            onChange={e => {
              const nuevaFecha = e.target.value;
              setPeriodo(prev => ({
                ...prev,
                fecha_cierre: nuevaFecha,
                cantidad_horas: calcularHorasLaborables(prev.fecha_inicio, nuevaFecha),
              }));
            }}
            className="border p-2 w-full mb-2"
          />
          <p className="mb-2">
            Horas calculadas: <strong>{periodo.cantidad_horas}</strong>
          </p>
          <label className="block text-sm font-medium">Responsable</label>
          <select
            data-testid="select-responsable"
            value={periodo.responsable}
            onChange={e => setPeriodo({ ...periodo, responsable: e.target.value })}
            className="border p-2 w-full mb-2"
          >
            <option value="">Seleccione un responsable</option>
            {usuarios.map(u => (
              <option key={u.id} value={`${u.nombre} ${u.apellido}`}>
                {u.nombre} {u.apellido}
              </option>
            ))}
          </select>
          <p className="mb-2">
            Costo total calculado: <strong>${periodo.monto}</strong>
          </p>
        </div>

        {/* Parte 2: Talento Humano */}
        <div className="mb-6 border p-4 rounded">
          <h3 className="text-xl font-semibold mb-2">Talento Humano</h3>
          <label className="block text-sm font-medium">Cantidad de Trabajadores</label>
          <input
            data-testid="input-cantidad-accion"
            type="number"
            placeholder="Cantidad"
            value={cantidad.cantidad}
            onChange={e => setCantidad({ ...cantidad, cantidad: Number(e.target.value) })}
            className="border p-2 w-full mb-2"
          />
          <label className="block text-sm font-medium">Costo por Trabajador</label>
          <input
            data-testid="input-costo"
            type="number"
            placeholder="Costo ($)"
            value={cantidad.costo}
            onChange={e => setCantidad({ ...cantidad, costo: Number(e.target.value) })}
            className="border p-2 w-full mb-2"
          />
          <p className="mb-2">
            Monto calculado: <strong>${cantidad.monto}</strong>
          </p>
        </div>

        {/* Parte 3: Categoría */}
        <div className="mb-6 border p-4 rounded">
          <h3 className="text-xl font-semibold mb-2">Insumos, Medidas y Equipos</h3>
          <label className="block text-sm font-medium">Categoría</label>
          <select
            data-testid="select-categoria"
            value={categoria.categoria}
            onChange={e => setCategoria({ ...categoria, categoria: e.target.value })}
            className="border p-2 w-full mb-2"
          >
            <option value="">Seleccione una categoría</option>
            <option value="Ninguno">Ninguno</option>
            <option value="Materiales">Materiales</option>
            <option value="Insumos">Insumos</option>
            <option value="Equipos">Equipos</option>
          </select>
          <label className="block text-sm font-medium">Descripción</label>
          <input
            data-testid="input-descripcion"
            type="text"
            placeholder="Descripción"
            value={categoria.descripcion}
            onChange={e => setCategoria({ ...categoria, descripcion: e.target.value })}
            className="border p-2 w-full mb-2"
          />
          <label className="block text-sm font-medium">Cantidad</label>
          <input
            data-testid="input-cantidad"
            type="number"
            placeholder="Cantidad"
            value={categoria.cantidad}
            onChange={e => setCategoria({ ...categoria, cantidad: Number(e.target.value) })}
            className="border p-2 w-full mb-2"
          />
          <label className="block text-sm font-medium">Medida</label>
          <select
            data-testid="select-medida"
            value={categoria.medida}
            onChange={e => setCategoria({ ...categoria, medida: e.target.value })}
            className="border p-2 w-full mb-2"
          >
            <option value="">Seleccione una medida</option>
            {unidades.map(m => (
              <option key={m.id} value={m.unidad}>
                {m.unidad}
            </option>
            ))}
          </select>
          <label className="block text-sm font-medium">Monto</label>
          <input
            data-testid="input-monto"
            type="number"
            placeholder="Monto ($)"
            value={categoria.monto}
            onChange={e => setCategoria({ ...categoria, monto: Number(e.target.value) })}
            className="border p-2 w-full mb-2"
          />
        </div>

        {/* Finalizar periodo */}
        <button
          data-testid="btn-agregar-actividad"
          onClick={guardarTodo}
          className="bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700"
        >
          Guardar todo
        </button>
      </div>
      )}
    </div>
      );
}
