import { useEffect, useState } from 'react';
import {
  obtenerProyectos,
  obtenerProyectosPorUsuario,
  obtenerUsuariosPorProyecto,
  obtenerUsuarios,
  crearProyecto,
  asociarUsuariosAProyecto,
  type Proyecto,
  type ProyectoSinID,
  type Usuario,
} from './api';

interface Props {
  usuario: Usuario;
  mostrarToast: (mensaje: string) => void;
}

export default function ProjectPanel({ usuario, mostrarToast }: Props) {
  const [proyectos, setProyectos] = useState<Proyecto[]>([]);
  const [usuariosPorProyecto, setUsuariosPorProyecto] = useState<Record<number, Usuario[]>>({});
  const [usuariosDisponibles, setUsuariosDisponibles] = useState<Usuario[]>([]);
  const [usuariosSeleccionados, setUsuariosSeleccionados] = useState<number[]>([]);
  const [proyectoActivo, setProyectoActivo] = useState<number | null>(null);
  const [mensajeError, setMensajeError] = useState('');
  const [cargando, setCargando] = useState(true);

  useEffect(() => {
    cargarProyectos();
  }, [usuario]);

  const cargarProyectos = async () => {
    try {
      setCargando(true);
      let datos: Proyecto[] = [];

      if (usuario.administrador) {
        datos = await obtenerProyectos();
      } else if (usuario.id !== undefined) {
        datos = await obtenerProyectosPorUsuario(usuario.id);
      }

      setProyectos(Array.isArray(datos) ? datos : []);
    } catch (error) {
      console.error('Error al cargar proyectos:', error);
      setMensajeError('Error al cargar proyectos');
      setProyectos([]);
    } finally {
      setCargando(false);
    }
  };

  const cargarUsuarios = async (proyectoId: number) => {
    try {
      const usuarios = await obtenerUsuariosPorProyecto(proyectoId);
      setUsuariosPorProyecto(prev => ({ ...prev, [proyectoId]: usuarios }));
    } catch (error) {
      console.error('Error al cargar usuarios del proyecto:', error);
      setMensajeError('Error al cargar usuarios del proyecto');
    }
  };

  const cargarUsuariosDisponibles = async () => {
    try {
      const todos = await obtenerUsuarios();
      setUsuariosDisponibles(todos);
    } catch (error) {
      console.error('Error al cargar usuarios disponibles:', error);
      setMensajeError('Error al cargar usuarios disponibles');
    }
  };

  const handleCrearProyecto = async (nuevo: ProyectoSinID) => {
    try {
      const creado = await crearProyecto(nuevo);
      setProyectos(prev => [...prev, creado]);
      mostrarToast('Proyecto creado exitosamente');
    } catch (error) {
      console.error('Error al crear proyecto:', error);
      setMensajeError('Error al crear proyecto');
    }
  };

  const handleAsociarUsuarios = async (e: React.FormEvent) => {
    e.preventDefault();
    if (proyectoActivo === null) return;

    try {
      await asociarUsuariosAProyecto(proyectoActivo, usuariosSeleccionados);
      mostrarToast('Usuarios asociados correctamente');
      setProyectoActivo(null);
      setUsuariosSeleccionados([]);
      cargarUsuarios(proyectoActivo);
    } catch (error) {
      console.error('Error al asociar usuarios:', error);
      setMensajeError('Error al asociar usuarios');
    }
  };

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-gray-800">
        {usuario.administrador ? 'Gestionar Proyectos' : 'Ver Proyectos'}
      </h2>

      {mensajeError && <p className="text-red-600">{mensajeError}</p>}

      {usuario.administrador && (
        <FormularioProyecto onCrear={handleCrearProyecto} />
      )}

      <div className="bg-white p-4 rounded shadow overflow-x-auto">
        {!Array.isArray(proyectos) ? (
          <p className="text-red-600">Error: los datos de proyectos no son válidos.</p>
        ) : cargando ? (
          <p className="text-gray-500 italic">Cargando proyectos...</p>
        ) : proyectos.length === 0 ? (
          <p className="text-gray-600 italic">No hay proyectos registrados aún.</p>
        ) : (
          <table className="w-full border-collapse">
            <thead>
              <tr className="bg-gray-200 text-left">
                <th className="p-2 border">ID</th>
                <th className="p-2 border">Descripción</th>
                <th className="p-2 border">Inicio</th>
                <th className="p-2 border">Cierre</th>
                {usuario.administrador && <th className="p-2 border">Usuarios</th>}
                <th className="p-2 border"></th>
                <th className="p-2 border"></th>
                <th className="p-2 border"></th>
                <th className="p-2 border"></th>
                <th className="p-2 border"></th>

              </tr>
            </thead>
            <tbody>
              {proyectos.map(p => (
                <tr key={p.id} className="border-t">
                  <td className="p-2 border">{p.id}</td>
                  <td className="p-2 border">{p.descripcion}</td>
                  <td className="p-2 border">{formatearFecha(p.fecha_inicio)}</td>
                  <td className="p-2 border">{formatearFecha(p.fecha_cierre)}</td>

                  {usuario.administrador && (
                    <td className="p-2 border">
                      <button
                        onClick={() => cargarUsuarios(p.id)}
                        className="text-blue-600 underline"
                      >
                        Ver usuarios
                      </button>
                      <button
                        onClick={() => {
                          setProyectoActivo(p.id);
                          cargarUsuariosDisponibles();
                        }}
                        className="text-green-600 underline ml-2"
                      >
                        Asignar usuarios
                      </button>
                      {usuariosPorProyecto[p.id] && (
                        <div className="mt-2 text-sm text-gray-700">
                          {usuariosPorProyecto[p.id].length === 0 ? (
                            <p className="italic text-gray-500">
                              No hay usuarios asociados a este proyecto.
                            </p>
                          ) : (
                            <ul>
                              {usuariosPorProyecto[p.id].map(u => (
                                <li key={u.id}>
                                  {u.nombre} {u.apellido} ({u.usuario})
                                </li>
                              ))}
                            </ul>
                          )}
                        </div>
                      )}
                    </td>
                  )}
                  <td className="p-2 border">
                    <button className="text-blue-600 hover:text-blue-800">📄</button>
                  </td>
                  <td className="p-2 border">
                    <button className="text-yellow-600 hover:text-yellow-800">✏️</button>
                  </td>
                  <td className="p-2 border">
                    <button className="text-red-600 hover:text-red-800">🚫</button>
                  </td>
                  <td className="p-2 border">
                    <button className="text-green-600 hover:text-green-800">✔️</button>
                  </td>
                  <td className="p-2 border">
                    <button className="text-gray-600 hover:text-gray-800">🖨️</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {proyectoActivo !== null && (
        <form
          onSubmit={handleAsociarUsuarios}
          className="bg-white p-4 rounded shadow space-y-4 mt-4"
        >
          <h3 className="text-lg font-semibold text-gray-800">
            Asignar usuarios al proyecto {proyectoActivo}
          </h3>

          <select
            multiple
            value={usuariosSeleccionados.map(String)}
            onChange={e =>
              setUsuariosSeleccionados(
                Array.from(e.target.selectedOptions, opt => parseInt(opt.value))
              )
            }
            className="w-full p-2 border rounded h-40"
          >
            {usuariosDisponibles.map(u => (
              <option key={u.id} value={u.id}>
                {u.nombre} {u.apellido} ({u.usuario})
              </option>
            ))}
          </select>

          <div className="flex gap-4">
            <button type="submit" className="bg-green-600 text-white px-4 py-2 rounded">
              Guardar
            </button>
            <button
              type="button"
              onClick={() => {
                setProyectoActivo(null);
                setUsuariosSeleccionados([]);
              }}
              className="bg-gray-400 text-white px-4 py-2 rounded"
            >
              Cancelar
            </button>
          </div>
        </form>
      )}
    </div>
  );
}

function formatearFecha(fecha: string): string {
  if (!fecha || !fecha.includes('-')) return '—';
  const [año, mes, día] = fecha.split('-');
  return `${día}/${mes}/${año}`;
}

function FormularioProyecto({ onCrear }: { onCrear: (p: ProyectoSinID) => void }) {
  const [descripcion, setDescripcion] = useState('');
  const [inicio, setInicio] = useState('');
  const [cierre, setCierre] = useState('');
  const [mostrarFormulario, setMostrarFormulario] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!descripcion || !inicio) return;
    onCrear({ descripcion, fecha_inicio: inicio, fecha_cierre: cierre });
    setDescripcion('');
    setInicio('');
    setCierre('');
    setMostrarFormulario(false);
  };

  const handleCancelar = () => {
    setDescripcion('');
    setInicio('');
    setCierre('');
    setMostrarFormulario(false);
  };

  return (
    <div className="space-y-4">
      {!mostrarFormulario ? (
        <button
          onClick={() => setMostrarFormulario(true)}
          className="bg-blue-600 text-white px-4 py-2 rounded"
        >
          Agregar proyecto
        </button>
      ) : (
        <form onSubmit={handleSubmit} className="space-y-4 bg-white p-4 rounded shadow">
          <h3 className="text-lg font-semibold text-gray-800">Nuevo Proyecto</h3>

          <div>
            <label className="block text-sm font-medium text-gray-700">
              Descripción del proyecto
            </label>
            <input
              type="text"
              placeholder="Descripción"
              value={descripcion}
              onChange={e => setDescripcion(e.target.value)}
              required
              className="w-full p-2 border rounded"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">
              Fecha de inicio del proyecto
            </label>
            <input
              type="date"
              value={inicio}
              onChange={e => setInicio(e.target.value)}
              required
              className="w-full p-2 border rounded"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">
              Fecha de cierre del proyecto
            </label>
            <input
              type="date"
              value={cierre}
              onChange={e => setCierre(e.target.value)}
              className="w-full p-2 border rounded"
            />
          </div>

          <div className="flex gap-4">
            <button type="submit" className="bg-blue-600 text-white px-4 py-2 rounded">
              Crear proyecto
            </button>
            <button
              type="button"
              onClick={handleCancelar}
              className="bg-gray-400 text-white px-4 py-2 rounded"
            >
              Cancelar
            </button>
          </div>
        </form>
      )}
    </div>
  );
}

