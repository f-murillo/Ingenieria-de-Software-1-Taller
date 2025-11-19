import { useEffect, useState } from 'react';
import {
  obtenerActividades,
  obtenerProyectos,
  obtenerLabores,
  obtenerEquipos,
  obtenerUsuariosPorProyecto,
  crearActividad,
  eliminarActividad,
} from './api';
import type {
  ActividadPorProyecto,
  Proyecto,
  LaborAgronomica,
  EquipoImplemento,
  Usuario,
  ActividadInput,
} from './api';

interface Props {
  usuario: Usuario;
  mostrarToast: (texto: string) => void;
}

export default function VistaActividades({ usuario, mostrarToast }: Props) {
  const [actividades, setActividades] = useState<ActividadPorProyecto[]>([]);
  const [proyectos, setProyectos] = useState<Proyecto[]>([]);
  const [labores, setLabores] = useState<LaborAgronomica[]>([]);
  const [equipos, setEquipos] = useState<EquipoImplemento[]>([]);
  const [usuariosProyecto, setUsuariosProyecto] = useState<Usuario[]>([]);
  const [mostrarFormulario, setMostrarFormulario] = useState(false);

  const [form, setForm] = useState<ActividadInput>({
    proyecto_id: 0,
    actividad_id: 0,
    implemento_id: 0,
    usuario_id: 0,
    recurso_humano: '',
    observaciones: '',
    costo: 0,
  });

  useEffect(() => {
    cargarTodo();
  }, []);

  async function cargarTodo() {
    try {
      const [acts, proys, labs, eqs] = await Promise.all([
        obtenerActividades(),
        obtenerProyectos(),
        obtenerLabores(),
        obtenerEquipos(),
      ]);
      setActividades(acts);
      setProyectos(proys);
      setLabores(labs);
      setEquipos(eqs);
    } catch (error) {
      console.error('Error al cargar datos:', error);
      mostrarToast('Error al cargar datos');
    }
  }

  async function cargarUsuariosDelProyecto(id: number) {
    try {
      const usuarios = await obtenerUsuariosPorProyecto(id);
      setUsuariosProyecto(usuarios);
    } catch (error) {
      console.error('Error al cargar usuarios:', error);
      mostrarToast('Error al cargar usuarios del proyecto');
    }
  }

  async function manejarCrear() {
    try {
      const nueva = await crearActividad(form);
      mostrarToast('Actividad creada correctamente');
      await cargarTodo();
      setForm({
        proyecto_id: 0,
        actividad_id: 0,
        implemento_id: 0,
        usuario_id: 0,
        recurso_humano: '',
        observaciones: '',
        costo: 0,
      });
      setUsuariosProyecto([]);
      setMostrarFormulario(false);
    } catch (error) {
      console.error('Error al crear actividad:', error);
      mostrarToast('Error al crear actividad');
    }
  }

  async function manejarEliminar(id: number) {
    try {
      await eliminarActividad(id);
      mostrarToast('Actividad eliminada');
      setActividades(actividades.filter(a => a.id !== id));
    } catch (error) {
      console.error('Error al eliminar actividad:', error);
      mostrarToast('Error al eliminar actividad');
    }
  }

 const faltanDatos =
  !Array.isArray(proyectos) || proyectos.length === 0 ||
  !Array.isArray(labores) || labores.length === 0 ||
  !Array.isArray(equipos) || equipos.length === 0;


return (
  <section>
    <h2 className="text-xl font-semibold text-gray-800 mb-4">Actividades por proyecto</h2>

    <div className="space-y-4 mb-6">
      {faltanDatos ? (
        <div className="text-red-600 font-medium space-y-2">
          {!Array.isArray(proyectos) || proyectos.length === 0 && <p>No hay proyectos creados. Crea al menos uno para poder agregar actividades.</p>}
          {!Array.isArray(labores) || labores.length === 0 && <p>No hay labores registradas. Agrega alguna labor para continuar.</p>}
          {!Array.isArray(equipos) || equipos.length === 0 && <p>No hay equipos disponibles. Registra al menos un implemento.</p>}
        </div>
      ) : (
        <>
          {!mostrarFormulario ? (
            <button
              data-testid="boton-agregar-actividad"
              onClick={() => setMostrarFormulario(true)}
              className="bg-blue-600 text-white px-4 py-2 rounded hover:cursor-pointer"
            >
              Agregar actividad
            </button>
          ) : (
            <form
              onSubmit={e => {
                e.preventDefault();
                manejarCrear();
              }}
              className="space-y-4 bg-white p-4 rounded shadow"
            >
              <h3 className="text-lg font-semibold text-gray-800">Nueva Actividad</h3>

              <div>
                <label className="block text-sm font-medium text-gray-700">Proyecto</label>
                <select
                  data-testid="selec-project"
                  value={form.proyecto_id}
                  onChange={e => {
                    const id = parseInt(e.target.value);
                    setForm({ ...form, proyecto_id: id });
                    cargarUsuariosDelProyecto(id);
                  }}
                  required
                  className="w-full p-2 border rounded"
                >
                  <option value={0}>Seleccionar proyecto</option>
                  {proyectos.map(p => (
                    <option key={p.id} value={p.id}>{p.descripcion}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">Labor</label>
                <select
                  data-testid="selec-labor"
                  value={form.actividad_id}
                  onChange={e => setForm({ ...form, actividad_id: parseInt(e.target.value) })}
                  required
                  className="w-full p-2 border rounded"
                >
                  <option value={0}>Seleccionar labor</option>
                  {labores.map(l => (
                    <option key={l.id} value={l.id}>{l.titulo}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">Equipo</label>
                <select
                  data-testid="selec-equipo"
                  value={form.implemento_id}
                  onChange={e => setForm({ ...form, implemento_id: parseInt(e.target.value) })}
                  required
                  className="w-full p-2 border rounded"
                >
                  <option value={0}>Seleccionar equipo</option>
                  {equipos.map(e => (
                    <option key={e.id} value={e.id}>{e.titulo}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">Usuario asignado</label>
                <select
                  data-testid="selec-usuario"
                  value={form.usuario_id}
                  onChange={e => setForm({ ...form, usuario_id: parseInt(e.target.value) })}
                  required
                  className="w-full p-2 border rounded"
                  disabled={usuariosProyecto.length === 0}
                >
                  <option value={0}>Seleccionar usuario</option>
                  {usuariosProyecto.map(u => (
                    <option key={u.id} value={u.id}>{u.nombre} {u.apellido}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">Recurso humano</label>
                <input
                  data-testid="input-recurso-humano"
                  type="text"
                  value={form.recurso_humano}
                  onChange={e => setForm({ ...form, recurso_humano: e.target.value })}
                  required
                  className="w-full p-2 border rounded"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">Observaciones</label>
                <textarea
                  data-testid="textarea-observaciones"
                  value={form.observaciones}
                  onChange={e => setForm({ ...form, observaciones: e.target.value })}
                  className="w-full p-2 border rounded"
                  rows={3}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">Costo</label>
                <input
                  data-testid="number-numero"
                  type="number"
                  value={form.costo}
                  onChange={e => setForm({ ...form, costo: parseFloat(e.target.value) })}
                  className="w-full p-2 border rounded"
                  min={0}
                  step="0.01"
                />
              </div>

              <div className="flex gap-4">
                <button 
                  data-testid="btn-formulario-actividades"
                 type="submit" className="bg-blue-600 text-white px-4 py-2 rounded hover:cursor-pointer">
                  Crear actividad
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setMostrarFormulario(false);
                    setForm({
                      proyecto_id: 0,
                      actividad_id: 0,
                      implemento_id: 0,
                      usuario_id: 0,
                      recurso_humano: '',
                      observaciones: '',
                      costo: 0,
                    });
                    setUsuariosProyecto([]);
                  }}
                  className="bg-gray-400 text-white px-4 py-2 rounded hover:cursor-pointer"
                >
                  Cancelar
                </button>
              </div>
            </form>
          )}
        </>
      )}
    </div>

    {/* Tabla de actividades */}
    <table className="w-full border border-gray-300">
      <thead className="bg-gray-200">
        <tr>
          <th className="px-4 py-2">Proyecto</th>
          <th className="px-4 py-2">Labor Agronómica</th>
          <th className="px-4 py-2">Equipos e Implementos</th>
          <th className="px-4 py-2">Encargado/a</th>
          <th className="px-4 py-2">Recurso humano</th>
          <th className="px-4 py-2">Observaciones</th>
          <th className="px-4 py-2">Costo</th>
          <th className="px-4 py-2">Acciones</th>
        </tr>
      </thead>
      <tbody>
        {(actividades ?? []).map(act => (
          <tr key={act.id} className="border-t">
            <td className="px-4 py-2">{act.proyecto}</td>
            <td className="px-4 py-2">{act.actividad}</td>
            <td className="px-4 py-2">{act.implemento}</td>
            <td className="px-4 py-2">{act.usuario}</td>
            <td className="px-4 py-2">{act.recurso_humano}</td>
            <td className="px-4 py-2">{act.observaciones}</td>
            <td className="px-4 py-2">{act.costo} Bs</td>
            <td className="px-4 py-2">
              <button
                data-testid={`btn-eliminar-actividades-${act.id}`}
                onClick={() => manejarEliminar(act.id)}
                className="bg-[#7a99c7] text-white px-3 py-1 rounded hover:bg-[#6785ac]"
              >
                Eliminar
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  </section>
);

}
