// AdminPanel.tsx

import { useEffect, useState } from 'react';
import { crearUsuario, obtenerUsuarios, type Usuario } from './api';
import { obtenerProyectosPorUsuario, type Proyecto } from './api';

interface Props {
  creador: string;
}

export default function AdminPanel({ creador }: Props) {
  const [usuarios, setUsuarios] = useState<Usuario[]>([]);
  const [nuevoUsuario, setNuevoUsuario] = useState({
    usuario: '',
    contraseña: '',
    nombre: '',
    apellido: '',
    rol: '',
    proyecto: '',
    administrador: false,
  });
  const [mensaje, setMensaje] = useState('');

  const [proyectosPorUsuario, setProyectosPorUsuario] = useState<Record<number, Proyecto[]>>({});


  useEffect(() => {
    obtenerUsuarios()
      .then(setUsuarios)
      .catch(() => setMensaje('Error al cargar usuarios'));
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await crearUsuario({ ...nuevoUsuario, creador });
      setMensaje('Usuario creado exitosamente');
      setNuevoUsuario({
        usuario: '',
        contraseña: '',
        nombre: '',
        apellido: '',
        rol: '',
        proyecto: '',
        administrador: false,
      });
      const actualizados = await obtenerUsuarios();
      setUsuarios(actualizados);
    } catch {
      setMensaje('Error al crear usuario');
    }
  };

    const cargarProyectos = async (usuarioId: number) => {
    try {
      const proyectos = await obtenerProyectosPorUsuario(usuarioId);
      setProyectosPorUsuario(prev => ({ ...prev, [usuarioId]: proyectos }));
    } catch (error) {
      console.error('Error al cargar proyectos del usuario:', error);
      setMensaje('Error al cargar proyectos del usuario');
    }
  };

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-gray-800">Gestión de usuarios</h2>

      {mensaje && <p className="text-green-600">{mensaje}</p>}

      <form onSubmit={handleSubmit} className="space-y-4 bg-white p-4 rounded shadow">
        <input
          type="text"
          placeholder="Usuario"
          value={nuevoUsuario.usuario}
          onChange={e => setNuevoUsuario({ ...nuevoUsuario, usuario: e.target.value })}
          className="border p-2 w-full"
          required
        />
        <input
          type="password"
          placeholder="Contraseña"
          value={nuevoUsuario.contraseña}
          onChange={e => setNuevoUsuario({ ...nuevoUsuario, contraseña: e.target.value })}
          className="border p-2 w-full"
          required
        />
        <input
          type="text"
          placeholder="Nombre"
          value={nuevoUsuario.nombre}
          onChange={e => setNuevoUsuario({ ...nuevoUsuario, nombre: e.target.value })}
          className="border p-2 w-full"
        />
        <input
          type="text"
          placeholder="Apellido"
          value={nuevoUsuario.apellido}
          onChange={e => setNuevoUsuario({ ...nuevoUsuario, apellido: e.target.value })}
          className="border p-2 w-full"
        />
        <input
          type="text"
          placeholder="Rol"
          value={nuevoUsuario.rol}
          onChange={e => setNuevoUsuario({ ...nuevoUsuario, rol: e.target.value })}
          className="border p-2 w-full"
        />
        <input
          type="text"
          placeholder="Proyecto"
          value={nuevoUsuario.proyecto}
          onChange={e => setNuevoUsuario({ ...nuevoUsuario, proyecto: e.target.value })}
          className="border p-2 w-full"
        />
        <label className="flex items-center space-x-2">
          <input
            type="checkbox"
            checked={nuevoUsuario.administrador}
            onChange={e => setNuevoUsuario({ ...nuevoUsuario, administrador: e.target.checked })}
          />
          <span>Administrador</span>
        </label>
        <button type="submit" className="bg-blue-600 text-white px-4 py-2 rounded">
          Crear usuario
        </button>
      </form>

      <div className="bg-white p-4 rounded shadow overflow-x-auto">
        <h3 className="text-lg font-semibold mb-2">Usuarios registrados</h3>
        <table className="w-full border-collapse">
          <thead>
            <tr className="bg-gray-200 text-left">
              <th className="p-2 border">ID</th>
              <th className="p-2 border">Usuario</th>
              <th className="p-2 border">Nombre</th>
              <th className="p-2 border">Apellido</th>
              <th className="p-2 border">Rol</th>
              <th className="p-2 border">Proyectos</th>
              <th className="p-2 border">Administrador</th>
            </tr>
          </thead>
          <tbody>
            {usuarios.map(u => (
              <tr key={u.usuario} className="border-t">
                <td className="p-2 border">{u.id}</td>
                <td className="p-2 border">{u.usuario}</td>
                <td className="p-2 border">{u.nombre}</td>
                <td className="p-2 border">{u.apellido}</td>
                <td className="p-2 border">{u.rol}</td>
                <td className="p-2 border">
                  <button
                    onClick={() => cargarProyectos(u.id)}
                    className="text-blue-600 underline"
                  >
                    Ver proyectos
                  </button>

                  {/* Espacio reservado para mostrar proyectos más adelante */}
                  <div className="mt-2 text-sm text-gray-700 italic">
                    <div className="mt-2 text-sm text-gray-700">
                      {proyectosPorUsuario[u.id] ? (
                        proyectosPorUsuario[u.id].length === 0 ? (
                          <p className="italic text-gray-500">No tiene proyectos asignados.</p>
                        ) : (
                          <ul className="list-disc pl-4">
                            {proyectosPorUsuario[u.id].map(p => (
                              <li key={p.id}>
                                {p.descripcion} ({p.fecha_inicio} → {p.fecha_cierre})
                              </li>
                            ))}
                          </ul>
                        )
                      ) : (
                        <p className="italic text-gray-500">(Aquí se mostrarán los proyectos del usuario)</p>
                      )}
                    </div>
                  </div>
                </td>
                <td className="p-2 border">{u.administrador ? 'Sí' : 'No'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
