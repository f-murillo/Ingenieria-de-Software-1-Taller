import { useState, useEffect } from 'react';
import { obtenerActividades } from './api'; // función que consulta la tabla actividades_por_proyecto
import type { ActividadPorProyecto } from './api';

export default function VistaActividades() {
  const [actividades, setActividades] = useState<ActividadPorProyecto[]>([]);

  useEffect(() => {
    obtenerActividades().then(setActividades);
  }, []);

  useEffect(() => {
  obtenerActividades().then((data) => {
    console.log('Actividades recibidas:', data);
    setActividades(data);
  });
}, []);


  return (
    <section>
      <h2 className="text-xl font-semibold text-gray-800 mb-4">Actividades por proyecto</h2>
      <table className="w-full border border-gray-300">
        <thead className="bg-gray-200">
          <tr>
            <th className="px-4 py-2">Proyecto</th>
            <th className="px-4 py-2">Actividad</th>
            <th className="px-4 py-2">Implemento</th>
            <th className="px-4 py-2">Usuario</th>
            <th className="px-4 py-2">Recurso humano</th>
          </tr>
        </thead>
        <tbody>
          {actividades.map((act) => (
            <tr key={act.id} className="border-t">
              <td className="px-4 py-2">{act.proyecto}</td>
              <td className="px-4 py-2">{act.actividad}</td>
              <td className="px-4 py-2">{act.implemento}</td>
              <td className="px-4 py-2">{act.usuario}</td>
              <td className="px-4 py-2">{act.recurso_humano}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
