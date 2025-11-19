import React, { useEffect, useState } from "react";
import type { LoggerEvento } from "./api";
import { obtenerEventos, eliminarEvento } from "./api";

export default function VistaEventos() {
  const [eventos, setEventos] = useState<LoggerEvento[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState(""); // nuevo estado para búsqueda
  const [mensaje, setMensaje] = useState<string | null>(null);


  useEffect(() => {
    obtenerEventos()
      .then(data => setEventos(Array.isArray(data) ? data : []))
      .catch(err => setError(err.message));
  }, []);

  const handleEliminar = async (id: number) => {
    try {
      await eliminarEvento(id);
      setEventos(eventos.filter(e => e.id !== id));
      setMensaje("Evento eliminado correctamente"); 
    } catch {
      setMensaje("Error al eliminar evento"); 
    }
  };


  // Filtrado por evento o módulo
  const filteredEventos = eventos.filter(e =>
    e.evento.toLowerCase().includes(searchTerm.toLowerCase()) ||
    e.modulo.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (error) return <p>Error: {error}</p>;

  return (

    <div className="p-4">
      <h2 className="text-xl font-bold mb-4">Logger de Eventos</h2>

      {/* Buscador */}
      <input
        data-testid="input-buscar-eventos"
        type="text"
        placeholder="Buscar por evento o módulo..."
        value={searchTerm}
        onChange={e => setSearchTerm(e.target.value)}
        className="border px-3 py-2 mb-4 w-full rounded"
      />
      {mensaje && (
        <div className="mb-4 p-2 rounded bg-blue-100 text-blue-800">
          {mensaje}
        </div>
    )}

      <table className="border-collapse border w-full">
        <thead>
          <tr>
            <th className="border p-2">ID</th>
            <th className="border p-2">Evento</th>
            <th className="border p-2">Módulo</th>
            <th className="border p-2">Fecha</th>
            <th className="border p-2">Hora</th>
            <th className="border p-2">Acciones</th>
          </tr>
        </thead>
        <tbody>
          {filteredEventos.length === 0 ? (
            <tr>
              <td colSpan={6} className="text-center p-4 text-gray-500">
                No hay eventos que coincidan
              </td>
            </tr>
          ) : (
            filteredEventos.map(e => (
              <tr key={e.id}>
                <td className="border p-2">{e.id}</td>
                <td className="border p-2">{e.evento}</td>
                <td className="border p-2">{e.modulo}</td>
                <td className="border p-2">{e.fecha}</td>
                <td className="border p-2">{e.hora}</td>
                <td className="border p-2 text-center">
                  <button
                    data-testid={`btn-eliminar-evento-${e.id}`}
                    onClick={() => handleEliminar(e.id)}
                    className="px-2 py-1 bg-[#7a99c7] text-white rounded hover:bg-[#6785ac]"
                  >
                    Eliminar
                  </button>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
