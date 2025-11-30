import React, { useEffect, useState } from "react";
import type { LoggerEvento } from "./api";
import { obtenerEventos, eliminarEvento } from "./api";

export default function VistaEventos() {
  const [eventos, setEventos] = useState<LoggerEvento[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState(""); // nuevo estado para búsqueda
  const [mensaje, setMensaje] = useState<string | null>(null);
  const [mes, setMes] = useState("");            // ej: "11" para noviembre
  const [trimestre, setTrimestre] = useState(""); // ej: "1", "2", "3", "4"
  const [anio, setAnio] = useState("");          // ej: "2025"
  const [dia, setDia] = useState("");            // ej: "2025-11-29"
  const [fechaInicio, setFechaInicio] = useState("");
  const [fechaFin, setFechaFin] = useState("");


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
  const filteredEventos = eventos.filter(e => {
  const fecha = new Date(e.fecha); // asumiendo formato YYYY-MM-DD

  // Filtro por texto
  const coincideTexto =
    e.evento.toLowerCase().includes(searchTerm.toLowerCase()) ||
    e.modulo.toLowerCase().includes(searchTerm.toLowerCase());

  // Filtro por mes (input type="month" devuelve "YYYY-MM")
  const coincideMes = mes ? e.fecha.startsWith(mes) : true;

  // Filtro por trimestre
  let coincideTrimestre = true;
  if (trimestre) {
    const mesNum = fecha.getMonth() + 1;
    const trimestreNum = Math.ceil(mesNum / 3);
    coincideTrimestre = trimestreNum.toString() === trimestre;
  }

  // Filtro por año
  const coincideAnio = anio ? fecha.getFullYear().toString() === anio : true;

  // Filtro por día exacto
  const coincideDia = dia ? e.fecha === dia : true;

  // Filtro por rango de fechas
  const coincideRango =
    (fechaInicio ? fecha >= new Date(fechaInicio) : true) &&
    (fechaFin ? fecha <= new Date(fechaFin) : true);

  return (
    coincideTexto &&
    coincideMes &&
    coincideTrimestre &&
    coincideAnio &&
    coincideDia &&
    coincideRango
  );
});


  if (error) return <p>Error: {error}</p>;

  return (

    <div className="p-4">
      <h2 className="text-xl font-bold mb-4">Logger de Eventos</h2>

      {/* Buscador */}
      <div className="grid grid-cols-2 gap-4 mb-4">
      <input
        data-testid="input-buscar-eventos"
        type="text"
        value={searchTerm}
        onChange={e => setSearchTerm(e.target.value)}
        className="border px-2 py-1 rounded"
        placeholder="Buscar por evento o módulo"
      />

      <input
        
        type="month"
        value={mes}
        onChange={e => setMes(e.target.value)}
        className="border px-2 py-1 rounded"
        placeholder="Filtrar por mes"
      />

      <select
        value={trimestre}
        onChange={e => setTrimestre(e.target.value)}
        className="border px-2 py-1 rounded"
      >
        <option value="">Todos los trimestres</option>
        <option value="1">1er Trimestre (Ene-Mar)</option>
        <option value="2">2do Trimestre (Abr-Jun)</option>
        <option value="3">3er Trimestre (Jul-Sep)</option>
        <option value="4">4to Trimestre (Oct-Dic)</option>
      </select>

      <input
        type="number"
        value={anio}
        onChange={e => setAnio(e.target.value)}
        className="border px-2 py-1 rounded"
        placeholder="Filtrar por año"
      />

      <input
        type="date"
        value={dia}
        onChange={e => setDia(e.target.value)}
        className="border px-2 py-1 rounded"
        placeholder="Filtrar por día"
      />

      <input
        type="date"
        value={fechaInicio}
        onChange={e => setFechaInicio(e.target.value)}
        className="border px-2 py-1 rounded"
        placeholder="Fecha inicio"
      />

      <input
        type="date"
        value={fechaFin}
        onChange={e => setFechaFin(e.target.value)}
        className="border px-2 py-1 rounded"
        placeholder="Fecha fin"
      />
    </div>

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
