import { useState } from "react";
import FormularioActividades from "./Actividades_periodo"; // CRUD de actividades_periodo
import VistaRecursosHumanos from "./VistaRecursosHumanos"; // CRUD de actividades_cantidad
import VistaInsumos from "./VistaInsumos"; // CRUD de actividades_categoria

export default function VistaPlanAccion() {
  // por defecto se muestra la subpestaña de actividades
  const [subvista, setSubvista] = useState("actividades");

  return (
    <div>
      <h2 className="text-2xl font-bold mb-4">Plan de Acción</h2>

      {/* Barra de subpestañas */}
      <div className="flex space-x-4 border-b mb-6">
        <button
          className={`pb-2 ${subvista === "actividades" ? "border-b-2 border-blue-500 font-semibold" : ""} hover:cursor-pointer`}
          onClick={() => setSubvista("actividades")}
        >
          Actividades
        </button>
        <button
          className={`pb-2 ${subvista === "recursos" ? "border-b-2 border-blue-500 font-semibold" : ""} hover:cursor-pointer`}
          onClick={() => setSubvista("recursos")}
        >
          Recursos Humanos
        </button>
        <button
          className={`pb-2 ${subvista === "insumos" ? "border-b-2 border-blue-500 font-semibold" : ""} hover:cursor-pointer`}
          onClick={() => setSubvista("insumos")}
        >
          Insumos y Materiales
        </button>
      </div>

      {/* Contenido según la subpestaña seleccionada */}
      {subvista === "actividades" && <FormularioActividades />}
      {subvista === "recursos" && <VistaRecursosHumanos />}
      {subvista === "insumos" && <VistaInsumos />}
    </div>
  );
}
