interface Props {
  administrador: boolean;
  onSeleccion: (vista: string) => void;
  onLogout: () => void;
  mensaje?: string;
}

export default function Panel({ administrador, onSeleccion, onLogout, mensaje }: Props) {
  return (
    <aside className="w-64 bg-gray-800 text-white p-6 space-y-4 flex-shrink-0">
      <h3 className="text-lg font-semibold">Menú</h3>

      <button
        onClick={() => onSeleccion('bienvenida')}
        className="block w-full text-left hover:underline hover:cursor-pointer"
      >
        Inicio
      </button>

      {administrador ? (
        <>
          <button
            data-testid="btn-usuarios"
            onClick={() => onSeleccion('usuarios')}
            className="block w-full text-left hover:underline hover:cursor-pointer"
          >
            Gestionar usuarios
          </button>
          <button
            data-testid="btn-proyectos"
            onClick={() => onSeleccion('proyectos')}
            className="block w-full text-left hover:underline hover:cursor-pointer"
          >
            Gestionar proyectos
          </button>
          <button
            data-testid="btn-actividades"
            onClick={() => onSeleccion('actividades')}
            className="block w-full text-left hover:underline hover:cursor-pointer"
          >
            Gestionar actividades
          </button>
          <button
            data-testid="btn-labores"
            onClick={() => onSeleccion('labores')}
            className="block w-full text-left hover:underline hover:cursor-pointer"
          >
            Gestionar labores
          </button>
          <button
            data-testid="btn-equipos"
            onClick={() => onSeleccion('equipos')}
            className="block w-full text-left hover:underline hover:cursor-pointer"
          >
            Gestionar equipos
          </button>
          <button
            data-testid="btn-eventos"
            onClick={() => onSeleccion('eventos')}
            className="block w-full text-left hover:underline hover:cursor-pointer"
          >
            Logger de eventos
          </button>
          <button
            data-testid="btn-unidades"
            onClick={() => onSeleccion('unidades')}
            className="block w-full text-left hover:underline hover:cursor-pointer">
            Gestionar unidades
          </button>

        </>
      ) : (
        <button
          onClick={() => onSeleccion('ver-proyectos')}
          className="block w-full text-left hover:underline hover:cursor-pointer"
        >
          Ver proyectos
        </button>
      )}

      <button
        onClick={onLogout}
        className="block w-full text-left text-red-300 hover:text-red-500 hover:cursor-pointer"
      >
        Cerrar sesión
      </button>

      {mensaje && <p className="text-sm mt-4 text-green-300">{mensaje}</p>}
    </aside>
  );
}
