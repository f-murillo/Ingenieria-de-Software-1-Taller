import { useState, useEffect } from 'react';
import LoginForm from './LoginForm';
import AdminPanel from './AdminPanel';
import Panel from './Panel';
import ProjectPanel from './ProjectPanel';
import VistaActividades from './VistaActividades';
import VistaLabores from './VistaLabores';
import VistaEquipos from './VistaEquipos';
import VistaEventos from './Eventos';
import VistaUnidades from './VistaUnidades';
import VistaPlanAccion from "./VistaPlanAccion"; // 👈 nuevo contenedor con subpestañas
import type { Usuario } from './api';

function App() {
  const [usuarioAutenticado, setUsuarioAutenticado] = useState<Usuario | null>(null);
  const [vista, setVista] = useState<string>('bienvenida');
  const [mensaje, setMensaje] = useState('');
  const [mostrarMensaje, setMostrarMensaje] = useState(false);

  const handleLogout = () => {
    setMensaje('Sesión cerrada exitosamente');
    setMostrarMensaje(true);
    setUsuarioAutenticado(null);
    setVista('bienvenida');

    setTimeout(() => {
      setMostrarMensaje(false);
    }, 3000);
  };

  const mostrarToast = (texto: string) => {
    setMensaje(texto);
    setMostrarMensaje(true);
    setTimeout(() => setMostrarMensaje(false), 3000);
  };

  useEffect(() => {
    if (usuarioAutenticado) {
      setMensaje('');
      setMostrarMensaje(false);
    }
  }, [usuarioAutenticado]);

  const renderContenido = () => {
    if (vista === 'bienvenida') {
      return (
        <h2 className="text-xl font-semibold text-gray-800">
          Bienvenido, {usuarioAutenticado?.nombre || usuarioAutenticado?.usuario}
        </h2>
      );
    }

    if (vista === 'usuarios' && usuarioAutenticado?.administrador) {
      return <AdminPanel creador={usuarioAutenticado.usuario} />;
    }

    if (vista === 'proyectos' && usuarioAutenticado?.administrador) {
      return <ProjectPanel usuario={usuarioAutenticado} mostrarToast={mostrarToast} />;
    }

    if (vista === 'ver-proyectos' && !usuarioAutenticado?.administrador && usuarioAutenticado !== null) {
      return <ProjectPanel usuario={usuarioAutenticado} mostrarToast={mostrarToast} />;
    }

    if (vista === 'actividades' && usuarioAutenticado?.administrador) {
      return <VistaActividades usuario={usuarioAutenticado} mostrarToast={mostrarToast} />;
    }

    if (vista === 'labores' && usuarioAutenticado?.administrador) {
      return <VistaLabores mostrarToast={mostrarToast} />;
    }

    if (vista === 'equipos' && usuarioAutenticado?.administrador) {
      return <VistaEquipos mostrarToast={mostrarToast} />;
    }
    
    if (vista === 'eventos' && usuarioAutenticado?.administrador) {
      return <VistaEventos />;
    }

    if (vista === 'unidades' && usuarioAutenticado?.administrador) {
      return <VistaUnidades mostrarToast={mostrarToast}/>;
    }

    // 👇 aquí el cambio: en vez de FormularioActividades, usamos VistaPlanAccion
    if (vista === 'formulario-actividades' && usuarioAutenticado?.administrador) {
      return <VistaPlanAccion />;
    }

    return <p>Vista no disponible</p>;
  };

  return (
    <>
      {!usuarioAutenticado ? (
        <div className="min-h-screen flex flex-col items-center justify-center bg-gray-100 relative">
          <LoginForm onLoginSuccess={setUsuarioAutenticado} />
          {mostrarMensaje && (
            <div className="absolute bottom-6 bg-green-600 text-white px-4 py-2 rounded shadow-md animate-fade-in">
              {mensaje}
            </div>
          )}
        </div>
      ) : (
        <div className="min-h-screen flex bg-gray-100 relative">
          <Panel
            administrador={!!usuarioAutenticado?.administrador}
            onSeleccion={setVista}
            onLogout={handleLogout}
          />
          <main className="flex-1 p-8">
            {(() => {
              try {
                return renderContenido();
              } catch (error) {
                console.error('Error en renderContenido:', error);
                return <p className="text-red-600">Ocurrió un error inesperado al cargar la vista.</p>;
              }
            })()}
          </main>
          {mostrarMensaje && (
            <div className="absolute bottom-6 left-1/2 transform -translate-x-1/2 bg-green-600 text-white px-4 py-2 rounded shadow-md animate-fade-in">
              {mensaje}
            </div>
          )}
        </div>
      )}
    </>
  );
}

export default App;
