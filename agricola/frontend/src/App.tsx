// App.tsx

import { useState, useEffect } from 'react';
import LoginForm from './LoginForm';
import AdminPanel from './AdminPanel';
import Panel from './Panel';
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

    // Oculta el mensaje automáticamente después de 3 segundos
    setTimeout(() => {
      setMostrarMensaje(false);
    }, 3000);
  };

  // Limpia el mensaje al iniciar sesión
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

    if (vista === 'proyectos') {
      return <p>Gestión de proyectos (pendiente)</p>;
    }

    if (vista === 'ver-proyectos') {
      return <p>Visualización de proyectos (pendiente)</p>;
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
        <div className="min-h-screen flex bg-gray-100">
          <Panel
            administrador={!!usuarioAutenticado?.administrador}
            onSeleccion={setVista}
            onLogout={handleLogout}
          />
          <main className="flex-1 p-8">{renderContenido()}</main>
        </div>
      )}
    </>
  );
}

export default App;
