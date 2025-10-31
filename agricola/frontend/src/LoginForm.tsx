// LoginForm.tsx

import { useState } from 'react';
import { login } from './api';
import type {Usuario} from './api';

interface Props {
  onLoginSuccess: (usuario: Usuario) => void;
}

export default function LoginForm({ onLoginSuccess }: Props) {
  const [usuario, setUsuario] = useState('');
  const [contraseña, setContraseña] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await login(usuario, contraseña);
      if (response && response.id) {
        setMessage(`Bienvenido, ${response.nombre || usuario}`);
        setError(false);
        onLoginSuccess(response);
      } else {
        setMessage('Usuario y/o contraseña inválidos');
        setError(true);
      }
    } catch (err) {
      setMessage('Error al iniciar sesión');
      setError(true);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <form
        onSubmit={handleSubmit}
        className="bg-white p-8 rounded shadow-md w-full max-w-sm space-y-4"
      >
        <h2 className="text-2xl font-semibold text-center text-gray-800">Iniciar sesión</h2>

        <input
          data-testid="input-usuario"
          value={usuario}
          onChange={e => setUsuario(e.target.value)}
          placeholder="Usuario"
          required
          className={`w-full px-4 py-2 border rounded focus:outline-none focus:ring-2 ${
            error ? 'border-red-500 focus:ring-red-500' : 'border-gray-300 focus:ring-blue-500'
          }`}
        />

        <input
          data-testid="input-contraseña"
          type="password"
          value={contraseña}
          onChange={e => setContraseña(e.target.value)}
          placeholder="Contraseña"
          required
          className={`w-full px-4 py-2 border rounded focus:outline-none focus:ring-2 ${
            error ? 'border-red-500 focus:ring-red-500' : 'border-gray-300 focus:ring-blue-500'
          }`}
        />

        <button
          data-testid="button-submit"
          type="submit"
          className="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700 hover:cursor-pointer transition"
        >
          Entrar
        </button>

        {message && (
          <p className={`text-center text-sm ${error ? 'text-red-600' : 'text-gray-700'}`}>
            {message}
          </p>
        )}
      </form>
    </div>
  );
}
