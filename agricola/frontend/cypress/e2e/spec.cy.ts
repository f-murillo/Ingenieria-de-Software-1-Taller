describe('Test de login', () => {

  it('Verifica que los elementos esten en pantalla', () => {
    cy.visit('http://localhost:5173/')
    cy.get('form').should('be.visible')
    cy.get('[data-testid="input-usuario"]').should('be.visible')
    cy.get('[data-testid="input-contraseña"]').should('be.visible')
    cy.get('[data-testid="button-submit"]').should('be.visible')
  })

  it('Realiza un login exitoso', () => {
    cy.visit('http://localhost:5173/')
    cy.get('[data-testid="input-usuario"]').type('akoto')
    cy.get('[data-testid="input-contraseña"]').type('pass123')
    cy.get('[data-testid="button-submit"]').click()
    cy.contains('Bienvenido,').should('be.visible')
  })

    it('Realiza un login de usuario', () => {
    cy.visit('http://localhost:5173/')
    cy.get('[data-testid="input-usuario"]').type('lrojas')
    cy.get('[data-testid="input-contraseña"]').type('pass456')
    cy.get('[data-testid="button-submit"]').click()
    cy.contains('Bienvenido,').should('be.visible')
  })

  it('Realiza un login fallido', () => {
    cy.visit('http://localhost:5173/')
    cy.get('[data-testid="input-usuario"]').type('usuario_incorrecto')
    cy.get('[data-testid="input-contraseña"]').type('contraseña_incorrecta')
    cy.get('[data-testid="button-submit"]').click()
    cy.contains('Error').should('be.visible')
  })
})

describe('Usuarios', () => {
  it('Agrega un nuevo usuario', () => {
    cy.visit('http://localhost:5173/')
    cy.get('[data-testid="input-usuario"]').type('akoto')
    cy.get('[data-testid="input-contraseña"]').type('pass123')
    cy.get('[data-testid="button-submit"]').click()
    cy.get('[data-testid="btn-usuarios"]').click()
    // Rellenar el formulario de nuevo usuario
    cy.get('[data-testid=boton-agregar-usuario]').click()
    cy.get('[data-testid="input-nuevo-usuario"]').type('nuevo_usuario')
    cy.get('[data-testid="input-nueva-contrasena"]').type('nueva_contraseña')
    cy.get('[data-testid="input-nuevo-nombre"]').type('Nuevo')
    cy.get('[data-testid="input-nuevo-apellido"]').type('Usuario')
    cy.get('[data-testid="input-nuevo-rol"]').type('Tester')
    cy.get('[data-testid="input-nuevo-administrador"]').check()
    // Enviar el formulario
    cy.get('form').submit()
    // Verificar que el usuario fue agregado (esto depende de la implementación, ajustar según sea necesario)
    cy.contains('Usuario creado exitosamente').should('be.visible')
  })


  it('Botones Funcionales', () => {
    cy.visit('http://localhost:5173/')
    cy.get('[data-testid="input-usuario"]').type('akoto')
    cy.get('[data-testid="input-contraseña"]').type('pass123')
    cy.get('[data-testid="button-submit"]').click()
    cy.get('[data-testid="btn-usuarios"]').click()
    cy.get('[data-testid="btn-editar-rol-1"]').click()
    cy.get('[data-testid="input-nuevo-rol-1"]').clear().type('Operador')
    cy.get('[data-testid="btn-confirmar-rol-1"]').click()
    cy.contains('Operador').should('be.visible')
    cy.get('[data-testid="btn-ver-proyectos-1"]').click()

  })

})

describe('Proyectos', () => {
  it('Agrega un nuevo proyecto', () => {
    cy.visit('http://localhost:5173/')
    cy.get('[data-testid="input-usuario"]').type('akoto')
    cy.get('[data-testid="input-contraseña"]').type('pass123')
    cy.get('[data-testid="button-submit"]').click()
    cy.get('[data-testid="btn-proyectos"]').click()
    // Hacer clic en el botón para agregar un nuevo proyecto
    cy.get('[data-testid="boton-agregar-proyecto"]').click()
    // Rellenar el formulario de nuevo proyecto
    cy.get('[data-testid="input-nueva-descripcion"]').type('Descripción del proyecto de prueba')
    cy.get('[data-testid="input-nueva-fecha-inicio"]').type('2024-07-01')
    cy.get('[data-testid="input-nueva-fecha-cierre"]').type('2024-12-31')
    // Enviar el formulario
    cy.get('form').submit()
    // Verificar que el proyecto fue agregado (esto depende de la implementación, ajustar según sea necesario)
    cy.contains('Descripción del proyecto de prueba').should('be.visible')
  })
  it('Botones funcionales', () => {
    cy.visit('http://localhost:5173/')
    cy.get('[data-testid="input-usuario"]').type('akoto')
    cy.get('[data-testid="input-contraseña"]').type('pass123')
    cy.get('[data-testid="button-submit"]').click()
    cy.get('[data-testid="btn-proyectos"]').click()
    cy.get('[data-testid="btn-ver-usuarios-1"]').click()
    cy.get('[data-testid="btn-asignar-usuarios-1"]').click()
    cy.get('[data-testid="select-usuarios-disponibles"]').select(['3'])
    cy.get('button[type="submit"]').click()
    cy.contains('Usuarios asociados correctamente').should('be.visible')
    cy.get('[data-testid="btn-detalles-proyecto-1"]').click()
    cy.get('[data-testid="btn-eliminar-proyecto-1"]').click()
    cy.get('[data-testid="btn-activar-proyecto-1"]').click()
    cy.get('[data-testid="btn-imprimir-proyecto-1"]').click()
    cy.get('[data-testid="btn-editar-1"]').click()
    cy.get('[data-testid="input-descripcion-1"]').clear().type('Nuevo nombre del proyecto')
    // Editar fecha de inicio
    cy.get('[data-testid="input-fecha-inicio-1"]').clear().type('2024-07-01')
    // Editar fecha de cierre
    cy.get('[data-testid="input-fecha-cierre-1"]').clear().type('2024-08-01')
    cy.get('[data-testid="btn-confirmar-1"]').click()
    cy.contains('Nuevo nombre del proyecto').should('be.visible')

  })
})

describe('Actividades', () => {
  it('Agrega una nueva actividad', () => {
    cy.visit('http://localhost:5173/')
    cy.get('[data-testid="input-usuario"]').type('akoto')
    cy.get('[data-testid="input-contraseña"]').type('pass123')
    cy.get('[data-testid="button-submit"]').click()
    cy.get('[data-testid="btn-actividades"]').click()
    cy.get('[data-testid="boton-agregar-actividad"]').click()
    cy.get('[data-testid="selec-project"]').select('Nuevo nombre del proyecto')
    cy.get('[data-testid="selec-labor"]').select('Siembra directa')
    cy.get('[data-testid="selec-equipo"]').select('Pulverizador de mochila')
    cy.get('[data-testid="selec-usuario"]').select('María Vera')
    cy.get('[data-testid="input-recurso-humano"]').type('5')
    cy.get('[data-testid="textarea-observaciones"]').type('Siembra en el Este')
    cy.get('[data-testid="number-numero"]').clear().type('200')
    cy.get('[data-testid="btn-formulario-actividades"]').click()
    cy.contains('Actividad creada correctamente').should('be.visible')
    cy.get('[data-testid="btn-eliminar-actividades-1"]').click()
    cy.contains('Actividad eliminada').should('be.visible')
  })
  

})

describe('Labores', () => {
  it('Labores', () => {
    cy.visit('http://localhost:5173/')
    cy.get('[data-testid="input-usuario"]').type('akoto')
    cy.get('[data-testid="input-contraseña"]').type('pass123')
    cy.get('[data-testid="button-submit"]').click()
    cy.get('[data-testid="btn-labores"]').click()
    cy.get('[data-testid="input-labores"]').type('Labor de prueba')
    cy.get('[data-testid="btn-agregar-labores"]').click()
  })
  
  it('Botones', () => {
    cy.visit('http://localhost:5173/')
    cy.get('[data-testid="input-usuario"]').type('akoto')
    cy.get('[data-testid="input-contraseña"]').type('pass123')
    cy.get('[data-testid="button-submit"]').click()
    cy.get('[data-testid="btn-labores"]').click()
    cy.get('[data-testid="btn-editar-labores-1"]').click()
    cy.get('[data-testid="input-titulo-labores-1"]').clear().type('Nombre de prueba')
    cy.get('[data-testid="guardar-labores-1"]').click()
    cy.get('[data-testid="btn-editar-labores-1"]').click()
    cy.get('[data-testid="input-titulo-labores-1"]').clear().type('Nombre de prueba')
    cy.get('[data-testid="cancelar-labores-1"]').click()
    cy.get('[data-testid="btn-eliminar-labores-1"]').click()
    cy.contains('Labor eliminada correctamente').should('be.visible')
    
  })

})

describe('Equipos', () => {
  it('Equipos', () => {
    cy.visit('http://localhost:5173/')
    cy.get('[data-testid="input-usuario"]').type('akoto')
    cy.get('[data-testid="input-contraseña"]').type('pass123')
    cy.get('[data-testid="button-submit"]').click()
    cy.get('[data-testid="btn-equipos"]').click()
    cy.get('[data-testid="input-equipos"]').type('Equipo de prueba')
    cy.get('[data-testid="btn-agregar-equipos"]').click()
  })
  
  it('Botones', () => {
    cy.visit('http://localhost:5173/')
    cy.get('[data-testid="input-usuario"]').type('akoto')
    cy.get('[data-testid="input-contraseña"]').type('pass123')
    cy.get('[data-testid="button-submit"]').click()
    cy.get('[data-testid="btn-equipos"]').click()
    cy.get('[data-testid="btn-editar-equipos-1"]').click()
    cy.get('[data-testid="input-titulo-equipos-1"]').clear().type('Nombre de prueba')
    cy.get('[data-testid="btn-guardar-equipos-1"]').click()
    cy.get('[data-testid="btn-editar-equipos-1"]').click()//
    cy.get('[data-testid="input-titulo-equipos-1"]').clear().type('Nombre de prueba')
    cy.get('[data-testid="cancelar-equipos-1"]').click()
    cy.get('[data-testid="btn-eliminar-equipos-1"]').click()
    cy.contains('Equipo eliminado correctamente').should('be.visible')
    
  })
})
describe('Eventos', () => {
  beforeEach(() => {
    cy.visit('http://localhost:5173/')
    cy.get('[data-testid="input-usuario"]').type('akoto')
    cy.get('[data-testid="input-contraseña"]').type('pass123')
    cy.get('[data-testid="button-submit"]').click()
    cy.get('[data-testid="btn-eventos"]').click()
  })

  it('Busca por texto (evento o módulo)', () => {
    cy.get('[data-testid="input-buscar-eventos"]').type('eliminar')
    cy.contains('Eliminar equipo').should('be.visible')
    
  })

})


describe('Unidades de medida', () => {
  it('Agrega una nueva unidad', () => {
    cy.visit('http://localhost:5173/')
    cy.get('[data-testid="input-usuario"]').type('akoto')
    cy.get('[data-testid="input-contraseña"]').type('pass123')
    cy.get('[data-testid="button-submit"]').click()
    cy.get('[data-testid="btn-unidades"]').click()
    cy.get('[data-testid="input-dimension"]').type('8')
    cy.get('[data-testid="input-unidad"]').type('Pulgadas')
    cy.get('[data-testid="btn-agregar-unidad"]').click()
    cy.contains('Unidad creada correctamente').should('be.visible')
    cy.contains('8').should('be.visible')
    cy.contains('Pulgadas').should('be.visible')
  })

  it('Botones funcionales', () => {
    cy.visit('http://localhost:5173/')
    cy.get('[data-testid="input-usuario"]').type('akoto')
    cy.get('[data-testid="input-contraseña"]').type('pass123')
    cy.get('[data-testid="button-submit"]').click()
    cy.get('[data-testid="btn-unidades"]').click()
    cy.get('[data-testid="btn-editar-unidad-1"]').click()
    cy.get('[data-testid="input-dimension"]').clear().type('10')
    cy.get('[data-testid="input-unidad"]').clear().type('Centímetros')
    cy.get('[data-testid="btn-guardar-unidad-1"]').click()
    cy.contains('Unidad actualizada correctamente').should('be.visible')
    cy.get('[data-testid="btn-editar-unidad-1"]').click()
    cy.get('[data-testid="input-dimension"]').clear().type('10')
    cy.get('[data-testid="input-unidad"]').clear().type('Centímetros')
    cy.get('[data-testid="cancelar-unidad-1"]').click()
    cy.get('[data-testid="btn-eliminar-unidad-1"]').click()
    cy.contains('Unidad eliminada correctamente').should('be.visible')
  })
})

describe('Acciones', () => {
  it('Crea una nueva actividad', () => {
    cy.visit('http://localhost:5173/')
    cy.get('[data-testid="input-usuario"]').type('akoto')
    cy.get('[data-testid="input-contraseña"]').type('pass123')
    cy.get('[data-testid="button-submit"]').click()
    cy.get('[data-testid="btn-acciones"]').click()
    cy.get('[data-testid="btn-nueva-actividad"]').click()

    // llenar formulario de nueva actividad
    cy.get('[data-testid="input-actividad"]').type('Siembra de maíz')
    cy.get('[data-testid="select-accion"]').select('Aplicación de fertilizantes')
    cy.get('[data-testid="input-fecha-inicio"]').type('2025-11-01')
    cy.get('[data-testid="input-fecha-cierre"]').type('2025-11-10')
    cy.get('[data-testid="select-responsable"]').select('Ana Koto')
    cy.get('[data-testid="input-cantidad"]').type('5')
    cy.get('[data-testid="input-costo"]').type('100')
    cy.get('[data-testid="select-categoria"]').select('Insumos')
    cy.get('[data-testid="input-descripcion"]').type('Fertilizante NPK 20-20-20')
    cy.get('[data-testid="input-cantidad-accion"]').type('50')
 //   cy.get('[data-testid="select-medida"]').select('Pulgadas')
    cy.get('[data-testid="input-monto"]').type('500')
    cy.get('[data-testid="btn-agregar-actividad"]').click()

    // verificar creación
    cy.contains('Accion Guardada Exitosamente').should('be.visible')
    cy.contains('Siembra de maíz').should('be.visible')
    cy.contains('Aplicación de fertilizantes').should('be.visible')
  })

  it('Buscador filtra actividades', () => {
    cy.visit('http://localhost:5173/')
    cy.get('[data-testid="input-usuario"]').type('akoto')
    cy.get('[data-testid="input-contraseña"]').type('pass123')
    cy.get('[data-testid="button-submit"]').click()
    cy.get('[data-testid="btn-acciones"]').click()

    // escribir en buscador
    cy.get('[data-testid="input-buscar-acciones"]').type('Siembra')
    cy.contains('Siembra').should('be.visible')

    // verificar que otras actividades no aparezcan
    cy.contains('Labranza').should('not.exist')
  })  

  it('Botones Editar y Eliminar funcionan', () => {
    cy.visit('http://localhost:5173/')
    cy.get('[data-testid="input-usuario"]').type('akoto')
    cy.get('[data-testid="input-contraseña"]').type('pass123')
    cy.get('[data-testid="button-submit"]').click()
    cy.get('[data-testid="btn-acciones"]').click()

    // editar actividad con id 1
    cy.get('[data-testid="btn-editar-actividad-1"]').click()
    cy.get('[data-testid="input-actividad-1"]').clear().type('Siembra de arroz')
    cy.get('[data-testid="btn-guardar-actividad-1"]').click()
    cy.contains('Actividad actualizada correctamente').should('be.visible')

    // eliminar actividad
    cy.get('[data-testid="btn-eliminar-actividad-1"]').click()
    cy.contains('Actividad eliminada correctamente').should('be.visible')
  })


})
