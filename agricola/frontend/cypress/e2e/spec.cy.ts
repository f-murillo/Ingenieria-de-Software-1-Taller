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
    cy.wait(2000)
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
//    cy.contains('No hay usuarios').should('be.visible')
//    cy.get('[data-testid="btn-asignar-usuarios-1"]').click()
//    cy.get('[data-testid="select-usuarios-disponibles"]').select(['3'])
//    cy.get('button[type="submit"]').click()
//    cy.contains('Usuarios asociados correctamente').should('be.visible')
    cy.get('[data-testid="btn-detalles-proyecto-1"]').click()
    
    cy.get('[data-testid="btn-eliminar-proyecto-1"]').click()
    
    cy.get('[data-testid="btn-activar-proyecto-1"]').click()
 
    cy.get('[data-testid="btn-imprimir-proyecto-1"]').click()
  })

})
