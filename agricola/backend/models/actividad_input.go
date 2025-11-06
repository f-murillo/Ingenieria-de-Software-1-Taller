package models

type ActividadInput struct {
	ID            int    `json:"id"`
	ProyectoID    int    `json:"proyecto_id"`
	ActividadID   int    `json:"actividad_id"`  // ID de la LaborAgronomica
	ImplementoID  int    `json:"implemento_id"` // ID del EquipoImplemento
	UsuarioID     int    `json:"usuario_id"`
	RecursoHumano string `json:"recurso_humano"`
}
