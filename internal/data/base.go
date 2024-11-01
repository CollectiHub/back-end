package data

import "kadocore/types"

type HealthCheckResponse struct {
	Version string                  `json:"version" example:"1.0.0"`
	Status  types.HealthCheckStatus `json:"status" example:"ok"`
}
