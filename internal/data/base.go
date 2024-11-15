package data

import "kadocore/types"

type HealthCheckResponse struct {
	Version string                  `json:"version" example:"1.0.0"`
	Status  types.HealthCheckStatus `json:"status" example:"ok"`
}

type FileUploadResponse struct {
	Location string `json:"location" example:"https://s3.amazonaws.com/bucketname/filename.jpg"`
}
