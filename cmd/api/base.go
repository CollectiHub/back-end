package main

import (
	"kadocore/internal/constants"
	"kadocore/internal/data"
	"kadocore/internal/util/json"
	"kadocore/types"
	"net/http"
)

// HealthCheck godoc
//
//	@Summary		Healthcheck
//	@Description	Serves as route to check if server is up and running
//	@Tags			base
//	@Produce		json
//	@Success		200	{object}	types.SuccessResponse{data=data.HealthCheckResponse}
//	@Failure		500	{object}	types.ErrorResponse	"Server is not available"
//	@Router			/healthcheck [get]
func (app *application) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	json.WriteJSON(
		w,
		http.StatusOK,
		constants.SuccessMessage,
		&data.HealthCheckResponse{Version: "1.0.0", Status: types.HEALTH_CHECK_STATUS_OK},
		nil,
	)
}
