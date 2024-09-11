package base

import (
	"collectihub/internal/constants"
	"collectihub/internal/data"
	"collectihub/internal/util/json"
	"collectihub/types"
	"net/http"
)

type API struct{}

func New() *API {
	return &API{}
}

// HealthCheck godoc
//
//	@Summary		Healthcheck
//	@Description	Serves as route to check if server is up and running
//	@Tags			base
//	@Produce		json
//	@Success		200	{object}	types.SuccessResponse{data=data.HealthCheckResponse}
//	@Failure		500	{object}	types.ErrorResponse	"Server is not available"
//	@Router			/healthcheck [get]
func (a *API) HealthCheck(w http.ResponseWriter, r *http.Request) {
	json.WriteJSON(
		w,
		http.StatusOK,
		constants.SuccessMessage,
		&data.HealthCheckResponse{Version: "1.0.0", Status: types.HEALTH_CHECK_STATUS_OK},
		nil,
	)
}
