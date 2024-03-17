package user

import (
	"aya/internal/util/json"
	"net/http"

	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

type API struct {
	logger     *zerolog.Logger
	repository *Repository
}

func New(logger *zerolog.Logger, db *gorm.DB) *API {
	return &API{logger, NewRepository(db)}
}

func (a *API) SignUp(w http.ResponseWriter, r *http.Request) {
	payload := &SignUpInput{}

	json.DecodeJSON(*r, payload)

	a.logger.Info().Msgf("Received request to create user: %v", payload)
}
