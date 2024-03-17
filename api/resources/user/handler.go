package user

import (
	"aya/internal/util"
	"aya/internal/util/json"
	"net/http"

	"github.com/go-playground/validator/v10"
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

	validate := validator.New()
	err := validate.Struct(payload)
	if err != nil {
		json.ValidatorErrorJSON(w, err)
		a.logger.Error().Err(err).Msg("Error happened during json validation")
		return
	}

	hashedPassword, err := util.HashPassword(payload.Password)
	if err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, err)
		a.logger.Error().Err(err).Msg("Error during password hashing")
		return
	}

	newUser := User{
		Email:    payload.Email,
		Username: payload.Username,
		Password: hashedPassword,
	}

	err = a.repository.Create(&newUser)
	if err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, err)
		a.logger.Error().Err(err).Msg("Error during adding new user to database")
		return
	}

	json.WriteJSON(w, http.StatusCreated, newUser, "data")
}
