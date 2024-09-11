package manufacturer

import (
	"collectihub/internal/common"
	"collectihub/internal/constants"
	"collectihub/internal/data"
	"collectihub/internal/database"
	"collectihub/internal/util/json"
	"collectihub/types"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

type API struct {
	logger                 *zerolog.Logger
	manufacturerRepository *database.Repository[data.Manufacturer]
	userRepository         *database.Repository[data.User]
}

func New(logger *zerolog.Logger, db *gorm.DB) *API {
	return &API{
		logger,
		database.NewRepository[data.Manufacturer](db),
		database.NewRepository[data.User](db),
	}
}

// GetAll godoc
//
//	@Summary		Get all manufacturers
//	@Description	Helps to retrieve a list of all manufacturers
//	@Tags			manufacturers
//	@Produce		json
//	@Success		200	{object}	types.SuccessResponse{data=[]data.GetManufacturerResponse}
//	@Failure		500	{object}	types.ErrorResponse	"Unexpected database error"
//	@Router			/manufacturers [get]
func (a *API) GetAll(w http.ResponseWriter, r *http.Request) {
	var manufacturers []data.Manufacturer
	if err := a.manufacturerRepository.FindAll(&manufacturers, &data.Manufacturer{}); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	response := make([]data.GetManufacturerResponse, len(manufacturers))
	for i, v := range manufacturers {
		response[i] = data.GetManufacturerResponse{
			ID:             v.ID,
			OriginalTitle:  v.OriginalTitle,
			DescriptionEng: v.DescriptionEng,
			DescriptionUkr: v.DescriptionUkr,
			Image:          v.Image,
		}
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, response, nil)
}

// GetSingle godoc
//
//	@Summary		Get single manufacturer by id
//	@Description	Helps to get the manufacturer with the specified id
//	@Tags			manufacturers
//	@Produce		json
//	@Param			id	path		uuid	true	"manufacturer id"
//	@Success		200	{object}	types.SuccessResponse{data=data.GetManufacturerResponse}
//	@Failure		400	{object}	types.ErrorResponse	"Incorrect id path"
//	@Failure		404	{object}	types.ErrorResponse	"Manufacturer not found"
//	@Failure		500	{object}	types.ErrorResponse	"Unexpected database error"
//	@Router			/manufacturers/{id} [get]
func (a *API) GetSingle(w http.ResponseWriter, r *http.Request) {
	idFromParams := chi.URLParam(r, "id")
	id, err := uuid.Parse(idFromParams)
	if err != nil {
		json.ErrorJSON(w, constants.IncorrectIdErrorMessage, types.HttpError{
			Status: http.StatusBadRequest,
		})
		return
	}

	var manufacturer data.Manufacturer
	if err := a.manufacturerRepository.FindOneById(&manufacturer, id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			json.ErrorJSON(w, constants.NotFoundMessage("Manufacturer"), types.HttpError{
				Status: 404,
			})
		} else {
			json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		}

		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, data.GetManufacturerResponse{
		ID:             manufacturer.ID,
		OriginalTitle:  manufacturer.OriginalTitle,
		DescriptionEng: manufacturer.DescriptionEng,
		DescriptionUkr: manufacturer.DescriptionUkr,
		Image:          manufacturer.Image,
	}, nil)
}

// Create godoc
//
//	@Summary		Create a manufacturer
//	@Description	Helps to create a new manufacturer
//	@Tags			manufacturers
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		data.CreateManufacturerRequest	true	"create manufacturer body"
//	@Failure		401		{object}	types.ErrorResponse					"User is not logged in"
//	@Failure		403		{object}	types.ErrorResponse					"Action is forbidden for user of this role"
//	@Failure		422		{object}	types.ErrorResponse					"Validation error"
//	@Failure		500		{object}	types.ErrorResponse					"Unexpected database error"
//	@Router			/manufacturers [post]
func (a *API) Create(w http.ResponseWriter, r *http.Request) {
	payload := &data.CreateManufacturerRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewValidationError(err, payload))
		return
	}

	newManufacturer := data.Manufacturer{
		OriginalTitle:  payload.OriginalTitle,
		DescriptionEng: payload.DescriptionEng,
		DescriptionUkr: payload.DescriptionUkr,
		Image:          payload.Image,
	}

	if err := a.manufacturerRepository.Create(&newManufacturer, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		a.logger.Err(err).Msgf("Database error during manufacturer insertion (%v)", newManufacturer)
		return
	}

	a.logger.Info().Msgf("New manufacturer (%s) was successfully created", *newManufacturer.OriginalTitle)
	json.WriteJSON(w, http.StatusCreated, constants.SuccessMessage, &data.GetManufacturerResponse{
		ID:             newManufacturer.ID,
		OriginalTitle:  newManufacturer.OriginalTitle,
		DescriptionEng: newManufacturer.DescriptionEng,
		DescriptionUkr: newManufacturer.DescriptionUkr,
		Image:          newManufacturer.Image,
	}, nil)
}

// Update godoc
//
//	@Summary		Update a manufacturer
//	@Description	Helps to update the existing manufacturer
//	@Tags			manufacturers
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			id		path		uuid								true	"manufacturer id"
//	@Param			body	body		data.UpdateManufacturerRequest	true	"update manufacturer body"
//	@Failure		400		{object}	types.ErrorResponse					"Incorrect id path"
//	@Failure		401		{object}	types.ErrorResponse					"User is not logged in"
//	@Failure		403		{object}	types.ErrorResponse					"Action is forbidden for user of this role"
//	@Failure		422		{object}	types.ErrorResponse					"Validation error"
//	@Failure		500		{object}	types.ErrorResponse					"Unexpected database error"
//	@Router			/manufacturers/{id} [patch]
func (a *API) Update(w http.ResponseWriter, r *http.Request) {
	idFromParams := chi.URLParam(r, "id")
	id, err := uuid.Parse(idFromParams)
	if err != nil {
		json.ErrorJSON(w, constants.IncorrectIdErrorMessage, types.HttpError{
			Status: http.StatusBadRequest,
		})
		return
	}

	payload := &data.UpdateManufacturerRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewValidationError(err, payload))
		return
	}

	updateBody := &data.Manufacturer{
		OriginalTitle:  payload.OriginalTitle,
		DescriptionEng: payload.DescriptionEng,
		DescriptionUkr: payload.DescriptionUkr,
		Image:          payload.Image,
	}

	if err := a.manufacturerRepository.Update(&data.Manufacturer{ID: id}, updateBody, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil, nil)
}

// Delete godoc
//
//	@Summary		Delete a manufacturer
//	@Description	Helps to delete the existing manufacturer
//	@Tags			manufacturers
//	@Security		BearerAuth
//	@Produce		json
//	@Param			id	path		uuid				true	"manufacturer id"
//	@Failure		400	{object}	types.ErrorResponse	"Incorrect id path"
//	@Failure		401	{object}	types.ErrorResponse	"User is not logged in"
//	@Failure		403	{object}	types.ErrorResponse	"Action is forbidden for user of this role"
//	@Failure		500	{object}	types.ErrorResponse	"Unexpected database error"
//	@Router			/manufacturers/{id} [delete]
func (a *API) Delete(w http.ResponseWriter, r *http.Request) {
	idFromParams := chi.URLParam(r, "id")
	id, err := uuid.Parse(idFromParams)
	if err != nil {
		json.ErrorJSON(w, constants.IncorrectIdErrorMessage, types.HttpError{
			Status: http.StatusBadRequest,
		})
		return
	}

	if err := a.manufacturerRepository.Delete(&data.Manufacturer{}, &data.Manufacturer{ID: id}, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil, nil)
}
