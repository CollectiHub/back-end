package manufacturer

import (
	"collectihub/api/models"
	"collectihub/internal/common"
	"collectihub/internal/constants"
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
	manufacturerRepository *database.Repository[models.Manufacturer]
	userRepository         *database.Repository[models.User]
}

func New(logger *zerolog.Logger, db *gorm.DB) *API {
	return &API{
		logger,
		database.NewRepository[models.Manufacturer](db),
		database.NewRepository[models.User](db),
	}
}

// GetAll godoc
//
//	@Summary		Get all manufacturers
//	@Description	Helps to retrieve a list of all manufacturers
//	@Tags			manufacturers
//	@Produce		json
//	@Success		200	{object}	types.SuccessResponse{data=[]models.GetManufacturerResponse}
//	@Failure		500	{object}	types.ErrorResponse	"Unexpected database error"
//	@Router			/manufacturers [get]
func (a *API) GetAll(w http.ResponseWriter, r *http.Request) {
	var manufacturers []models.Manufacturer
	if err := a.manufacturerRepository.FindAll(&manufacturers, &models.Manufacturer{}); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	response := make([]models.GetManufacturerResponse, len(manufacturers))
	for i, v := range manufacturers {
		response[i] = models.GetManufacturerResponse{
			ID:             v.ID,
			OriginalTitle:  v.OriginalTitle,
			DescriptionEng: v.DescriptionEng,
			DescriptionUkr: v.DescriptionUkr,
		}
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, response)
}

// GetSingle godoc
//
//	@Summary		Get single manufacturer by id
//	@Description	Helps to get the manufacturer with the specified id
//	@Tags			manufacturers
//	@Produce		json
//	@Param			id	path		uuid	true	"manufacturer id"
//	@Success		200	{object}	types.SuccessResponse{data=models.GetManufacturerResponse}
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

	var manufacturer models.Manufacturer
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

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, models.GetManufacturerResponse{
		ID:             manufacturer.ID,
		OriginalTitle:  manufacturer.OriginalTitle,
		DescriptionEng: manufacturer.DescriptionEng,
		DescriptionUkr: manufacturer.DescriptionUkr,
	})
}

// Create godoc
//
//	@Summary		Create a manufacturer
//	@Description	Helps to create a new manufacturer
//	@Tags			manufacturers
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		models.CreateManufacturerRequest	true	"create manufacturer body"
//	@Failure		401		{object}	types.ErrorResponse					"User is not logged in"
//	@Failure		403		{object}	types.ErrorResponse					"Action is forbidden for user of this role"
//	@Failure		422		{object}	types.ErrorResponse					"Validation error"
//	@Failure		500		{object}	types.ErrorResponse					"Unexpected database error"
//	@Router			/manufacturers [post]
func (a *API) Create(w http.ResponseWriter, r *http.Request) {
	payload := &models.CreateManufacturerRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewValidationError(err, payload))
		return
	}

	newManufacturer := models.Manufacturer{
		OriginalTitle:  payload.OriginalTitle,
		DescriptionEng: payload.DescriptionEng,
		DescriptionUkr: payload.DescriptionUkr,
	}

	if err := a.manufacturerRepository.Create(&newManufacturer, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		a.logger.Err(err).Msgf("Database error during manufacturer insertion (%v)", newManufacturer)
		return
	}

	a.logger.Info().Msgf("New manufacturer (%s) was successfully created", *newManufacturer.OriginalTitle)
	json.WriteJSON(w, http.StatusCreated, constants.SuccessMessage, &models.GetManufacturerResponse{
		ID:             newManufacturer.ID,
		OriginalTitle:  newManufacturer.OriginalTitle,
		DescriptionEng: newManufacturer.DescriptionEng,
		DescriptionUkr: newManufacturer.DescriptionUkr,
	})
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
//	@Param			body	body		models.UpdateManufacturerRequest	true	"update manufacturer body"
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

	payload := &models.UpdateManufacturerRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewDatabaseError(err))
		return
	}

	updateBody := &models.Manufacturer{
		OriginalTitle:  payload.OriginalTitle,
		DescriptionEng: payload.DescriptionEng,
		DescriptionUkr: payload.DescriptionUkr,
	}

	if err := a.manufacturerRepository.Update(&models.Manufacturer{ID: id}, updateBody, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil)
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

	if err := a.manufacturerRepository.Delete(&models.Manufacturer{}, &models.Manufacturer{ID: id}, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil)
}
