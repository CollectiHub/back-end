package main

import (
	"errors"
	"kadocore/internal/common"
	"kadocore/internal/constants"
	"kadocore/internal/data"
	"kadocore/internal/util/json"
	"kadocore/types"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GetAll godoc
//
//	@Summary		Get all manufacturers
//	@Description	Helps to retrieve a list of all manufacturers
//	@Tags			manufacturers
//	@Produce		json
//	@Success		200	{object}	types.SuccessResponse{data=[]data.GetManufacturerResponse}
//	@Failure		500	{object}	types.ErrorResponse	"Unexpected database error"
//	@Router			/manufacturers [get]
func (app *application) getAllManufacturersHandler(w http.ResponseWriter, r *http.Request) {
	manufacturers, err := app.models.Manufacturers.FindAll(&data.Manufacturer{})
	if err != nil {
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
func (app *application) getManufacturerByIdHandler(w http.ResponseWriter, r *http.Request) {
	idFromParams := chi.URLParam(r, "id")
	id, err := uuid.Parse(idFromParams)
	if err != nil {
		json.ErrorJSON(w, constants.IncorrectIdErrorMessage, types.HttpError{
			Status: http.StatusBadRequest,
		})
		return
	}

	manufacturer, err := app.models.Manufacturers.FindOneById(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			json.ErrorJSON(w, constants.NotFoundMessage("Manufacturer"), types.HttpError{
				Status: http.StatusNotFound,
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
//	@Failure		401		{object}	types.ErrorResponse				"User is not logged in"
//	@Failure		403		{object}	types.ErrorResponse				"Action is forbidden for user of this role"
//	@Failure		422		{object}	types.ErrorResponse				"Validation error"
//	@Failure		500		{object}	types.ErrorResponse				"Unexpected database error"
//	@Router			/manufacturers [post]
func (app *application) createManufacturerHandler(w http.ResponseWriter, r *http.Request) {
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

	if err := app.models.Manufacturers.Create(&newManufacturer, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		app.logger.Err(err).Msgf("Database error during manufacturer insertion (%v)", newManufacturer)
		return
	}

	app.logger.Info().Msgf("New manufacturer (%s) was successfully created", *newManufacturer.OriginalTitle)
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
//	@Param			id		path		uuid							true	"manufacturer id"
//	@Param			body	body		data.UpdateManufacturerRequest	true	"update manufacturer body"
//	@Success		200		{object}	types.SuccessResponse
//	@Failure		400		{object}	types.ErrorResponse	"Incorrect id path"
//	@Failure		401		{object}	types.ErrorResponse	"User is not logged in"
//	@Failure		403		{object}	types.ErrorResponse	"Action is forbidden for user of this role"
//	@Failure		422		{object}	types.ErrorResponse	"Validation error"
//	@Failure		500		{object}	types.ErrorResponse	"Unexpected database error"
//	@Router			/manufacturers/{id} [patch]
func (app *application) updateManufacturerHandler(w http.ResponseWriter, r *http.Request) {
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

	if err := app.models.Manufacturers.Update(&data.Manufacturer{ID: id}, updateBody, nil); err != nil {
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
func (app *application) deleteManufacturerHandler(w http.ResponseWriter, r *http.Request) {
	idFromParams := chi.URLParam(r, "id")
	id, err := uuid.Parse(idFromParams)
	if err != nil {
		json.ErrorJSON(w, constants.IncorrectIdErrorMessage, types.HttpError{
			Status: http.StatusBadRequest,
		})
		return
	}

	if err := app.models.Manufacturers.DeleteOneById(id, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil, nil)
}

// Add non-existent cards godoc
//
//	@Summary		Add non-existent cards
//	@Description	Helps to add non-existent cards to manufacturer
//	@Tags			manufacturers
//	@Security		BearerAuth
//	@Produce		json
//	@Param			id		path		uuid								true	"manufacturer id"
//	@Param			body	body		data.CreateNonExistentCardRequest	true	"add non-existent card body"
//	@Failure		400		{object}	types.ErrorResponse					"Incorrect id path"
//	@Failure		401		{object}	types.ErrorResponse					"User is not logged in"
//	@Failure		403		{object}	types.ErrorResponse					"Action is forbidden for user of this role"
//	@Failure		500		{object}	types.ErrorResponse					"Unexpected database error"
//	@Router			/manufacturers/{id}/add-non-existent-card [post]
func (app *application) addNonExistentCardHandler(w http.ResponseWriter, r *http.Request) {
	idFromParams := chi.URLParam(r, "id")
	id, err := uuid.Parse(idFromParams)
	if err != nil {
		json.ErrorJSON(w, constants.IncorrectIdErrorMessage, types.HttpError{
			Status: http.StatusBadRequest,
		})
		return
	}

	payload := &data.CreateNonExistentCardRequest{}
	json.DecodeJSON(*r, payload)
	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewValidationError(err, payload))
		return
	}

	newNonExistentCard := data.NonExistentCard{
		ManufacturerID: id,
		Rarity:         payload.Rarity,
		SerialNumber:   payload.SerialNumber,
	}

	if err := app.models.NonExistentCards.Create(&newNonExistentCard, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil, nil)
}

// Get all non-existent cards godoc
//
//	@Summary		Get non-existent cards
//	@Description	Helps to get non-existent cards of manufacturer
//	@Tags			manufacturers
//	@Security		BearerAuth
//	@Produce		json
//	@Param			id	path		uuid				true	"manufacturer id"
//	@Failure		400	{object}	types.ErrorResponse	"Incorrect id path"
//	@Failure		500	{object}	types.ErrorResponse	"Unexpected database error"
//	@Router			/manufacturers/{id}/non-existent-cards [get]
func (app *application) getNonExistentCardsHandler(w http.ResponseWriter, r *http.Request) {
	idFromParams := chi.URLParam(r, "id")
	id, err := uuid.Parse(idFromParams)
	if err != nil {
		json.ErrorJSON(w, constants.IncorrectIdErrorMessage, types.HttpError{
			Status: http.StatusBadRequest,
		})
		return
	}

	nonExistentCards, err := app.models.NonExistentCards.FindAll(&data.NonExistentCard{
		ManufacturerID: id,
	})
	if err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	response := make([]data.GetNonExistentCardResponse, len(nonExistentCards))
	for i, v := range nonExistentCards {
		response[i] = data.GetNonExistentCardResponse{
			ID:           v.ID,
			Rarity:       v.Rarity,
			SerialNumber: v.SerialNumber,
		}
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, response, nil)
}

// Delete non-existent card godoc
//
//	@Summary		Delete non-existent card
//	@Description	Helps to delete the existing non-exitent card
//	@Tags			manufacturers
//	@Security		BearerAuth
//	@Produce		json
//	@Param			id	path		uuid				true	"non-exitent card id"
//	@Failure		400	{object}	types.ErrorResponse	"Incorrect id path"
//	@Failure		401	{object}	types.ErrorResponse	"User is not logged in"
//	@Failure		403	{object}	types.ErrorResponse	"Action is forbidden for user of this role"
//	@Failure		500	{object}	types.ErrorResponse	"Unexpected database error"
//	@Router			/manufacturers/non-existent-card/{id} [delete]
func (app *application) deleteNonExistentCardHandler(w http.ResponseWriter, r *http.Request) {
	idFromParams := chi.URLParam(r, "id")
	id, err := uuid.Parse(idFromParams)
	if err != nil {
		json.ErrorJSON(w, constants.IncorrectIdErrorMessage, types.HttpError{
			Status: http.StatusBadRequest,
		})
		return
	}

	if err := app.models.NonExistentCards.DeleteOneById(id, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil, nil)
}
