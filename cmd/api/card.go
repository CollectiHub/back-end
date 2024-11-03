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

// Create godoc
//
//	@Summary		Create a card
//	@Description	Helps to create a new card
//	@Tags			cards
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		data.CreateCardRequest	true	"create card body"
//	@Success		201		{object}	types.SuccessResponse{data=data.GetCardResponse}
//	@Failure		401		{object}	types.ErrorResponse	"User is not logged in"
//	@Failure		403		{object}	types.ErrorResponse	"Action is forbidden for user of this role"
//	@Failure		422		{object}	types.ErrorResponse	"Validation error"
//	@Failure		500		{object}	types.ErrorResponse	"Unexpected database error"
//	@Router			/cards [post]
func (app *application) createCardHandler(w http.ResponseWriter, r *http.Request) {
	payload := &data.CreateCardRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewValidationError(err, payload))
		return
	}

	newCard := data.Card{
		ManufacturerID: payload.ManufacturerID,
		Rarity:         payload.Rarity,
		CharacterName:  payload.CharacterName,
		SerialNumber:   payload.SerialNumber,
		ImageUrl:       payload.ImageUrl,
	}

	if err := app.models.Cards.Create(&newCard, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		app.logger.Err(err).Msgf("Database error during card insertion (%v)", newCard)
		return
	}

	app.logger.Info().Msgf("New card (%s) was successfully created", *newCard.SerialNumber)
	json.WriteJSON(w, http.StatusCreated, constants.SuccessMessage, &data.GetCardResponse{
		ID:            newCard.ID,
		Rarity:        newCard.Rarity,
		CharacterName: newCard.CharacterName,
		SerialNumber:  newCard.SerialNumber,
		ImageUrl:      newCard.ImageUrl,
	}, nil)
}

// GetAll godoc
//
//	@Summary		Get all cards
//	@Description	Helps to retrieve a list of all cards
//	@Tags			cards
//	@Produce		json
//	@Param			id	path		uuid	true	"manufacturer id"
//	@Success		200	{object}	types.SuccessResponse{data=[]data.GetCardResponse}
//	@Failure		500	{object}	types.ErrorResponse	"Unexpected database error"
//	@Router			/cards/by-manufacturer/{id} [get]
func (app *application) getAllCardsHandler(w http.ResponseWriter, r *http.Request) {
	idFromParams := chi.URLParam(r, "id")
	id, err := uuid.Parse(idFromParams)
	if err != nil {
		json.ErrorJSON(w, constants.IncorrectIdErrorMessage, types.HttpError{
			Status: http.StatusBadRequest,
		})
		return
	}

	cards, err := app.models.Cards.FindAll(&data.Card{ManufacturerID: id})
	if err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	response := make([]data.GetCardResponse, 0)
	for _, card := range cards {
		response = append(response, data.GetCardResponse{
			ID:            card.ID,
			Rarity:        card.Rarity,
			CharacterName: card.CharacterName,
			SerialNumber:  card.SerialNumber,
			ImageUrl:      card.ImageUrl,
		})
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, response, nil)
}

// Update godoc
//
//	@Summary		Update a card
//	@Description	Helps to update an existing card
//	@Tags			cards
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		data.UpdateCardRequest	true	"update card body"
//	@Param			id		path		uuid					true	"card id"
//	@Success		200		{object}	types.SuccessResponse
//	@Failure		401		{object}	types.ErrorResponse	"User is not logged in"
//	@Failure		403		{object}	types.ErrorResponse	"Action is forbidden for user of this role"
//	@Failure		404		{object}	types.ErrorResponse	"Card not found"
//	@Failure		422		{object}	types.ErrorResponse	"Validation error"
//	@Failure		500		{object}	types.ErrorResponse	"Unexpected database error"
//	@Router			/cards/by-id/{id} [patch]
func (app *application) updateCardHandler(w http.ResponseWriter, r *http.Request) {
	idFromParams := chi.URLParam(r, "id")
	id, err := uuid.Parse(idFromParams)
	if err != nil {
		json.ErrorJSON(w, constants.IncorrectIdErrorMessage, types.HttpError{
			Status: http.StatusBadRequest,
		})
		return
	}

	payload := &data.UpdateCardRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewValidationError(err, payload))
		return
	}

	updateBody := data.Card{
		Rarity:        payload.Rarity,
		CharacterName: payload.CharacterName,
		SerialNumber:  payload.SerialNumber,
		ImageUrl:      payload.ImageUrl,
	}

	if err := app.models.Cards.Update(&data.Card{ID: id}, &updateBody, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil, nil)
}

// Get by id godoc
//
//	@Summary		Get by id
//	@Description	Helps to retrieve an existing card by id
//	@Tags			cards
//	@Produce		json
//	@Param			id	path		uuid	true	"card id"
//	@Success		200	{object}	types.SuccessResponse{data=data.GetCardResponse}
//	@Failure		400	{object}	types.ErrorResponse	"Incorrect id format"
//	@Failure		401	{object}	types.ErrorResponse	"User is not logged in"
//	@Failure		404	{object}	types.ErrorResponse	"Card not found"
//	@Failure		500	{object}	types.ErrorResponse	"Unexpected database error"
//	@Router			/cards/by-id/{id} [get]
func (app *application) getCardByIdHandler(w http.ResponseWriter, r *http.Request) {
	idFromParams := chi.URLParam(r, "id")
	id, err := uuid.Parse(idFromParams)
	if err != nil {
		json.ErrorJSON(w, constants.IncorrectIdErrorMessage, types.HttpError{
			Status: http.StatusBadRequest,
		})
		return
	}

	card, err := app.models.Cards.FindOne(&data.Card{ID: id})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			json.ErrorJSON(w, constants.NotFoundMessage("Card"), types.HttpError{
				Status: http.StatusNotFound,
			})
		} else {
			json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		}

		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, data.GetCardResponse{
		ID:            card.ID,
		Rarity:        card.Rarity,
		CharacterName: card.CharacterName,
		SerialNumber:  card.SerialNumber,
		ImageUrl:      card.ImageUrl,
	}, nil)
}

// Delete by id godoc
//
//	@Summary		Delete by id
//	@Description	Helps to delete an existing card by id
//	@Tags			cards
//	@Security		BearerAuth
//	@Produce		json
//	@Param			id	path		uuid	true	"card id"
//	@Success		200	{object}	types.SuccessResponse
//	@Failure		401	{object}	types.ErrorResponse	"User is not logged in"
//	@Failure		403	{object}	types.ErrorResponse	"Action is forbidden for user of this role"
//	@Failure		404	{object}	types.ErrorResponse	"Card not found"
//	@Failure		422	{object}	types.ErrorResponse	"Validation error"
//	@Failure		500	{object}	types.ErrorResponse	"Unexpected database error"
//	@Router			/cards/by-id/{id} [delete]
func (app *application) deleteCardByIdHandler(w http.ResponseWriter, r *http.Request) {
	idFromParams := chi.URLParam(r, "id")
	id, err := uuid.Parse(idFromParams)
	if err != nil {
		json.ErrorJSON(w, constants.IncorrectIdErrorMessage, types.HttpError{
			Status: http.StatusBadRequest,
		})
		return
	}

	if err := app.models.Cards.DeleteOneById(id, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil, nil)
}

// Get collection info godoc
//
//	@Summary		Get collection info
//	@Description	Helps to retrieve collection info
//	@Tags			cards
//	@Security		BearerAuth
//	@Produce		json
//	@Success		200	{object}	types.SuccessResponse{data=data.GetCollectionInfoResponse}
//	@Failure		401	{object}	types.ErrorResponse	"User is not logged in"
//	@Failure		500	{object}	types.ErrorResponse	"Unexpected database error"
//	@Router			/collection/info [get]
func (app *application) getCollectionInfoHandler(w http.ResponseWriter, r *http.Request) {
	user, err := data.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, constants.NotLoggedInErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
		return
	}

	rarities, err := app.models.Cards.GetAllRarities()
	if err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	totalCount, err := app.models.Cards.GetTotalCount()
	if err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	ownedCount, err := app.models.Cards.GetCollectedCount(user.ID.String())
	if err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	nonExistentCardsRows, err := app.models.NonExistentCards.FindAll(&data.NonExistentCard{})
	if err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	var nonExistentCards []data.GetNonExistentCardResponse
	for _, row := range nonExistentCardsRows {
		nonExistentCards = append(nonExistentCards, data.GetNonExistentCardResponse{
			ID:           row.ID,
			Rarity:       row.Rarity,
			SerialNumber: row.SerialNumber,
		})
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, data.GetCollectionInfoResponse{
		Rarities:         rarities,
		CardsTotal:       totalCount,
		CardsCollected:   ownedCount,
		NonExistentCards: nonExistentCards,
	}, nil)
}

// Get all cards by rarity godoc
//
//	@Summary		Get all cards by rarity
//	@Description	Helps to retrieve all cards by rarity
//	@Tags			cards
//	@Security		BearerAuth
//	@Param			rarity	query	string	false	"rarity of the card"
//	@Produce		json
//	@Success		200	{object}	types.SuccessResponse{data=[]data.GetOwnedCardResponse}
//	@Failure		400	{object}	types.ErrorResponse	"Rarity is required"
//	@Failure		401	{object}	types.ErrorResponse	"User is not logged in"
//	@Failure		500	{object}	types.ErrorResponse	"Unexpected database error"
//	@Router			/collection/get-by-rarity [get]
func (app *application) getAllCardsByRarityHandler(w http.ResponseWriter, r *http.Request) {
	rarity := r.URL.Query().Get("rarity")
	user, err := data.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, constants.NotLoggedInErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
		return
	}

	if rarity == "" {
		json.ErrorJSON(w, constants.RarityIsRequiredErrorMessage, types.HttpError{
			Status: http.StatusBadRequest,
		})
		return
	}

	cards, err := app.models.Cards.FindAllOwnedByRarity(user.ID.String(), rarity)
	if err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, cards, nil)
}

// Update collection info godoc
//
//	@Summary		Update collection info
//	@Description	Helps to update collection info (change collected status)
//	@Tags			cards
//	@Security		BearerAuth
//	@Produce		json
//	@Accept			json
//	@Param			body	body		data.UpdateCollectionRequest	true	"collection update body"
//	@Success		200		{object}	types.SuccessResponse{data=data.UpdateCollectionResponse}
//	@Failure		400		{object}	types.ErrorResponse	"Rarity is required"
//	@Failure		401		{object}	types.ErrorResponse	"User is not logged in"
//	@Failure		500		{object}	types.ErrorResponse	"Unexpected database error"
//	@Router			/collection/update [post]
func (app *application) updateCollectionInfoHandler(w http.ResponseWriter, r *http.Request) {
	user, err := data.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, constants.NotLoggedInErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
		return
	}

	payload := &data.UpdateCollectionRequest{}
	json.DecodeJSON(*r, payload)

	if err = app.models.CollectionCardInfos.UpdateAllByUserIDAndCardIDs(
		user.ID.String(),
		payload.Ids,
		payload.Change.Status, nil,
	); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	ownedCount, err := app.models.Cards.GetCollectedCount(user.ID.String())
	if err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, data.UpdateCollectionResponse{
		CardsCollected: ownedCount,
	}, nil)
}

// Search cards by term godoc
//
//	@Summary		Search cards by term
//	@Description	Helps to search cards by term (by character name or serial number)
//	@Tags			cards
//	@Security		BearerAuth
//	@Param			term	query	string	false	"search term"
//	@Produce		json
//	@Success		200	{object}	types.SuccessResponse{data=[]data.GetOwnedCardResponse}
//	@Failure		400	{object}	types.ErrorResponse	"Term is required"
//	@Failure		401	{object}	types.ErrorResponse	"User is not logged in"
//	@Failure		500	{object}	types.ErrorResponse	"Unexpected database error"
//	@Router			/collection/search [get]
func (app *application) searchCardsWithTermHandler(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("term")
	user, err := data.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, constants.NotLoggedInErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
		return
	}

	if term == "" {
		json.ErrorJSON(w, constants.RarityIsRequiredErrorMessage, types.HttpError{
			Status: http.StatusBadRequest,
		})
		return
	}

	cards, err := app.models.Cards.SearchCardsWithTerm(user.ID.String(), term)
	if err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, cards, nil)
}
