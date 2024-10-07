package main

import (
	"collectihub/internal/common"
	"collectihub/internal/constants"
	"collectihub/internal/data"
	"collectihub/internal/util/json"
	"collectihub/types"
	"errors"
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
//	@Failure		401		{object}	types.ErrorResponse		"User is not logged in"
//	@Failure		403		{object}	types.ErrorResponse		"Action is forbidden for user of this role"
//	@Failure		422		{object}	types.ErrorResponse		"Validation error"
//	@Failure		500		{object}	types.ErrorResponse		"Unexpected database error"
//	@Router			/cards [post]
func (app *application) createCardHandler(w http.ResponseWriter, r *http.Request) {
	payload := &data.CreateCardRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewValidationError(err, payload))
		return
	}

	newCard := data.Card{
		Rarity:        payload.Rarity,
		CharacterName: payload.CharacterName,
		SerialNumber:  payload.SerialNumber,
		ImageUrl:      payload.ImageUrl,
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
//	@Success		200	{object}	types.SuccessResponse{data=[]data.GetCardResponse}
//	@Failure		500	{object}	types.ErrorResponse	"Unexpected database error"
//	@Router			/cards [get]
func (app *application) getAllCardsHandler(w http.ResponseWriter, _ *http.Request) {
	cards, err := app.models.Cards.FindAll(&data.Card{})
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

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, data.GetCollectionInfoResponse{
		Rarities:       rarities,
		CardsTotal:     totalCount,
		CardsCollected: ownedCount,
	}, nil)
}

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
