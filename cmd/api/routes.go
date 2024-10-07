package main

import (
	"collectihub/internal/constants"
	"collectihub/types"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger/v2"
)

func (app *application) routes() http.Handler {
	router := chi.NewRouter()
	r := chi.NewRouter()

	r.Use(chiMiddleware.Recoverer)

	// Base handlers
	r.Get("/healthcheck", app.healthCheckHandler)
	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL(fmt.Sprintf("%s/swagger/doc.json", app.config.BaseUrl)),
	))

	// User handlers
	r.Post("/auth/register", app.signUpHandler)
	r.Post("/auth/login", app.signInHandler)
	r.Post("/auth/refresh-token", app.refreshAccessTokenHandler)
	r.Post("/auth/logout", app.logoutHandler)

	r.Get("/auth/google/login", app.googleLoginHandler)
	r.Get("/auth/google/callback", app.googleCallbackHandler)

	r.Get("/users/me", app.authenticate(app.getAuthenticatedUserHandler))
	r.Patch("/users", app.authenticate(app.updateUserHandler))
	r.Patch("/users/change-password", app.authenticate(app.changePasswordHandler))
	r.Delete("/users", app.authenticate(app.deleteUserHandler))
	r.Post("/users/verify-email", app.authenticate(app.verifyEmailHandler))
	r.Post("/users/resend-verification-email", app.authenticate(app.resendEmailVerificationHandler))
	r.Post("/users/request-password-reset", app.sendPasswordResetEmailHandler)
	r.Post("/users/verify-password-reset", app.passwordResetHandler)

	// Manufacturer handlers
	r.Get("/manufacturers", app.getAllManufacturersHandler)
	r.Get("/manufacturers/{id}", app.getManufacturerByIdHandler)
	r.Post("/manufacturers", app.requireRole(app.createManufacturerHandler, types.ADMIN))
	r.Patch("/manufacturers/{id}", app.requireRole(app.updateManufacturerHandler, types.ADMIN))
	r.Delete("/manufacturers/{id}", app.requireRole(app.deleteManufacturerHandler, types.ADMIN))

	// Cards
	r.Post("/cards", app.requireRole(app.createCardHandler, types.ADMIN))
	r.Get("/cards", app.getAllCardsHandler)
	r.Get("/cards/by-id/{id}", app.getCardByIdHandler)
	r.Patch("/cards/by-id/{id}", app.requireRole(app.updateCardHandler, types.ADMIN))
	r.Delete("/cards/by-id/{id}", app.requireRole(app.deleteCardByIdHandler, types.ADMIN))
	r.Get("/collection/info", app.authenticate(app.getCollectionInfoHandler))
	r.Patch("/collection/update", app.authenticate(app.updateCollectionInfoHandler))
	r.Get("/collection/get-by-rarity", app.authenticate(app.getAllCardsByRarityHandler))

	router.Mount(constants.MainRoute, r)

	return router
}
