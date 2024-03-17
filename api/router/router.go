package router

import (
	"aya/api/resources/user"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

func New(l *zerolog.Logger, db *gorm.DB) *chi.Mux {
	r := chi.NewRouter()
	api := chi.NewRouter()

	// Users
	userAPI := user.New(l, db)
	api.Post("/users", userAPI.SignUp)

	r.Mount("/v1", api)

	return r
}
