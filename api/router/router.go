package router

import (
	"collectihub/api/middleware"
	"collectihub/api/resources/user"
	"collectihub/internal/config"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

func New(l *zerolog.Logger, db *gorm.DB, cfg config.Config) *chi.Mux {
	r := chi.NewRouter()
	api := chi.NewRouter()
	auth := middleware.NewAuthenticator(cfg, db)

	// Users
	userAPI := user.New(l, db, cfg)
	api.Post("/auth/register", userAPI.SignUp)
	api.Post("/auth/login", userAPI.SignIn)
	api.Post("/auth/refresh-token", userAPI.RefreshAccessToken)
	api.Post("/auth/logout", userAPI.Logout)
	api.Get("/users/me", auth.Authenticate(userAPI.GetMe))

	r.Mount("/v1", api)

	return r
}
