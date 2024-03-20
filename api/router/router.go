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
	api.Patch("/users", auth.Authenticate(userAPI.UpdateUser))
	api.Patch("/users/change-password", auth.Authenticate(userAPI.ChangePassword))
	api.Delete("/users", auth.Authenticate(userAPI.DeleteUser))

	r.Mount("/v1", api)

	return r
}
