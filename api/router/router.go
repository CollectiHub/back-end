package router

import (
	user "collectihub/api/handlers"
	"collectihub/api/middleware"
	"collectihub/internal/config"
	"collectihub/internal/constants"
	"fmt"

	_ "collectihub/docs"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
	httpSwagger "github.com/swaggo/http-swagger/v2"
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

	api.Get("/auth/google/login", userAPI.GoogleLogIn)
	api.Get("/auth/google/callback", userAPI.GoogleCallback)

	api.Get("/users/me", auth.Authenticate(userAPI.GetMe))
	api.Patch("/users", auth.Authenticate(userAPI.UpdateUser))
	api.Patch("/users/change-password", auth.Authenticate(userAPI.ChangePassword))
	api.Delete("/users", auth.Authenticate(userAPI.DeleteUser))
	api.Post("/users/verify-email", auth.Authenticate(userAPI.VerifyEmail))
	api.Post("/users/resend-verification-email", auth.Authenticate(userAPI.ResendEmailVerification))
	api.Post("/users/request-password-reset", userAPI.SendPasswordResetEmail)
	api.Post("/users/verify-password-reset", userAPI.PasswordReset)

	r.Mount(constants.MainRoute, api)

	// Swagger
	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL(fmt.Sprintf("%s/swagger/doc.json", cfg.BaseUrl)),
	))

	return r
}
