package router

import (
	"collectihub/api/handlers/base"
	"collectihub/api/handlers/manufacturer"
	"collectihub/api/handlers/user"
	"collectihub/api/middleware"
	"collectihub/internal/config"
	"collectihub/internal/constants"
	"collectihub/types"
	"fmt"

	_ "collectihub/docs"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	httpSwagger "github.com/swaggo/http-swagger/v2"
	"gorm.io/gorm"
)

func New(l *zerolog.Logger, db *gorm.DB, cfg config.Config) *chi.Mux {
	r := chi.NewRouter()
	mainRoute := chi.NewRouter()
	auth := middleware.NewAuthenticator(cfg, db)
	rr := middleware.NewRoleRequirer(cfg, db)

	r.Use(chiMiddleware.Recoverer)

	baseAPI := base.New()
	InitBaseRoutes(mainRoute, baseAPI)

	userAPI := user.New(l, db, cfg)
	InitUserRoutes(mainRoute, userAPI, auth)

	manufacturerAPI := manufacturer.New(l, db)
	InitManufacturerRoutes(mainRoute, manufacturerAPI, rr)

	r.Mount(constants.MainRoute, mainRoute)

	// Swagger
	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL(fmt.Sprintf("%s/swagger/doc.json", cfg.BaseUrl)),
	))

	return r
}

func InitBaseRoutes(r *chi.Mux, api *base.API) {
	r.Get("/healthcheck", api.HealthCheck)
}

func InitUserRoutes(r *chi.Mux, api *user.API, auth *middleware.Authenticator) {
	r.Post("/auth/register", api.SignUp)
	r.Post("/auth/login", api.SignIn)
	r.Post("/auth/refresh-token", api.RefreshAccessToken)
	r.Post("/auth/logout", api.Logout)

	r.Get("/auth/google/login", api.GoogleLogIn)
	r.Get("/auth/google/callback", api.GoogleCallback)

	r.Get("/users/me", auth.Authenticate(api.GetMe))
	r.Patch("/users", auth.Authenticate(api.UpdateUser))
	r.Patch("/users/change-password", auth.Authenticate(api.ChangePassword))
	r.Delete("/users", auth.Authenticate(api.DeleteUser))
	r.Post("/users/verify-email", auth.Authenticate(api.VerifyEmail))
	r.Post("/users/resend-verification-email", auth.Authenticate(api.ResendEmailVerification))
	r.Post("/users/request-password-reset", api.SendPasswordResetEmail)
	r.Post("/users/verify-password-reset", api.PasswordReset)
}

func InitManufacturerRoutes(
	r *chi.Mux,
	api *manufacturer.API,
	roleRequirer *middleware.RoleRequirer,
) {
	r.Get("/manufacturers", api.GetAll)
	r.Get("/manufacturers/{id}", api.GetSingle)
	r.Post("/manufacturers", roleRequirer.RequireRole(api.Create, types.ADMIN))
	r.Patch("/manufacturers/{id}", roleRequirer.RequireRole(api.Update, types.ADMIN))
	r.Delete("/manufacturers/{id}", roleRequirer.RequireRole(api.Delete, types.ADMIN))
}
