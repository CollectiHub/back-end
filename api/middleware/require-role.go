package middleware

import (
	"collectihub/api/models"
	"collectihub/internal/config"
	"collectihub/internal/constants"
	"collectihub/internal/util/json"
	"collectihub/types"
	"net/http"

	"gorm.io/gorm"
)

type RoleRequirer struct {
	config config.Config
	db     *gorm.DB
}

func NewRoleRequirer(config config.Config, db *gorm.DB) *RoleRequirer {
	return &RoleRequirer{config, db}
}

func (rr *RoleRequirer) RequireRole(next http.HandlerFunc, role types.UserRole) http.HandlerFunc {
	authenticator := NewAuthenticator(rr.config, rr.db)
	return authenticator.Authenticate(func(w http.ResponseWriter, r *http.Request) {
		user, err := models.GetUserFromRequestContext(r)
		if err != nil {
			json.ErrorJSON(w, constants.NotLoggedInErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
			return
		}

		if user.Role != role {
			json.ErrorJSON(w, constants.ForbiddenActionErrorMessage, types.HttpError{Status: http.StatusForbidden, Err: nil})
			return
		}

		next.ServeHTTP(w, r)
	})
}
