package middleware

import (
	"collectihub/api/models"
	"collectihub/internal/config"
	"collectihub/internal/constants"
	"collectihub/internal/util"
	"collectihub/internal/util/json"
	"context"
	"net/http"
	"strings"

	"gorm.io/gorm"
)

type Authenticator struct {
	config config.Config
	db     *gorm.DB
}

func NewAuthenticator(config config.Config, db *gorm.DB) *Authenticator {
	return &Authenticator{config, db}
}

func (a *Authenticator) Authenticate(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var access_token string
		cookie, cookie_err := r.Cookie(constants.AccessTokenCookie)

		authorizationHeader := r.Header.Get("Authorization")
		fields := strings.Fields(authorizationHeader)

		if len(fields) != 0 && fields[0] == "Bearer" {
			access_token = fields[1]
		} else if cookie_err == nil {
			access_token = cookie.Value
		} else {
			json.ErrorJSON(w, http.StatusUnauthorized, "You are not logged in", nil)
			return
		}

		sub, err := util.ValidateToken(access_token, a.config.AccessTokenPublicKey)
		if err != nil {
			json.ErrorJSON(w, http.StatusUnauthorized, "Token is not valid", err)
			return
		}

		user_id, ok := sub.(string)
		if !ok {
			json.ErrorJSON(w, http.StatusBadRequest, "Unexpected error", nil)
			return
		}

		var user models.User
		if err = a.db.First(&user, "id = ?", user_id).Error; err != nil {
			json.ErrorJSON(w, http.StatusForbidden, "User not found", nil)
			return
		}

		ctx := context.WithValue(r.Context(), constants.CurrentUserContext, user)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
