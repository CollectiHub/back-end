package main

import (
	"collectihub/internal/constants"
	"collectihub/internal/data"
	"collectihub/internal/util"
	"collectihub/internal/util/json"
	"collectihub/types"
	"context"
	"net/http"
	"strings"
)

func (app *application) authenticate(next http.HandlerFunc) http.HandlerFunc {
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
			json.ErrorJSON(w, constants.NotLoggedInErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
			return
		}

		sub, err := util.ValidateToken(access_token, app.config.AccessTokenPublicKey)
		if err != nil {
			json.ErrorJSON(w, constants.TokenIsNotValidErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
			return
		}

		user_id, ok := sub.(string)
		if !ok {
			json.ErrorJSON(w, constants.UnexpectedErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
			return
		}

		user, err := app.models.Users.FindOneById(user_id)

		if err != nil {
			json.ErrorJSON(w, constants.NotFoundMessage("User"), types.HttpError{Status: http.StatusForbidden, Err: nil})
			return
		}

		ctx := context.WithValue(r.Context(), constants.CurrentUserContext, user)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (app *application) requireRole(next http.HandlerFunc, role types.UserRole) http.HandlerFunc {
	return app.authenticate(func(w http.ResponseWriter, r *http.Request) {
		user, err := data.GetUserFromRequestContext(r)
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
