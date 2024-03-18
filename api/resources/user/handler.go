package user

import (
	"collectihub/internal/config"
	"collectihub/internal/constants"
	"collectihub/internal/util"
	"collectihub/internal/util/json"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

type API struct {
	logger     *zerolog.Logger
	repository *Repository
	config     config.Config
}

func New(logger *zerolog.Logger, db *gorm.DB, cfg config.Config) *API {
	return &API{logger, NewRepository(db), cfg}
}

func (a *API) SignUp(w http.ResponseWriter, r *http.Request) {
	payload := &SignUpInput{}
	json.DecodeJSON(*r, payload)

	validate := validator.New()
	err := validate.Struct(payload)
	if err != nil {
		json.ValidatorErrorJSON(w, err)
		a.logger.Error().Err(err).Msg(constants.DefaultJsonValidationErrorMessage)
		return
	}

	hashedPassword, err := util.HashPassword(payload.Password)
	if err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, "Error during password hashing", err)
		a.logger.Error().Err(err).Msg("Error during password hashing")
		return
	}

	newUser := User{
		Email:    payload.Email,
		Username: payload.Username,
		Password: hashedPassword,
	}

	err = a.repository.Create(&newUser)
	if err != nil {
		json.DatabaseErrorJSON(w, err)
		a.logger.Error().Err(err).Msg("Error during adding new user to database")
		return
	}

	a.logger.Info().Msgf("New user (%s) was successfully created", newUser.Username)
	json.WriteJSON(w, http.StatusCreated, constants.SuccessMessage, &GetUserResponse{
		ID:       newUser.ID,
		Username: newUser.Username,
		Email:    newUser.Email,
		Role:     newUser.Role,
		Verified: newUser.Verified,
	})
}

func (a *API) SignIn(w http.ResponseWriter, r *http.Request) {
	payload := &SignInInput{}
	json.DecodeJSON(*r, payload)

	validate := validator.New()
	err := validate.Struct(payload)
	if err != nil {
		json.ValidatorErrorJSON(w, err)
		a.logger.Error().Err(err).Msg(constants.DefaultJsonValidationErrorMessage)
		return
	}

	var user User
	if err = a.repository.FindOneByEmail(&user, payload.Email); err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, constants.UserNotFound, nil)
		a.logger.Error().Err(err).Msgf("User was not found during signing in: %s", payload.Email)
		return
	}

	if err = util.VerifyPassword(user.Password, payload.Password); err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, "incorrect password", nil)
		a.logger.Error().Err(err).Msgf("User (%s) failed to sign in due to incorrect password", user.ID)
		return
	}

	access_token, err := util.CreateToken(a.config.AccessTokenExpiresIn, user.ID, a.config.AccessTokenPrivateKey)
	if err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, "Error during access token generation", err)
		a.logger.Error().Err(err).Msg("Error during acccess token generation")
		return
	}

	refresh_token, err := util.CreateToken(a.config.RefreshTokenExpiresIn, user.ID, a.config.RefreshTokenPrivateKey)
	if err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, "Error during refresh token generation", err)
		a.logger.Error().Err(err).Msg("Error during refresh token generation")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     constants.AccessTokenCookie,
		Value:    access_token,
		MaxAge:   int(a.config.AccessTokenExpiresIn.Seconds()),
		Path:     "/",
		Domain:   a.config.HostDomain,
		Secure:   false,
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     constants.RefreshTokenCookie,
		Value:    refresh_token,
		MaxAge:   int(a.config.RefreshTokenExpiresIn.Seconds()),
		Path:     "/",
		Domain:   a.config.HostDomain,
		Secure:   false,
		HttpOnly: true,
	})

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, map[string]string{
		"access_token": access_token,
	})
}

func (a *API) RefreshAccessToken(w http.ResponseWriter, r *http.Request) {
	refresh_token_from_cookie, err := r.Cookie(constants.RefreshTokenCookie)
	if err != nil {
		json.ErrorJSON(w, http.StatusForbidden, "could not refresh token", nil)
		return
	}

	sub, err := util.ValidateToken(refresh_token_from_cookie.Value, a.config.RefreshTokenPublicKey)
	if err != nil {
		json.ErrorJSON(w, http.StatusForbidden, "could not refresh token", nil)
		return
	}

	user_id, ok := sub.(string)
	if !ok {
		json.ErrorJSON(w, http.StatusForbidden, "could not refresh token", nil)
		return
	}

	var user User
	if err = a.repository.FindOneById(&user, user_id); err != nil {
		json.ErrorJSON(w, http.StatusForbidden, "could not refresh token", nil)
		return
	}

	access_token, err := util.CreateToken(a.config.AccessTokenExpiresIn, user.ID, a.config.AccessTokenPrivateKey)
	if err != nil {
		json.ErrorJSON(w, http.StatusForbidden, "could not refresh token", nil)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     constants.AccessTokenCookie,
		Value:    access_token,
		MaxAge:   int(a.config.AccessTokenExpiresIn.Seconds()),
		Path:     "/",
		Domain:   a.config.HostDomain,
		Secure:   false,
		HttpOnly: true,
	})

	json.WriteJSON(w, http.StatusOK, "Logged in successfully", map[string]string{
		"access_token": access_token,
	})
}

func (a *API) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     constants.AccessTokenCookie,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Domain:   a.config.HostDomain,
		Secure:   false,
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     constants.RefreshTokenCookie,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Domain:   a.config.HostDomain,
		Secure:   false,
		HttpOnly: true,
	})

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil)
}
