package user

import (
	"collectihub/api/models"
	refreshtoken "collectihub/api/resources/refresh-token"
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
	logger         *zerolog.Logger
	userRepository *Repository
	config         config.Config

	refreshTokenRepository *refreshtoken.Repository
}

func New(logger *zerolog.Logger, db *gorm.DB, cfg config.Config) *API {
	return &API{logger, NewRepository(db), cfg, refreshtoken.NewRepository(db)}
}

func (a *API) SignUp(w http.ResponseWriter, r *http.Request) {
	payload := &models.SignUpInput{}
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

	newUser := models.User{
		Email:    payload.Email,
		Username: payload.Username,
		Password: hashedPassword,
	}

	err = a.userRepository.Create(&newUser)
	if err != nil {
		json.DatabaseErrorJSON(w, err)
		a.logger.Error().Err(err).Msg("Error during adding new user to database")
		return
	}

	a.logger.Info().Msgf("New user (%s) was successfully created", newUser.Username)
	json.WriteJSON(w, http.StatusCreated, constants.SuccessMessage, &models.GetUserResponse{
		ID:       newUser.ID,
		Username: newUser.Username,
		Email:    newUser.Email,
		Role:     newUser.Role,
		Verified: newUser.Verified,
	})
}

func (a *API) SignIn(w http.ResponseWriter, r *http.Request) {
	payload := &models.SignInInput{}
	json.DecodeJSON(*r, payload)

	validate := validator.New()
	err := validate.Struct(payload)
	if err != nil {
		json.ValidatorErrorJSON(w, err)
		a.logger.Error().Err(err).Msg(constants.DefaultJsonValidationErrorMessage)
		return
	}

	var user models.User
	if err = a.userRepository.FindOneByEmail(&user, payload.Email); err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, constants.UserNotFound, nil)
		a.logger.Error().Err(err).Msgf("User was not found during signing in: %s", payload.Email)
		return
	}

	if err = util.VerifyPassword(user.Password, payload.Password); err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, "incorrect password", nil)
		a.logger.Error().Err(err).Msgf("User (%s) failed to sign in due to incorrect password", user.ID)
		return
	}

	accessToken, err := util.CreateToken(a.config.AccessTokenExpiresIn, user.ID, a.config.AccessTokenPrivateKey)
	if err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, "Error during access token generation", err)
		a.logger.Error().Err(err).Msg("Error during acccess token generation")
		return
	}

	refreshToken, err := util.CreateToken(a.config.RefreshTokenExpiresIn, user.ID, a.config.RefreshTokenPrivateKey)
	if err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, "Error during refresh token generation", err)
		a.logger.Error().Err(err).Msg("Error during refresh token generation")
		return
	}

	a.refreshTokenRepository.Create(&models.RefreshToken{
		Token: refreshToken,
		User:  user,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     constants.AccessTokenCookie,
		Value:    accessToken,
		MaxAge:   int(a.config.AccessTokenExpiresIn.Seconds()),
		Path:     "/",
		Domain:   a.config.HostDomain,
		Secure:   false,
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     constants.RefreshTokenCookie,
		Value:    refreshToken,
		MaxAge:   int(a.config.RefreshTokenExpiresIn.Seconds()),
		Path:     "/",
		Domain:   a.config.HostDomain,
		Secure:   false,
		HttpOnly: true,
	})

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, map[string]string{
		"access_token": accessToken,
	})
}

func (a *API) RefreshAccessToken(w http.ResponseWriter, r *http.Request) {
	refreshTokenFromCookie, err := r.Cookie(constants.RefreshTokenCookie)
	if err != nil {
		json.ErrorJSON(w, http.StatusForbidden, "could not refresh token", nil)
		return
	}

	sub, err := util.ValidateToken(refreshTokenFromCookie.Value, a.config.RefreshTokenPublicKey)
	if err != nil {
		json.ErrorJSON(w, http.StatusForbidden, "could not refresh token", nil)
		return
	}

	userID, ok := sub.(string)
	if !ok {
		json.ErrorJSON(w, http.StatusForbidden, "could not refresh token", nil)
		return
	}

	var user models.User
	if err = a.userRepository.FindOneById(&user, userID); err != nil {
		json.ErrorJSON(w, http.StatusForbidden, "could not refresh token", nil)
		return
	}

	var refreshTokenFromDB models.RefreshToken
	if err = a.refreshTokenRepository.FindOne(&refreshTokenFromDB, &models.RefreshToken{Token: refreshTokenFromCookie.Value, UserID: user.ID}); err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, "could not find token in db", nil)
		return
	}

	// If token was already used before, it means someone suspicious is trying to
	// retrieve access token. In this case we remove all refresh tokens for the
	// user. It'll make anyone, who whenever had access to account, log in again
	// when access token expires.
	if refreshTokenFromDB.Used {
		if err = a.refreshTokenRepository.DeleteAllByUser(user.ID); err != nil {
			json.ErrorJSON(w, http.StatusBadRequest, "database error", nil)
			return
		}

		json.ErrorJSON(w, http.StatusForbidden, "malicious activity detected, token were wiped from database, you need to log in again", nil)
		return
	}

	// If token was not used before, we mark it as used and give the user new
	// set of tokens.
	a.logger.Info().Msgf("%s", refreshTokenFromDB.ID)
	if err = a.refreshTokenRepository.Update(&refreshTokenFromDB, &models.RefreshToken{Used: true}); err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, "database error", nil)
		return
	}

	access_token, err := util.CreateToken(a.config.AccessTokenExpiresIn, user.ID, a.config.AccessTokenPrivateKey)
	if err != nil {
		json.ErrorJSON(w, http.StatusForbidden, "could not refresh token", nil)
		return
	}

	refreshToken, err := util.CreateToken(a.config.RefreshTokenExpiresIn, user.ID, a.config.RefreshTokenPrivateKey)
	if err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, "Error during refresh token generation", err)
		a.logger.Error().Err(err).Msg("Error during refresh token generation")
		return
	}

	a.refreshTokenRepository.Create(&models.RefreshToken{
		Token: refreshToken,
		User:  user,
	})

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
		Value:    refreshToken,
		MaxAge:   int(a.config.RefreshTokenExpiresIn.Seconds()),
		Path:     "/",
		Domain:   a.config.HostDomain,
		Secure:   false,
		HttpOnly: true,
	})

	json.WriteJSON(w, http.StatusOK, "Tokens were refreshed successfully", map[string]string{
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

func (a *API) GetMe(w http.ResponseWriter, r *http.Request) {
	user, err := models.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, http.StatusUnauthorized, "not authed", nil)
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, models.GetUserResponse{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		Role:     user.Role,
		Verified: user.Verified,
	})
}
