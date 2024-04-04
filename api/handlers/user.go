package user

import (
	"collectihub/api/models"
	"collectihub/internal/auth"
	"collectihub/internal/config"
	"collectihub/internal/constants"
	"collectihub/internal/database"
	"collectihub/internal/mailer"
	"collectihub/internal/util"
	"collectihub/internal/util/json"
	"collectihub/types"
	"context"
	jsonLib "encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

type API struct {
	logger                 *zerolog.Logger
	userRepository         *database.Repository[models.User]
	refreshTokenRepository *database.Repository[models.RefreshToken]
	verificationRepository *database.Repository[models.VerificationCode]
	config                 config.Config
	oauth                  auth.OAuthConfig
	mailer                 *mailer.Mailer
}

func New(logger *zerolog.Logger, db *gorm.DB, cfg config.Config) *API {
	return &API{
		logger,
		database.NewRepository[models.User](db),
		database.NewRepository[models.RefreshToken](db),
		database.NewRepository[models.VerificationCode](db),
		cfg,
		auth.NewOAuth(cfg),
		mailer.New(cfg, logger),
	}
}

// SignUp godoc
//
//	@Summary		Sign up
//	@Description	Serves as registration endpoints for new users creation.
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		models.SignUpRequest	true	"sign up body"
//	@Success		201		{object}	types.SuccessResponse{data=models.GetUserResponse}
//	@Failure		400		{object}	types.ErrorResponse "Validation error; Password hashing error; Unexpected database error;"
//	@Failure		409		{object}	types.ErrorResponse "Username of email in from request is already taken"
//	@Router			/auth/register [post]
func (a *API) SignUp(w http.ResponseWriter, r *http.Request) {
	payload := &models.SignUpRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		return
	}

	hashedPassword, err := util.HashPassword(payload.Password)
	if err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, constants.PasswordHashingErrorMessage, err)
		a.logger.Error().Err(err).Msgf("Error during password hashing for user (%s)", payload.Email)
		return
	}

	newUser := models.User{
		Email:    payload.Email,
		Username: payload.Username,
		Password: hashedPassword,
	}

	if err = a.userRepository.Create(&newUser); err != nil {
		json.DatabaseErrorJSON(w, err)
		a.logger.Error().Err(err).Msgf("Database error during user insertion (%v)", newUser)
		return
	}

	// Sending verification email
	expiration := time.Now().Add(time.Minute * 5)
	emailVerification := &models.VerificationCode{
		UserID:  newUser.ID,
		Expires: expiration,
		Type:    types.EmailVerificationType,
		Code:    util.GenerateRandomNumberString(constants.EmailVerificationCodeLength),
	}

	if err = a.verificationRepository.Create(emailVerification); err != nil {
		json.DatabaseErrorJSON(w, err)
		return
	}

	go a.mailer.SendAccountVerificationEmail(newUser.Email, emailVerification.Code)

	a.logger.Info().Msgf("New user (%s) was successfully created", newUser.Username)
	json.WriteJSON(w, http.StatusCreated, constants.SuccessMessage, &models.GetUserResponse{
		ID:       newUser.ID,
		Username: newUser.Username,
		Email:    newUser.Email,
		Role:     newUser.Role,
		Verified: newUser.Verified,
	})
}

func (a *API) GoogleLogIn(w http.ResponseWriter, r *http.Request) {
	url := a.oauth.GoogleLoginConfig.AuthCodeURL(a.config.GoogleState)

	http.Redirect(w, r, url, http.StatusSeeOther)
}

func (a *API) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	if state := r.URL.Query().Get("state"); state != a.config.GoogleState {
		json.ErrorJSON(w, http.StatusBadRequest, constants.IncorrectOAuthStateErrorMessage, nil)
		return
	}

	code := r.URL.Query().Get("code")

	token, err := a.oauth.GoogleLoginConfig.Exchange(context.Background(), code)
	if err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, constants.OAuthExchangeErrorMessage, nil)
		return
	}

	res, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, constants.OAuthUserDataFetchErrorMessage, nil)
		return
	}

	userData, err := io.ReadAll(res.Body)
	if err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, constants.UserDataReadingErrorMessage, nil)
		return
	}

	data := &models.GoogleUserData{}
	if err = jsonLib.Unmarshal(userData, &data); err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, constants.JsonValidationErrorMessage, nil)
		return
	}

	var user models.User
	if err = a.userRepository.FindOne(&user, &models.User{OAuthProvider: "google", OAuthIndentity: data.Email}); err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			json.DatabaseErrorJSON(w, err)
			return
		}
	}

	// register user if account does not exist yet
	if errors.Is(err, gorm.ErrRecordNotFound) {
		user := models.User{
			OAuthProvider:  "google",
			OAuthIndentity: data.Email,
			Username:       util.GenerateRandomString(10),
			Verified:       true,
		}

		if err = a.userRepository.Create(&user); err != nil {
			json.DatabaseErrorJSON(w, err)
			return
		}
	}

	// Generate and return token pair for logged in / registered user
	a.generateUserTokenPair(w, user, true, true)
}

func (a *API) SignIn(w http.ResponseWriter, r *http.Request) {
	payload := &models.SignInRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		return
	}

	var user models.User
	if err := a.userRepository.FindOne(&user, &models.User{Email: payload.Email}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			json.ErrorJSON(w, http.StatusNotFound, constants.NotFoundMessage("User"), nil)
		} else {
			json.ErrorJSON(w, http.StatusBadRequest, constants.DatabaseErrorMessage, nil)
		}

		return
	}

	if err := util.VerifyPassword(user.Password, payload.Password); err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, constants.IncorrectPasswordErrorMessage, nil)
		return
	}

	a.generateUserTokenPair(w, user, true, true)
}

func (a *API) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	user, err := models.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, http.StatusUnauthorized, constants.NotLoggedInErrorMessage, nil)
		return
	}

	payload := &models.AccountVerificationRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		return
	}

	if user.Verified {
		json.ErrorJSON(w, http.StatusBadRequest, constants.AccountIsAlreadyVerified, nil)
		return
	}

	err = a.verificationRepository.FindOne(&models.VerificationCode{}, &models.VerificationCode{
		UserID: user.ID,
		Type:   types.EmailVerificationType,
		Code:   payload.Code,
	})
	if err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, "Wrong account verification code", nil)
		return
	}

	if err = a.userRepository.Update(&models.User{ID: user.ID}, &models.User{Verified: true}); err != nil {
		json.DatabaseErrorJSON(w, err)
		return
	}

	if err = a.verificationRepository.Delete(&models.VerificationCode{}, &models.VerificationCode{UserID: user.ID}); err != nil {
		json.DatabaseErrorJSON(w, err)
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil)
}

func (a *API) ResendEmailVerification(w http.ResponseWriter, r *http.Request) {
	user, err := models.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, http.StatusUnauthorized, constants.NotLoggedInErrorMessage, nil)
		return
	}

	if user.Verified {
		json.ErrorJSON(w, http.StatusBadRequest, constants.AccountIsAlreadyVerified, nil)
		return
	}

	expiration := time.Now().Add(time.Minute * 5)
	emailVerification := &models.VerificationCode{
		UserID:  user.ID,
		Expires: expiration,
		Type:    types.EmailVerificationType,
		Code:    util.GenerateRandomNumberString(constants.EmailVerificationCodeLength),
	}

	if err = a.verificationRepository.Create(emailVerification); err != nil {
		json.DatabaseErrorJSON(w, err)
		return
	}

	go a.mailer.SendAccountVerificationEmail(user.Email, emailVerification.Code)

	json.WriteJSON(w, http.StatusOK, "New messages was successfully sent", nil)
}

func (a *API) SendPasswordResetMail(w http.ResponseWriter, r *http.Request) {
	payload := &models.SendPasswordResetMailRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		return
	}

	var user models.User
	err := a.userRepository.FindOne(&user, &models.User{Email: payload.Email})
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		json.DatabaseErrorJSON(w, err)
		return
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		json.ErrorJSON(w, http.StatusNotFound, constants.NotFoundMessage("User"), nil)
		return
	}

	expiration := time.Now().Add(time.Minute * 5)
	passwordReset := &models.VerificationCode{
		UserID:  user.ID,
		Expires: expiration,
		Type:    types.PasswordResetType,
		Code:    util.GenerateRandomNumberString(constants.PasswordresetVerificationCodeLength),
	}

	if err := a.verificationRepository.Create(passwordReset); err != nil {
		json.DatabaseErrorJSON(w, err)
		return
	}

	go a.mailer.SendPasswordResetVerificationEmail(user.Email, passwordReset.Code)

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil)
}

func (a *API) PasswordReset(w http.ResponseWriter, r *http.Request) {
	payload := &models.PasswordResetRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		return
	}

	var user models.User
	err := a.userRepository.FindOne(&user, &models.User{Email: payload.Email})
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		json.DatabaseErrorJSON(w, err)
		return
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		json.ErrorJSON(w, http.StatusNotFound, constants.NotFoundMessage("User"), nil)
		return
	}

	var passwordReset models.VerificationCode
	if err := a.verificationRepository.FindOne(
		&passwordReset,
		&models.VerificationCode{UserID: user.ID, Type: types.PasswordResetType, Code: payload.Code},
	); err != nil {
		json.DatabaseErrorJSON(w, err)
		return
	}

	hashedPassword, err := util.HashPassword(payload.NewPassword)
	if err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, constants.PasswordHashingErrorMessage, nil)
		return
	}

	err = a.userRepository.Update(&models.User{ID: user.ID}, &models.User{Password: hashedPassword})
	if err != nil {
		json.DatabaseErrorJSON(w, err)
		return
	}

	err = a.verificationRepository.Delete(
		&models.VerificationCode{},
		&models.VerificationCode{UserID: user.ID, Type: types.PasswordResetType},
	)
	if err != nil {
		json.DatabaseErrorJSON(w, err)
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil)
}

func (a *API) RefreshAccessToken(w http.ResponseWriter, r *http.Request) {
	refreshTokenFromCookie, err := r.Cookie(constants.RefreshTokenCookie)
	if err != nil {
		json.ErrorJSON(w, http.StatusForbidden, constants.TokenProcessingErrorMessage, nil)
		return
	}

	sub, err := util.ValidateToken(refreshTokenFromCookie.Value, a.config.RefreshTokenPublicKey)
	if err != nil {
		json.ErrorJSON(w, http.StatusForbidden, constants.TokenProcessingErrorMessage, nil)
		return
	}

	userID, ok := sub.(string)
	if !ok {
		json.ErrorJSON(w, http.StatusForbidden, constants.TokenProcessingErrorMessage, nil)
		return
	}

	var user models.User
	if err = a.userRepository.FindOneById(&user, userID); err != nil {
		json.ErrorJSON(w, http.StatusForbidden, constants.NotFoundMessage("User"), nil)
		return
	}

	var refreshTokenFromDB models.RefreshToken
	if err = a.refreshTokenRepository.FindOne(&refreshTokenFromDB, &models.RefreshToken{Token: refreshTokenFromCookie.Value, UserID: user.ID}); err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, constants.NotFoundMessage("Token"), nil)
		return
	}

	// If token was already used before, it means someone suspicious is trying to
	// retrieve access token. In this case we remove all refresh tokens for the
	// user. It'll make anyone, who whenever had access to account, log in again
	// when access token expires.
	if refreshTokenFromDB.Used {
		if err = a.refreshTokenRepository.Delete(&models.RefreshToken{}, &models.RefreshToken{UserID: user.ID}); err != nil {
			json.ErrorJSON(w, http.StatusBadRequest, constants.DatabaseErrorMessage, nil)
			return
		}

		json.ErrorJSON(w, http.StatusForbidden, constants.MaliciousActivityErrorMessage, nil)
		return
	}

	// If token was not used before, we mark it as used and give the user new
	// set of tokens.
	if err = a.refreshTokenRepository.Update(&refreshTokenFromDB, &models.RefreshToken{Used: true}); err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, constants.DatabaseErrorMessage, nil)
		return
	}

	a.generateUserTokenPair(w, user, true, true)
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
		json.ErrorJSON(w, http.StatusUnauthorized, constants.NotLoggedInErrorMessage, nil)
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

func (a *API) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user, err := models.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, http.StatusUnauthorized, constants.NotLoggedInErrorMessage, nil)
		return
	}

	payload := &models.ChangePasswordRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		return
	}

	if err = util.VerifyPassword(user.Password, payload.OldPassword); err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, constants.IncorrectPasswordErrorMessage, nil)
		return
	}

	hashedPassword, err := util.HashPassword(payload.NewPassword)
	if err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, constants.PasswordHashingErrorMessage, nil)
		return
	}

	if err = a.userRepository.Update(&models.User{ID: user.ID}, &models.User{Password: hashedPassword}); err != nil {
		json.DatabaseErrorJSON(w, err)
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil)
}

func (a *API) UpdateUser(w http.ResponseWriter, r *http.Request) {
	user, err := models.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, http.StatusUnauthorized, constants.NotLoggedInErrorMessage, nil)
		return
	}

	payload := &models.UpdateUserRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		return
	}

	if err = a.userRepository.Update(&models.User{ID: user.ID}, &models.User{Username: payload.Username, Email: payload.Email}); err != nil {
		json.DatabaseErrorJSON(w, err)
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil)
}

func (a *API) DeleteUser(w http.ResponseWriter, r *http.Request) {
	user, err := models.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, http.StatusUnauthorized, constants.NotLoggedInErrorMessage, nil)
		return
	}

	if err = a.userRepository.DeleteOneById(&models.User{}, user.ID); err != nil {
		json.DatabaseErrorJSON(w, err)
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil)
}

func (a *API) generateUserTokenPair(w http.ResponseWriter, user models.User, setCookies bool, writeResponse bool) {
	accessToken, err := util.CreateToken(a.config.AccessTokenExpiresIn, user, a.config.AccessTokenPrivateKey)
	if err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, constants.TokenProcessingErrorMessage, err)
		return
	}

	refreshToken, err := util.CreateToken(a.config.RefreshTokenExpiresIn, user, a.config.RefreshTokenPrivateKey)
	if err != nil {
		json.ErrorJSON(w, http.StatusBadRequest, constants.TokenProcessingErrorMessage, err)
		return
	}

	a.refreshTokenRepository.Create(&models.RefreshToken{
		Token: refreshToken,
		User:  user,
	})

	if setCookies {
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
	}

	if writeResponse {
		json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, models.AccessTokenResponse{AccessToken: accessToken})
	}
}
