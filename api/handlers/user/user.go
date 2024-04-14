package user

import (
	"collectihub/api/models"
	"collectihub/internal/auth"
	"collectihub/internal/common"
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
//	@Description	Serves as a registration endpoint for new users creation. After registration email verification is sent.
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		models.SignUpRequest	true	"sign up body"
//	@Success		201		{object}	types.SuccessResponse{data=models.GetUserResponse}
//	@Failure		400		{object}	types.ErrorResponse	"Password hashing error; Unexpected database error;"
//	@Failure		422		{object}	types.ErrorResponse	"Validation error"
//	@Failure		409		{object}	types.ErrorResponse	"Username of email in from request is already taken"
//	@Router			/auth/register [post]
func (a *API) SignUp(w http.ResponseWriter, r *http.Request) {
	payload := &models.SignUpRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewValidationError(err, payload))
		return
	}

	hashedPassword, err := util.HashPassword(*payload.Password)
	if err != nil {
		json.ErrorJSON(w, constants.PasswordHashingErrorMessage, types.HttpError{Status: http.StatusBadRequest, Err: err})
		a.logger.Error().Err(err).Msgf("Error during password hashing for user (%s)", *payload.Email)
		return
	}

	newUser := models.User{
		Email:    payload.Email,
		Username: payload.Username,
		Password: &hashedPassword,
	}

	// Begin transaction
	tx := a.userRepository.DB.Begin()

	if err = a.userRepository.Create(&newUser, tx); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		a.logger.Error().Err(err).Msgf("Database error during user insertion (%v)", newUser)
		return
	}

	// Sending verification email
	expiration := time.Now().Add(time.Minute * 5)
	code := util.GenerateRandomNumberString(constants.EmailVerificationCodeLength)
	emailVerification := &models.VerificationCode{
		UserID:  newUser.ID,
		Expires: expiration,
		Type:    types.EmailVerificationType,
		Code:    &code,
	}

	if err = a.verificationRepository.Create(emailVerification, tx); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	go a.mailer.SendAccountVerificationEmail(*newUser.Email, *emailVerification.Code)

	// Commit transaction
	tx.Commit()

	a.logger.Info().Msgf("New user (%s) was successfully created", *newUser.Username)
	json.WriteJSON(w, http.StatusCreated, constants.SuccessMessage, &models.GetUserResponse{
		ID:       newUser.ID,
		Username: newUser.Username,
		Email:    newUser.Email,
		Role:     newUser.Role,
		Verified: newUser.Verified,
	})
}

// GoogleLogin godoc
//
//	@Summary		Google login
//	@Description	Used to login/register with Google account, user will be redirected to Google's OAuth page.
//	@Tags			auth
//	@Success		303 "Redirected"
//	@Router			/auth/google/login [get]
func (a *API) GoogleLogIn(w http.ResponseWriter, r *http.Request) {
	url := a.oauth.GoogleLoginConfig.AuthCodeURL(a.config.GoogleState)

	http.Redirect(w, r, url, http.StatusSeeOther)
}

// GoogleCallback godoc
//
//	@Summary		Google callback
//	@Description	This endpoint will be automatically trigerred by Google with related credentials. If user with this credetials doesn't exist in database, server will automatically create a new user (with randomized username) and return auth token pair. Otherwise it will login user with auth token pair.
//	@Tags			auth
//	@Produce		json
//	@Success		200	{object}	types.SuccessResponse{data=models.AccessTokenResponse}
//	@Failure		400	{object}	types.ErrorResponse	"Incorrect OAuth state; OAuth exchange error; OAuth user fetching error; UserData reading error; Unexpected database error;"
//	@Failure		422	{object}	types.ErrorResponse	"Validation error"
//	@Router			/auth/google/callback [get]
func (a *API) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	if state := r.URL.Query().Get("state"); state != a.config.GoogleState {
		json.ErrorJSON(w, constants.IncorrectOAuthStateErrorMessage, types.HttpError{Status: http.StatusBadRequest, Err: nil})
		return
	}

	code := r.URL.Query().Get("code")

	token, err := a.oauth.GoogleLoginConfig.Exchange(context.Background(), code)
	if err != nil {
		json.ErrorJSON(w, constants.OAuthExchangeErrorMessage, types.HttpError{Status: http.StatusBadRequest, Err: nil})
		return
	}

	res, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		json.ErrorJSON(w, constants.OAuthUserDataFetchErrorMessage, types.HttpError{Status: http.StatusBadRequest, Err: nil})
		return
	}

	userData, err := io.ReadAll(res.Body)
	if err != nil {
		json.ErrorJSON(w, constants.UserDataReadingErrorMessage, types.HttpError{Status: http.StatusBadRequest, Err: nil})
		return
	}

	data := &models.GoogleUserData{}
	if err = jsonLib.Unmarshal(userData, &data); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, types.HttpError{Status: http.StatusUnprocessableEntity, Err: nil})
		return
	}

	var user models.User
	if err = a.userRepository.FindOne(&user, &models.User{
		OAuthProvider:  util.Pointer("google"),
		OAuthIndentity: data.Email,
	}); err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
			return
		}
	}

	// register user if account does not exist yet
	if errors.Is(err, gorm.ErrRecordNotFound) {
		user := models.User{
			OAuthProvider:  util.Pointer("google"),
			OAuthIndentity: data.Email,
			Username:       util.Pointer(util.GenerateRandomString(10)),
			Verified:       util.Pointer(true),
		}

		if err = a.userRepository.Create(&user, nil); err != nil {
			json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
			return
		}
	}

	// Generate and return token pair for logged in / registered user
	a.generateUserTokenPair(w, user, true, true)
}

// SignIn godoc
//
//	@Summary		Login
//	@Description	Used to login users registered with email. Refresh token is saved in secured cookies and can be used to refresh token pair (refresh and access token).
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		models.SignInRequest	true	"sign in body"
//	@Success		200		{object}	types.SuccessResponse{data=models.AccessTokenResponse}
//	@Failure		400		{object}	types.ErrorResponse	"Unexpected database error; Incorrect password;"
//	@Failure		404		{object}	types.ErrorResponse	"User not found"
//	@Failure		422		{object}	types.ErrorResponse	"Validation error"
//	@Router			/auth/login [post]
func (a *API) SignIn(w http.ResponseWriter, r *http.Request) {
	payload := &models.SignInRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewValidationError(err, payload))
		return
	}

	var user models.User
	if err := a.userRepository.FindOne(&user, &models.User{Email: payload.Email}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			json.ErrorJSON(w, constants.NotFoundMessage("User"), types.HttpError{Status: http.StatusNotFound, Err: nil})
		} else {
			json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		}

		return
	}

	if err := util.VerifyPassword(*user.Password, *payload.Password); err != nil {
		json.ErrorJSON(w, constants.IncorrectPasswordErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
		return
	}

	a.generateUserTokenPair(w, user, true, true)
}

// VerifyEmail godoc
//
//	@Summary		Verify email
//	@Description	Helps to verify account using the code sent to user's email.
//	@Tags			users
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		models.AccountVerificationRequest	true	"account verification body"
//	@Success		200		{object}	types.SuccessResponse
//	@Failure		400		{object}	types.ErrorResponse	"User is already verified; Incorrect verification code; Unexpected database error;"
//	@Failure		401		{object}	types.ErrorResponse	"User is not logged in"
//	@Failure		422		{object}	types.ErrorResponse	"Validation error"
//	@Router			/users/verify-email [post]
func (a *API) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	user, err := models.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, constants.NotLoggedInErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
		return
	}

	payload := &models.AccountVerificationRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewValidationError(err, payload))
		return
	}

	if *user.Verified {
		json.ErrorJSON(w, constants.AccountIsAlreadyVerified, types.HttpError{Status: http.StatusBadRequest, Err: nil})
		return
	}

	err = a.verificationRepository.FindOne(&models.VerificationCode{}, &models.VerificationCode{
		UserID: user.ID,
		Type:   types.EmailVerificationType,
		Code:   payload.Code,
	})
	if err != nil {
		json.ErrorJSON(w, constants.WrongVerificationCodeErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
		return
	}

	// Begin transaction
	tx := a.userRepository.DB.Begin()

	if err = a.userRepository.Update(&models.User{ID: user.ID}, &models.User{Verified: util.Pointer(true)}, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	if err = a.verificationRepository.Delete(&models.VerificationCode{}, &models.VerificationCode{UserID: user.ID}, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	// Commit transaction
	tx.Commit()

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil)
}

// ResendEmailVerification godoc
//
//	@Summary		Resend email verification
//	@Description	Used to resend email verification in case of sending error or wrong email.
//	@Tags			users
//	@Security		BearerAuth
//	@Produce		json
//	@Success		200	{object}	types.SuccessResponse	"new message successfully sent"
//	@Failure		400	{object}	types.ErrorResponse		"User is already verified; Unexpected database error;"
//	@Failure		401	{object}	types.ErrorResponse		"User is not logged in"
//	@Router			/users/resend-verification-email [post]
func (a *API) ResendEmailVerification(w http.ResponseWriter, r *http.Request) {
	user, err := models.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, constants.NotLoggedInErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
		return
	}

	if *user.Verified {
		json.ErrorJSON(w, constants.AccountIsAlreadyVerified, types.HttpError{Status: http.StatusBadRequest, Err: nil})
		return
	}

	expiration := time.Now().Add(time.Minute * 5)
	code := util.GenerateRandomNumberString(constants.EmailVerificationCodeLength)
	emailVerification := &models.VerificationCode{
		UserID:  user.ID,
		Expires: expiration,
		Type:    types.EmailVerificationType,
		Code:    &code,
	}

	if err = a.verificationRepository.Create(emailVerification, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	go a.mailer.SendAccountVerificationEmail(*user.Email, *emailVerification.Code)

	json.WriteJSON(w, http.StatusOK, "New messages was successfully sent", nil)
}

// SendPasswordResetEmail godoc
//
//	@Summary		Send password reset email
//	@Description	Helps to send password reset verification code to user's email. It can be used to reset password on other endpoint.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Param			body	body		models.SendPasswordResetEmailRequest	true	"send password reset email body"
//	@Success		200		{object}	types.SuccessResponse					"password email reset was successfully sent"
//	@Failure		400		{object}	types.ErrorResponse						"Unexpected database error"
//	@Failure		404		{object}	types.ErrorResponse						"User not found"
//	@Failure		422		{object}	types.ErrorResponse						"Validation error"
//	@Router			/users/request-password-reset [post]
func (a *API) SendPasswordResetEmail(w http.ResponseWriter, r *http.Request) {
	payload := &models.SendPasswordResetEmailRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewValidationError(err, payload))
		return
	}

	var user models.User
	err := a.userRepository.FindOne(&user, &models.User{Email: payload.Email})
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		json.ErrorJSON(w, constants.NotFoundMessage("User"), types.HttpError{Status: http.StatusNotFound, Err: nil})
		return
	}

	expiration := time.Now().Add(time.Minute * 5)
	code := util.GenerateRandomNumberString(constants.PasswordresetVerificationCodeLength)
	passwordReset := &models.VerificationCode{
		UserID:  user.ID,
		Expires: expiration,
		Type:    types.PasswordResetType,
		Code:    &code,
	}

	if err := a.verificationRepository.Create(passwordReset, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	go a.mailer.SendPasswordResetVerificationEmail(*user.Email, *passwordReset.Code)

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil)
}

// PasswordReset godoc
//
//	@Summary		Password reset verification
//	@Description	Used to update user password with code received from email.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Param			body	body		models.PasswordResetRequest	true	"password reset body"
//	@Success		200		{object}	types.SuccessResponse
//	@Failure		400		{object}	types.ErrorResponse	"Unexpected database error; Password hashing error;"
//	@Failure		404		{object}	types.ErrorResponse	"User not found"
//	@Failure		422		{object}	types.ErrorResponse	"Validation error"
//	@Router			/users/verify-password-reset [post]
func (a *API) PasswordReset(w http.ResponseWriter, r *http.Request) {
	payload := &models.PasswordResetRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewValidationError(err, payload))
		return
	}

	var user models.User
	err := a.userRepository.FindOne(&user, &models.User{Email: payload.Email})
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		json.ErrorJSON(w, constants.NotFoundMessage("User"), types.HttpError{Status: http.StatusNotFound, Err: nil})
		return
	}

	var passwordReset models.VerificationCode
	if err := a.verificationRepository.FindOne(
		&passwordReset,
		&models.VerificationCode{UserID: user.ID, Type: types.PasswordResetType, Code: payload.Code},
	); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	hashedPassword, err := util.HashPassword(*payload.NewPassword)
	if err != nil {
		json.ErrorJSON(w, constants.PasswordHashingErrorMessage, types.HttpError{Status: http.StatusBadRequest, Err: nil})
		return
	}

	// Begin transaction
	tx := a.userRepository.DB.Begin()

	err = a.userRepository.Update(&models.User{ID: user.ID}, &models.User{Password: &hashedPassword}, tx)
	if err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	err = a.verificationRepository.Delete(
		&models.VerificationCode{},
		&models.VerificationCode{UserID: user.ID, Type: types.PasswordResetType},
		tx,
	)
	if err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	// Commit transaction
	tx.Commit()

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil)
}

// RefreshAccessToken godoc
//
//	@Summary		Refresh access token
//	@Description	Helps to refresh access token. Returns new access token and store refresh token in cookies. Refresh tokens are saved in database and their usage is tracked. So if refresh token is used second time, all user's refresh tokens will be wiped. This deletion will force all user's authenticated devices to log in again when access token expires.
//	@Tags			auth
//	@Produce		json
//	@Success		200	{object}	types.SuccessResponse{data=models.AccessTokenResponse}
//	@Failure		400	{object}	types.ErrorResponse	"Unexpected database error"
//	@Failure		403	{object}	types.ErrorResponse	"Token processing error; Malicious activity detected;"
//	@Failure		404	{object}	types.ErrorResponse	"User not found; Token not found;"
//	@Router			/auth/refresh-token [post]
func (a *API) RefreshAccessToken(w http.ResponseWriter, r *http.Request) {
	refreshTokenFromCookie, err := r.Cookie(constants.RefreshTokenCookie)
	if err != nil {
		json.ErrorJSON(w, constants.TokenProcessingErrorMessage, types.HttpError{Status: http.StatusForbidden, Err: nil})
		return
	}

	sub, err := util.ValidateToken(refreshTokenFromCookie.Value, a.config.RefreshTokenPublicKey)
	if err != nil {
		json.ErrorJSON(w, constants.TokenProcessingErrorMessage, types.HttpError{Status: http.StatusForbidden, Err: nil})
		return
	}

	userID, ok := sub.(string)
	if !ok {
		json.ErrorJSON(w, constants.TokenProcessingErrorMessage, types.HttpError{Status: http.StatusForbidden, Err: nil})
		return
	}

	var user models.User
	if err = a.userRepository.FindOneById(&user, userID); err != nil {
		json.ErrorJSON(w, constants.NotFoundMessage("User"), types.HttpError{Status: http.StatusNotFound, Err: nil})
		return
	}

	var refreshTokenFromDB models.RefreshToken
	if err = a.refreshTokenRepository.FindOne(&refreshTokenFromDB, &models.RefreshToken{Token: refreshTokenFromCookie.Value, UserID: user.ID}); err != nil {
		json.ErrorJSON(w, constants.NotFoundMessage("Token"), types.HttpError{Status: http.StatusNotFound, Err: nil})
		return
	}

	// If token was already used before, it means someone suspicious is trying to
	// retrieve access token. In this case we remove all refresh tokens for the
	// user. It'll make anyone, who whenever had access to account, log in again
	// when access token expires.
	if refreshTokenFromDB.Used {
		if err = a.refreshTokenRepository.Delete(&models.RefreshToken{}, &models.RefreshToken{UserID: user.ID}, nil); err != nil {
			json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
			return
		}

		json.ErrorJSON(w, constants.MaliciousActivityErrorMessage, types.HttpError{Status: http.StatusForbidden, Err: nil})
		return
	}

	// If token was not used before, we mark it as used and give the user new
	// set of tokens.
	if err = a.refreshTokenRepository.Update(&refreshTokenFromDB, &models.RefreshToken{Used: true}, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	a.generateUserTokenPair(w, user, true, true)
}

// Logout godoc
//
//	@Summary		Logout
//	@Description	Helps user to log out. This endpoint will trigger auth cookies expiration.
//	@Tags			auth
//	@Produce		json
//	@Success		200	{object}	types.SuccessResponse
//	@Router			/auth/logout [post]
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

// GetMe godoc
//
//	@Summary		Get info about user
//	@Description	Helps to retrieve data of authenticated user
//	@Tags			users
//	@Security		BearerAuth
//	@Produce		json
//	@Success		200	{object}	types.SuccessResponse{data=models.GetUserResponse}
//	@Failure		401	{object}	types.ErrorResponse	"User is not logged in"
//	@Router			/users/me [get]
func (a *API) GetMe(w http.ResponseWriter, r *http.Request) {
	user, err := models.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, constants.NotLoggedInErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
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

// ChangePassword godoc
//
//	@Summary		Change password
//	@Description	Helps to change password of authenticated user.
//	@Tags			users
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		models.ChangePasswordRequest	true	"change password body"
//	@Success		200		{object}	types.SuccessResponse
//	@Failure		400		{object}	types.ErrorResponse	"Incorrect old password; Password hashing error; Unexpected database error;"
//	@Failure		401		{object}	types.ErrorResponse	"User is not logged in"
//	@Failure		422		{object}	types.ErrorResponse	"Validation error"
//	@Router			/users/change-password [patch]
func (a *API) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user, err := models.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, constants.NotLoggedInErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
		return
	}

	payload := &models.ChangePasswordRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewValidationError(err, payload))
		return
	}

	if err = util.VerifyPassword(*user.Password, *payload.OldPassword); err != nil {
		json.ErrorJSON(w, constants.IncorrectPasswordErrorMessage, types.HttpError{Status: http.StatusBadRequest, Err: nil})
		return
	}

	hashedPassword, err := util.HashPassword(*payload.NewPassword)
	if err != nil {
		json.ErrorJSON(w, constants.PasswordHashingErrorMessage, types.HttpError{Status: http.StatusBadRequest, Err: nil})
		return
	}

	if err = a.userRepository.Update(&models.User{ID: user.ID}, &models.User{Password: &hashedPassword}, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil)
}

// UpdateUser godoc
//
//	@Summary		Update user
//	@Description	Helps to update user's data
//	@Tags			users
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		models.UpdateUserRequest	true	"update user body"
//	@Success		200		{object}	types.SuccessResponse
//	@Failure		400		{object}	types.ErrorResponse	"Unexpected database error"
//	@Failure		401		{object}	types.ErrorResponse	"User is not logged in"
//	@Failure		422		{object}	types.ErrorResponse	"Validation error"
//	@Router			/users [patch]
func (a *API) UpdateUser(w http.ResponseWriter, r *http.Request) {
	user, err := models.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, constants.NotLoggedInErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
		return
	}

	payload := &models.UpdateUserRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewValidationError(err, payload))
		return
	}

	if err = a.userRepository.Update(&models.User{ID: user.ID}, &models.User{Username: payload.Username, Email: payload.Email}, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil)
}

// DeleteUser godoc
//
//	@Summary		Delete user
//	@Description	Helps completely delete a user and all related data
//	@Tags			users
//	@Security		BearerAuth
//	@Produce		json
//	@Success		200	{object}	types.SuccessResponse
//	@Failure		400	{object}	types.ErrorResponse	"Unexpected database error"
//	@Failure		401	{object}	types.ErrorResponse	"User is not logged in"
//	@Router			/users [delete]
func (a *API) DeleteUser(w http.ResponseWriter, r *http.Request) {
	user, err := models.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, constants.NotLoggedInErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
		return
	}

	if err = a.userRepository.DeleteOneById(&models.User{}, user.ID, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil)
}

func (a *API) generateUserTokenPair(w http.ResponseWriter, user models.User, setCookies bool, writeResponse bool) {
	accessToken, err := util.CreateToken(a.config.AccessTokenExpiresIn, user, a.config.AccessTokenPrivateKey)
	if err != nil {
		json.ErrorJSON(w, constants.TokenProcessingErrorMessage, types.HttpError{Status: http.StatusBadRequest, Err: err})
		return
	}

	refreshToken, err := util.CreateToken(a.config.RefreshTokenExpiresIn, user, a.config.RefreshTokenPrivateKey)
	if err != nil {
		json.ErrorJSON(w, constants.TokenProcessingErrorMessage, types.HttpError{Status: http.StatusBadRequest, Err: err})
		return
	}

	a.refreshTokenRepository.Create(&models.RefreshToken{
		Token: refreshToken,
		User:  user,
	}, nil)

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
		json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, models.AccessTokenResponse{AccessToken: &accessToken})
	}
}
