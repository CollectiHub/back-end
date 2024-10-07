package main

import (
	"collectihub/internal/common"
	"collectihub/internal/constants"
	"collectihub/internal/data"
	"collectihub/internal/util"
	"collectihub/internal/util/json"
	"collectihub/types"
	"context"
	jsonLib "encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"gorm.io/gorm"
)

// SignUp godoc
//
//	@Summary		Sign up
//	@Description	Serves as a registration endpoint for new users creation. After registration email verification is sent.
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		data.SignUpRequest	true	"sign up body"
//	@Success		201		{object}	types.SuccessResponse{data=data.GetUserResponse}
//	@Failure		400		{object}	types.ErrorResponse	"Password hashing error; Unexpected database error;"
//	@Failure		422		{object}	types.ErrorResponse	"Validation error"
//	@Failure		409		{object}	types.ErrorResponse	"Username of email in from request is already taken"
//	@Router			/auth/register [post]
func (app *application) signUpHandler(w http.ResponseWriter, r *http.Request) {
	payload := &data.SignUpRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewValidationError(err, payload))
		return
	}

	hashedPassword, err := util.HashPassword(*payload.Password)
	if err != nil {
		json.ErrorJSON(w, constants.PasswordHashingErrorMessage, types.HttpError{Status: http.StatusBadRequest, Err: err})
		app.logger.Error().Err(err).Msgf("Error during password hashing for user (%s)", *payload.Email)
		return
	}

	newUser := data.User{
		Email:    payload.Email,
		Username: payload.Username,
		Password: &hashedPassword,
	}

	// Begin transaction
	tx := app.models.Users.DB.Begin()

	if err = app.models.Users.Create(&newUser, tx); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		app.logger.Error().Err(err).Msgf("Database error during user insertion (%v)", newUser)
		return
	}

	// Sending verification email
	expiration := time.Now().Add(time.Minute * 5)
	code := util.GenerateRandomNumberString(constants.EmailVerificationCodeLength)
	emailVerification := &data.VerificationCode{
		UserID:  newUser.ID,
		Expires: expiration,
		Type:    types.EmailVerificationType,
		Code:    &code,
	}

	if err = app.models.VerificationCodes.Create(emailVerification, tx); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	go app.mailer.SendAccountVerificationEmail(*newUser.Email, *emailVerification.Code)

	// Commit transaction
	tx.Commit()

	app.logger.Info().Msgf("New user (%s) was successfully created", *newUser.Username)
	json.WriteJSON(w, http.StatusCreated, constants.SuccessMessage, &data.GetUserResponse{
		ID:       newUser.ID,
		Username: newUser.Username,
		Email:    newUser.Email,
		Role:     newUser.Role,
		Verified: newUser.Verified,
	}, nil)
}

// GoogleLogin godoc
//
//	@Summary		Google login
//	@Description	Used to login/register with Google account, user will be redirected to Google's OAuth page.
//	@Tags			auth
//	@Success		303	"Redirected"
//	@Router			/auth/google/login [get]
func (app *application) googleLoginHandler(w http.ResponseWriter, r *http.Request) {
	url := app.oauth.GoogleLoginConfig.AuthCodeURL(app.config.GoogleState)

	http.Redirect(w, r, url, http.StatusSeeOther)
}

// GoogleCallback godoc
//
//	@Summary		Google callback
//	@Description	This endpoint will be automatically trigerred by Google with related credentials. If user with this credetials doesn't exist in database, server will automatically create a new user (with randomized username) and return auth token pair. Otherwise it will login user with auth token pair.
//	@Tags			auth
//	@Produce		json
//	@Success		200	{object}	types.SuccessResponse{data=data.AccessTokenResponse}
//	@Failure		400	{object}	types.ErrorResponse	"Incorrect OAuth state; OAuth exchange error; OAuth user fetching error; UserData reading error; Unexpected database error;"
//	@Failure		422	{object}	types.ErrorResponse	"Validation error"
//	@Router			/auth/google/callback [get]
func (app *application) googleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	if state := r.URL.Query().Get("state"); state != app.config.GoogleState {
		json.ErrorJSON(w, constants.IncorrectOAuthStateErrorMessage, types.HttpError{Status: http.StatusBadRequest, Err: nil})
		return
	}

	code := r.URL.Query().Get("code")

	token, err := app.oauth.GoogleLoginConfig.Exchange(context.Background(), code)
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

	googleUserData := &data.GoogleUserData{}
	if err = jsonLib.Unmarshal(userData, &googleUserData); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, types.HttpError{Status: http.StatusUnprocessableEntity, Err: nil})
		return
	}

	user, err := app.models.Users.FindOne(&data.User{
		OAuthProvider:  util.Pointer("google"),
		OAuthIndentity: googleUserData.Email,
	})

	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
			return
		}
	}

	// register user if account does not exist yet
	if errors.Is(err, gorm.ErrRecordNotFound) {
		user := data.User{
			OAuthProvider:  util.Pointer("google"),
			OAuthIndentity: googleUserData.Email,
			Username:       util.Pointer(util.GenerateRandomString(10)),
			Verified:       util.Pointer(true),
		}

		if err = app.models.Users.Create(&user, nil); err != nil {
			json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
			return
		}
	}

	// Generate and return token pair for logged in / registered user
	app.generateUserTokenPair(w, user, true, true)
}

// SignIn godoc
//
//	@Summary		Login
//	@Description	Used to login users registered with email. Refresh token is saved in secured cookies and can be used to refresh token pair (refresh and access token).
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		data.SignInRequest	true	"sign in body"
//	@Success		200		{object}	types.SuccessResponse{data=data.AccessTokenResponse}
//	@Failure		400		{object}	types.ErrorResponse	"Unexpected database error; Incorrect password;"
//	@Failure		404		{object}	types.ErrorResponse	"User not found"
//	@Failure		422		{object}	types.ErrorResponse	"Validation error"
//	@Router			/auth/login [post]
func (app *application) signInHandler(w http.ResponseWriter, r *http.Request) {
	payload := &data.SignInRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewValidationError(err, payload))
		return
	}

	user, err := app.models.Users.FindOne(&data.User{Email: payload.Email})

	if err != nil {
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

	app.generateUserTokenPair(w, user, true, true)
}

// VerifyEmail godoc
//
//	@Summary		Verify email
//	@Description	Helps to verify account using the code sent to user's email.
//	@Tags			users
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		data.AccountVerificationRequest	true	"account verification body"
//	@Success		200		{object}	types.SuccessResponse
//	@Failure		400		{object}	types.ErrorResponse	"User is already verified; Incorrect verification code; Unexpected database error;"
//	@Failure		401		{object}	types.ErrorResponse	"User is not logged in"
//	@Failure		422		{object}	types.ErrorResponse	"Validation error"
//	@Router			/users/verify-email [post]
func (app *application) verifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	user, err := data.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, constants.NotLoggedInErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
		return
	}

	payload := &data.AccountVerificationRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewValidationError(err, payload))
		return
	}

	if *user.Verified {
		json.ErrorJSON(w, constants.AccountIsAlreadyVerified, types.HttpError{Status: http.StatusBadRequest, Err: nil})
		return
	}

	_, err = app.models.VerificationCodes.FindOne(&data.VerificationCode{
		UserID: user.ID,
		Type:   types.EmailVerificationType,
		Code:   payload.Code,
	})
	if err != nil {
		json.ErrorJSON(w, constants.WrongVerificationCodeErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
		return
	}

	// Begin transaction
	tx := app.models.Users.DB.Begin()

	if err = app.models.Users.Update(&data.User{ID: user.ID}, &data.User{Verified: util.Pointer(true)}, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	if err = app.models.VerificationCodes.DeleteAll(&data.VerificationCode{UserID: user.ID}, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	// Commit transaction
	tx.Commit()

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil, nil)
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
func (app *application) resendEmailVerificationHandler(w http.ResponseWriter, r *http.Request) {
	user, err := data.GetUserFromRequestContext(r)
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
	emailVerification := &data.VerificationCode{
		UserID:  user.ID,
		Expires: expiration,
		Type:    types.EmailVerificationType,
		Code:    &code,
	}

	if err = app.models.VerificationCodes.Create(emailVerification, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	go app.mailer.SendAccountVerificationEmail(*user.Email, *emailVerification.Code)

	json.WriteJSON(w, http.StatusOK, "New messages was successfully sent", nil, nil)
}

// SendPasswordResetEmail godoc
//
//	@Summary		Send password reset email
//	@Description	Helps to send password reset verification code to user's email. It can be used to reset password on other endpoint.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Param			body	body		data.SendPasswordResetEmailRequest	true	"send password reset email body"
//	@Success		200		{object}	types.SuccessResponse				"password email reset was successfully sent"
//	@Failure		400		{object}	types.ErrorResponse					"Unexpected database error"
//	@Failure		404		{object}	types.ErrorResponse					"User not found"
//	@Failure		422		{object}	types.ErrorResponse					"Validation error"
//	@Router			/users/request-password-reset [post]
func (app *application) sendPasswordResetEmailHandler(w http.ResponseWriter, r *http.Request) {
	payload := &data.SendPasswordResetEmailRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewValidationError(err, payload))
		return
	}

	user, err := app.models.Users.FindOne(&data.User{Email: payload.Email})

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
	passwordReset := &data.VerificationCode{
		UserID:  user.ID,
		Expires: expiration,
		Type:    types.PasswordResetType,
		Code:    &code,
	}

	if err := app.models.VerificationCodes.Create(passwordReset, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	go app.mailer.SendPasswordResetVerificationEmail(*user.Email, *passwordReset.Code)

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil, nil)
}

// PasswordReset godoc
//
//	@Summary		Password reset verification
//	@Description	Used to update user password with code received from email.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Param			body	body		data.PasswordResetRequest	true	"password reset body"
//	@Success		200		{object}	types.SuccessResponse
//	@Failure		400		{object}	types.ErrorResponse	"Unexpected database error; Password hashing error;"
//	@Failure		404		{object}	types.ErrorResponse	"User not found"
//	@Failure		422		{object}	types.ErrorResponse	"Validation error"
//	@Router			/users/verify-password-reset [post]
func (app *application) passwordResetHandler(w http.ResponseWriter, r *http.Request) {
	payload := &data.PasswordResetRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewValidationError(err, payload))
		return
	}

	user, err := app.models.Users.FindOne(&data.User{Email: payload.Email})

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		json.ErrorJSON(w, constants.NotFoundMessage("User"), types.HttpError{Status: http.StatusNotFound, Err: nil})
		return
	}

	_, err = app.models.VerificationCodes.FindOne(&data.VerificationCode{UserID: user.ID, Type: types.PasswordResetType, Code: payload.Code})
	if err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	hashedPassword, err := util.HashPassword(*payload.NewPassword)
	if err != nil {
		json.ErrorJSON(w, constants.PasswordHashingErrorMessage, types.HttpError{Status: http.StatusBadRequest, Err: nil})
		return
	}

	// Begin transaction
	tx := app.models.Users.DB.Begin()

	err = app.models.Users.Update(&data.User{ID: user.ID}, &data.User{Password: &hashedPassword}, tx)
	if err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	err = app.models.VerificationCodes.DeleteAll(
		&data.VerificationCode{UserID: user.ID, Type: types.PasswordResetType},
		tx,
	)
	if err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	// Commit transaction
	tx.Commit()

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil, nil)
}

// RefreshAccessToken godoc
//
//	@Summary		Refresh access token
//	@Description	Helps to refresh access token. Returns new access token and store refresh token in cookies. Refresh tokens are saved in database and their usage is tracked. So if refresh token is used second time, all user's refresh tokens will be wiped. This deletion will force all user's authenticated devices to log in again when access token expires.
//	@Tags			auth
//	@Produce		json
//	@Success		200	{object}	types.SuccessResponse{data=data.AccessTokenResponse}
//	@Failure		400	{object}	types.ErrorResponse	"Unexpected database error"
//	@Failure		403	{object}	types.ErrorResponse	"Token processing error; Malicious activity detected;"
//	@Failure		404	{object}	types.ErrorResponse	"User not found; Token not found;"
//	@Router			/auth/refresh-token [post]
func (app *application) refreshAccessTokenHandler(w http.ResponseWriter, r *http.Request) {
	refreshTokenFromCookie, err := r.Cookie(constants.RefreshTokenCookie)
	if err != nil {
		json.ErrorJSON(w, constants.TokenProcessingErrorMessage, types.HttpError{Status: http.StatusForbidden, Err: nil})
		return
	}

	sub, err := util.ValidateToken(refreshTokenFromCookie.Value, app.config.RefreshTokenPublicKey)
	if err != nil {
		json.ErrorJSON(w, constants.TokenProcessingErrorMessage, types.HttpError{Status: http.StatusForbidden, Err: nil})
		return
	}

	userID, ok := sub.(string)
	if !ok {
		json.ErrorJSON(w, constants.TokenProcessingErrorMessage, types.HttpError{Status: http.StatusForbidden, Err: nil})
		return
	}

	user, err := app.models.Users.FindOneById(userID)
	if err != nil {
		json.ErrorJSON(w, constants.NotFoundMessage("User"), types.HttpError{Status: http.StatusNotFound, Err: nil})
		return
	}

	refreshTokenFromDB, err := app.models.RefreshTokens.FindOne(&data.RefreshToken{Token: refreshTokenFromCookie.Value, UserID: user.ID})

	if err != nil {
		json.ErrorJSON(w, constants.NotFoundMessage("Token"), types.HttpError{Status: http.StatusNotFound, Err: nil})
		return
	}

	// If token was already used before, it means someone suspicious is trying to
	// retrieve access token. In this case we remove all refresh tokens for the
	// user. It'll make anyone, who whenever had access to account, log in again
	// when access token expires.
	if refreshTokenFromDB.Used {
		if err = app.models.RefreshTokens.DeleteAll(&data.RefreshToken{UserID: user.ID}, nil); err != nil {
			json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
			return
		}

		json.ErrorJSON(w, constants.MaliciousActivityErrorMessage, types.HttpError{Status: http.StatusForbidden, Err: nil})
		return
	}

	// If token was not used before, we mark it as used and give the user new
	// set of tokens.
	if err = app.models.RefreshTokens.Update(&data.RefreshToken{ID: refreshTokenFromDB.ID}, &data.RefreshToken{Used: true}, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	app.generateUserTokenPair(w, user, true, true)
}

// Logout godoc
//
//	@Summary		Logout
//	@Description	Helps user to log out. This endpoint will trigger auth cookies expiration.
//	@Tags			auth
//	@Produce		json
//	@Success		200	{object}	types.SuccessResponse
//	@Router			/auth/logout [post]
func (app *application) logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     constants.AccessTokenCookie,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Domain:   app.config.HostDomain,
		Secure:   false,
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     constants.RefreshTokenCookie,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Domain:   app.config.HostDomain,
		Secure:   false,
		HttpOnly: true,
	})

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil, nil)
}

// GetMe godoc
//
//	@Summary		Get info about user
//	@Description	Helps to retrieve data of authenticated user
//	@Tags			users
//	@Security		BearerAuth
//	@Produce		json
//	@Success		200	{object}	types.SuccessResponse{data=data.GetUserResponse}
//	@Failure		401	{object}	types.ErrorResponse	"User is not logged in"
//	@Router			/users/me [get]
func (app *application) getAuthenticatedUserHandler(w http.ResponseWriter, r *http.Request) {
	user, err := data.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, constants.NotLoggedInErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, data.GetUserResponse{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		Role:     user.Role,
		Verified: user.Verified,
	}, nil)
}

// ChangePassword godoc
//
//	@Summary		Change password
//	@Description	Helps to change password of authenticated user.
//	@Tags			users
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		data.ChangePasswordRequest	true	"change password body"
//	@Success		200		{object}	types.SuccessResponse
//	@Failure		400		{object}	types.ErrorResponse	"Incorrect old password; Password hashing error; Unexpected database error;"
//	@Failure		401		{object}	types.ErrorResponse	"User is not logged in"
//	@Failure		422		{object}	types.ErrorResponse	"Validation error"
//	@Router			/users/change-password [patch]
func (app *application) changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	user, err := data.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, constants.NotLoggedInErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
		return
	}

	payload := &data.ChangePasswordRequest{}
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

	if err = app.models.Users.Update(&data.User{ID: user.ID}, &data.User{Password: &hashedPassword}, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil, nil)
}

// UpdateUser godoc
//
//	@Summary		Update user
//	@Description	Helps to update user's data
//	@Tags			users
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		data.UpdateUserRequest	true	"update user body"
//	@Success		200		{object}	types.SuccessResponse
//	@Failure		400		{object}	types.ErrorResponse	"Unexpected database error"
//	@Failure		401		{object}	types.ErrorResponse	"User is not logged in"
//	@Failure		422		{object}	types.ErrorResponse	"Validation error"
//	@Router			/users [patch]
func (app *application) updateUserHandler(w http.ResponseWriter, r *http.Request) {
	user, err := data.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, constants.NotLoggedInErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
		return
	}

	payload := &data.UpdateUserRequest{}
	json.DecodeJSON(*r, payload)

	if err := json.ValidateStruct(w, payload); err != nil {
		json.ErrorJSON(w, constants.JsonValidationErrorMessage, common.NewValidationError(err, payload))
		return
	}

	if err = app.models.Users.Update(&data.User{ID: user.ID}, &data.User{Username: payload.Username, Email: payload.Email}, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil, nil)
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
func (app *application) deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	user, err := data.GetUserFromRequestContext(r)
	if err != nil {
		json.ErrorJSON(w, constants.NotLoggedInErrorMessage, types.HttpError{Status: http.StatusUnauthorized, Err: nil})
		return
	}

	if err = app.models.Users.DeleteOneById(user.ID, nil); err != nil {
		json.ErrorJSON(w, constants.DatabaseErrorMessage, common.NewDatabaseError(err))
		return
	}

	json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, nil, nil)
}

func (app *application) generateUserTokenPair(w http.ResponseWriter, user data.User, setCookies bool, writeResponse bool) {
	accessToken, err := util.CreateToken(app.config.AccessTokenExpiresIn, user, app.config.AccessTokenPrivateKey)
	if err != nil {
		json.ErrorJSON(w, constants.TokenProcessingErrorMessage, types.HttpError{Status: http.StatusBadRequest, Err: err})
		return
	}

	refreshToken, err := util.CreateToken(app.config.RefreshTokenExpiresIn, user, app.config.RefreshTokenPrivateKey)
	if err != nil {
		json.ErrorJSON(w, constants.TokenProcessingErrorMessage, types.HttpError{Status: http.StatusBadRequest, Err: err})
		return
	}

	app.models.RefreshTokens.Create(&data.RefreshToken{
		Token: refreshToken,
		User:  user,
	}, nil)

	if setCookies {
		http.SetCookie(w, &http.Cookie{
			Name:     constants.AccessTokenCookie,
			Value:    accessToken,
			MaxAge:   int(app.config.AccessTokenExpiresIn.Seconds()),
			Path:     "/",
			Domain:   app.config.HostDomain,
			Secure:   false,
			HttpOnly: true,
		})

		http.SetCookie(w, &http.Cookie{
			Name:     constants.RefreshTokenCookie,
			Value:    refreshToken,
			MaxAge:   int(app.config.RefreshTokenExpiresIn.Seconds()),
			Path:     "/",
			Domain:   app.config.HostDomain,
			Secure:   false,
			HttpOnly: true,
		})
	}

	if writeResponse {
		json.WriteJSON(w, http.StatusOK, constants.SuccessMessage, data.AccessTokenResponse{AccessToken: &accessToken}, nil)
	}
}
