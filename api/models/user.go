package models

import (
	"collectihub/internal/constants"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID             uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primary_key"`
	Username       string    `gorm:"type:varchar(32);uniqueIndex;not null"`
	Email          string    `gorm:"type:varchar(64);uniqueIndex"`
	Password       string    `gorm:"type:varchar(256);not null"`
	OAuthProvider  string    `gorm:"type:varchar(32)"`
	OAuthIndentity string    `gorm:"type:varchar(64)"`
	Role           string    `gorm:"type:varchar(32);default:'user';not null"`
	Verified       bool      `gorm:"type:boolean;default:false"`
	CreatedAt      time.Time `gorm:"not null"`
	UpdatedAt      time.Time `gorm:"not null"`
}

type SignUpRequest struct {
	Username string `json:"username" example:"real_naruto" validate:"required,min=6"`
	Email    string `json:"email" example:"realnaruto@gmail.com" validate:"required,email"`
	Password string `json:"password" example:"k4kash1sense1" validate:"required,min=8"` // TODO: update when password is ready
}

type SignInRequest struct {
	Email    string `json:"email" example:"realnaruto@gmail.com" validate:"required"`
	Password string `json:"password" example:"k4kash1sense1" validate:"required"`
}

type UpdateUserRequest struct {
	Username string `json:"username" example:"realhokage" validate:"omitempty,min=6"`
	Email    string `json:"email" example:"realhokage@gmail.com" validate:"omitempty,email"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" example:"k4kash1sense1" validate:"required,min=8"`
	NewPassword string `json:"new_password" example:"re41h0k4ge" validate:"required,min=8"`
}

type GetUserResponse struct {
	ID       uuid.UUID `json:"id" example:"3c1e3b82-3a29-4cc0-a4b2-4e7c4ac58052" format:"uuid"`
	Username string    `json:"username" example:"realhokage"`
	Email    string    `json:"email" example:"realhokage@gmail.com"`
	Role     string    `json:"role" example:"user"`
	Verified bool      `json:"verified" example:"true"`
}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
}

// "id": "111243771685272064005",
// "email": "skillaut@gmail.com",
// "verified_email": true,
// "name": "Andrii",
// "given_name": "Andrii",
// "picture": "https://lh3.googleusercontent.com/a/ACg8ocLjwYpQ8-YGEiPKwClrKobn7LzEyjpYRHMIRusOqy0fA-8=s96-c",
// "locale": "uk"

type GoogleUserData struct {
	Id            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}

func GetUserFromRequestContext(r *http.Request) (*User, error) {
	cur, ok := r.Context().Value(constants.CurrentUserContext).(User)
	if !ok {
		return nil, errors.New("user not found in context")
	}

	return &cur, nil
}
