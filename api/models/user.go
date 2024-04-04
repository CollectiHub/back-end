package models

import (
	"collectihub/internal/constants"
	"collectihub/types"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID             uuid.UUID      `gorm:"type:uuid;default:uuid_generate_v4();primary_key"`
	Username       string         `gorm:"type:varchar(32);uniqueIndex;not null"`
	Email          string         `gorm:"type:varchar(64);uniqueIndex"`
	Password       string         `gorm:"type:varchar(256);not null"`
	OAuthProvider  string         `gorm:"type:varchar(32)"`
	OAuthIndentity string         `gorm:"type:varchar(64)"`
	Role           types.UserRole `gorm:"type:user_role;default:'regular';not null"`
	Verified       bool           `gorm:"type:boolean;default:false;not null"`
	CreatedAt      time.Time      `gorm:"not null"`
	UpdatedAt      time.Time      `gorm:"not null"`
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

type AccountVerificationRequest struct {
	Code string `json:"code" example:"12345" validate:"required,len=5"`
}

type SendPasswordResetMailRequest struct {
	Email string `json:"email" example:"re4lhok5ge@gmail.com" validate:"required,email"`
}

type PasswordResetRequest struct {
	Email       string `json:"email" example:"re4lhok4ge@gmail.com" validate:"required,email"`
	Code        string `json:"code" example:"123456" validate:"required,len=6"`
	NewPassword string `json:"new_password" example:"strongpass" validate:"required,min=8"`
}

type GetUserResponse struct {
	ID       uuid.UUID      `json:"id" example:"3c1e3b82-3a29-4cc0-a4b2-4e7c4ac58052" format:"uuid"`
	Username string         `json:"username" example:"realhokage"`
	Email    string         `json:"email" example:"realhokage@gmail.com"`
	Role     types.UserRole `json:"role" example:"regular"`
	Verified bool           `json:"verified" example:"true"`
}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
}

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
