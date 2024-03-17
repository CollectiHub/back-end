package user

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID        uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primary_key"`
	Username  string    `gorm:"type:varchar(32);uniqueIndex;not null"`
	Email     string    `gorm:"type:varchar(64);uniqueIndex;not null"`
	Password  string    `gorm:"type:varchar(256);not null"`
	Role      string    `gorm:"type:varchar(32);not null"`
	Verified  bool      `gorm:"type:boolean;default:'User'"`
	CreatedAt time.Time `gorm:"not null"`
	UpdatedAt time.Time `gorm:"not null"`
}

type SignUpInput struct {
	Username string `json:"username" validate:"required"`
	Email    string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required,min=8"` // TODO: update when policy is ready
}

type SignInInput struct {
	Email    string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type GetUserResponse struct {
	ID       uuid.UUID `json:"id"`
	Username string    `json:"username"`
	Email    string    `json:"email"`
	Role     string    `json:"role"`
	Verified bool      `json:"verified"`
}