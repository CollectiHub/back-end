package models

import (
	"github.com/google/uuid"
)

type RefreshToken struct {
	ID     uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primary_key"`
	Token  string    `gorm:"type:text;not null"`
	UserID uuid.UUID
	User   User `gorm:"constraint:OnDelete:CASCADE"`
	Used   bool `gorm:"type:boolean;default:false"`
}
