package models

import (
	"collectihub/types"
	"time"

	"github.com/google/uuid"
)

type VerificationCode struct {
	ID      uuid.UUID              `gorm:"type:uuid;default:uuid_generate_v4();primary_key"`
	Code    string                 `gorm:"type:varchar(12);not null"`
	Type    types.VerificationType `gorm:"type:verification_type;not null"`
	Expires time.Time
	UserID  uuid.UUID
	User    User `gorm:"constraint:OnDelete:CASCADE"`
}
