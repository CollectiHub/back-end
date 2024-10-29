package data

import (
	"collectihub/types"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type VerificationCode struct {
	ID      uuid.UUID              `gorm:"type:uuid;default:uuid_generate_v4();primary_key"`
	Code    *string                `gorm:"type:varchar(32);not null"`
	Type    types.VerificationType `gorm:"type:verification_type;not null"`
	Expires time.Time
	UserID  uuid.UUID
	User    User `gorm:"constraint:OnDelete:CASCADE"`
}

type VerificationCodeModel struct {
	DB *gorm.DB
}

func (m VerificationCodeModel) Create(obj *VerificationCode, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Create(&obj).Error; err != nil {
			tx.Rollback()
			return err
		}

		return nil
	}

	return m.DB.Create(&obj).Error
}

func (m VerificationCodeModel) FindOne(find *VerificationCode) (VerificationCode, error) {
	var dest VerificationCode
	err := m.DB.First(&dest, &find).Error

	return dest, err
}

func (m VerificationCodeModel) DeleteAll(find *VerificationCode, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Delete(&VerificationCode{}, &find).Error; err != nil {
			tx.Rollback()
			return err
		}
		return nil
	}
	return m.DB.Delete(&VerificationCode{}, &find).Error
}
