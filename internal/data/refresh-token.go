package data

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type RefreshToken struct {
	ID     uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primary_key"`
	Token  string    `gorm:"type:text;not null"`
	UserID uuid.UUID
	User   User `gorm:"constraint:OnDelete:CASCADE"`
	Used   bool `gorm:"type:boolean;default:false"`
}

type RefreshTokenModel struct {
	DB *gorm.DB
}

func (m RefreshTokenModel) Create(obj *RefreshToken, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Create(&obj).Error; err != nil {
			tx.Rollback()
			return err
		}

		return nil
	}

	return m.DB.Create(&obj).Error
}

func (m RefreshTokenModel) FindOne(find *RefreshToken) (RefreshToken, error) {
	var dest RefreshToken
	err := m.DB.First(&dest, &find).Error

	return dest, err
}

func (m RefreshTokenModel) Update(find *RefreshToken, update *RefreshToken, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Model(&find).Updates(&update).Error; err != nil {
			tx.Rollback()
			return err
		}

		return nil
	}

	return m.DB.Model(&find).Updates(&update).Error
}

func (m RefreshTokenModel) DeleteAll(find *RefreshToken, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Delete(&RefreshToken{}, &find).Error; err != nil {
			tx.Rollback()
			return err
		}
		return nil
	}
	return m.DB.Delete(&RefreshToken{}, &find).Error
}
