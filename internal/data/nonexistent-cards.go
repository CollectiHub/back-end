package data

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type NonExistentCard struct {
	ID             uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primary_key"`
	ManufacturerID uuid.UUID
	Rarity         *string `gorm:"type:varchar(12);not null"`
	SerialNumber   *string `gorm:"type:varchar(64);not null"`
}

type NonExistentCardsModel struct {
	DB *gorm.DB
}

func (m NonExistentCardsModel) Create(obj *NonExistentCard, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Create(&obj).Error; err != nil {
			tx.Rollback()
			return err
		}

		return nil
	}

	return m.DB.Create(&obj).Error
}

func (m NonExistentCardsModel) FindOne(find *NonExistentCard) (NonExistentCard, error) {
	var dest NonExistentCard
	err := m.DB.First(&dest, &find).Error

	return dest, err
}

func (m NonExistentCardsModel) FindAll(find *NonExistentCard) ([]NonExistentCard, error) {
	var dest []NonExistentCard
	err := m.DB.Find(&dest, &find).Error

	return dest, err
}

func (m NonExistentCardsModel) DeleteOneById(id interface{}, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Delete(&NonExistentCard{}, "id = ?", id).Error; err != nil {
			tx.Rollback()
			return err
		}

		return nil
	}

	return m.DB.Delete(&NonExistentCard{}, "id = ?", id).Error
}

func (m NonExistentCardsModel) DeleteAll(find *NonExistentCard, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Delete(&NonExistentCard{}, &find).Error; err != nil {
			tx.Rollback()
			return err
		}
		return nil
	}
	return m.DB.Delete(&NonExistentCard{}, &find).Error
}

type CreateNonExistentCardRequest struct {
	Rarity       *string `json:"rarity" example:"SSR" validate:"len=0|required,max=12"`
	SerialNumber *string `json:"serial_number" example:"SE-014" validate:"len=0|min=1,max=64"`
}

type GetNonExistentCardResponse struct {
	ID           uuid.UUID `json:"id" example:"00000000-0000-0000-0000-000000000000"`
	Rarity       *string   `json:"rarity" example:"SSR"`
	SerialNumber *string   `json:"serial_number" example:"SE-014"`
}
