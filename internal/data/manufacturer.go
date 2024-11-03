package data

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Manufacturer struct {
	ID             uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primary_key"`
	OriginalTitle  *string   `gorm:"type:varchar(64);not null"`
	DescriptionEng *string   `gorm:"type:text;default:''"`
	DescriptionUkr *string   `gorm:"type:text;default:''"`
	Image          *string   `gorm:"type:varchar(256);default:''"`

	NonExistentCards []NonExistentCard `gorm:"constraint:OnDelete:CASCADE"`
	Cards            []Card            `gorm:"constraint:OnDelete:CASCADE"`

	CreatedAt time.Time `gorm:"not null"`
	UpdatedAt time.Time `gorm:"not null"`
}

type ManufacturerModel struct {
	DB *gorm.DB
}

func (m ManufacturerModel) Create(obj *Manufacturer, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Create(&obj).Error; err != nil {
			tx.Rollback()
			return err
		}

		return nil
	}

	return m.DB.Create(&obj).Error
}

func (m ManufacturerModel) Update(find *Manufacturer, update *Manufacturer, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Model(&find).Updates(&update).Error; err != nil {
			tx.Rollback()
			return err
		}

		return nil
	}

	return m.DB.Model(&find).Updates(&update).Error
}

func (m ManufacturerModel) FindOne(find *Manufacturer) (Manufacturer, error) {
	var dest Manufacturer
	err := m.DB.First(&dest, &find).Error

	return dest, err
}

func (m ManufacturerModel) FindOneById(id interface{}) (Manufacturer, error) {
	var dest Manufacturer
	err := m.DB.First(&dest, "id = ?", id).Error

	return dest, err
}

func (m ManufacturerModel) FindAll(find *Manufacturer) ([]Manufacturer, error) {
	var dest []Manufacturer
	err := m.DB.Find(&dest, &find).Error

	return dest, err
}

func (m ManufacturerModel) DeleteOneById(id interface{}, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Delete(&Manufacturer{}, "id = ?", id).Error; err != nil {
			tx.Rollback()
			return err
		}

		return nil
	}

	return m.DB.Delete(&Manufacturer{}, "id = ?", id).Error
}

type CreateManufacturerRequest struct {
	OriginalTitle  *string `json:"original_title" example:"Kayou" validate:"required,min=4"`
	DescriptionEng *string `json:"description_eng" example:"Chinese manufacturer that is popular for Naruto collection cards" validate:"omitempty,min=6"`
	DescriptionUkr *string `json:"description_ukr" example:"Китайський виробник, популярний за колекційні картки по Наруто" validate:"omitempty,min=6"`
	Image          *string `json:"image" example:"https://example.com/image.png" validate:"omitempty,url"`
}

type UpdateManufacturerRequest struct {
	OriginalTitle  *string `json:"original_title" example:"Kayou" validate:"omitempty,min=4"`
	DescriptionEng *string `json:"description_eng" example:"Chinese manufacturer that is popular for Naruto collection cards" validate:"omitempty,min=6"`
	DescriptionUkr *string `json:"description_ukr" example:"Китайський виробник, популярний за колекційні картки по Наруто" validate:"omitempty,min=6"`
	Image          *string `json:"image" example:"https://example.com/image.png" validate:"omitempty,url"`
}

type GetManufacturerResponse struct {
	ID             uuid.UUID `json:"id" example:"3c1e3b82-3a29-4cc0-a4b2-4e7c4ac58052" format:"uuid"`
	OriginalTitle  *string   `json:"original_title" example:"Kayou"`
	DescriptionEng *string   `json:"description_eng" example:"Chinese manufacturer that is popular for Naruto collection cards"`
	DescriptionUkr *string   `json:"description_ukr" example:"Китайський виробник, популярний за колекційні картки по Наруто"`
	Image          *string   `json:"image" example:"https://example.com/image.png"`
}
