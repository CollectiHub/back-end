package models

import (
	"time"

	"github.com/google/uuid"
)

type Manufacturer struct {
	ID             uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primary_key"`
	OriginalTitle  *string   `gorm:"type:varchar(64);not null"`
	DescriptionEng *string   `gorm:"type:text"`
	DescriptionUkr *string   `gorm:"type:text"`
	Image          *string   `gorm:"type:varchar(256)"`
	CreatedAt      time.Time `gorm:"not null"`
	UpdatedAt      time.Time `gorm:"not null"`
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
