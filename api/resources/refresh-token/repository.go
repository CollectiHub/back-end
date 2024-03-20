package refreshtoken

import (
	"collectihub/api/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db}
}

func (r *Repository) Create(refreshToken *models.RefreshToken) error {
	return r.db.Create(&refreshToken).Error
}

func (r *Repository) FindOne(refreshToken *models.RefreshToken, find *models.RefreshToken) error {
	return r.db.First(&refreshToken, find).Error
}

func (r *Repository) Update(find *models.RefreshToken, update *models.RefreshToken) error {
	return r.db.Model(&find).Updates(&update).Error
}

func (r *Repository) DeleteAllByUser(userId uuid.UUID) error {
	return r.db.Delete(&models.RefreshToken{}, &models.RefreshToken{UserID: userId}).Error
}
