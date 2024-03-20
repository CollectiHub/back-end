package user

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

func (r *Repository) Create(user *models.User) error {
	return r.db.Create(&user).Error
}

func (r *Repository) FindOneByEmail(user *models.User, email string) error {
	return r.db.First(&user, &models.User{Email: email}).Error
}

func (r *Repository) FindOneById(user *models.User, id string) error {
	uuid, err := uuid.Parse(id)
	if err != nil {
		return err
	}

	return r.db.First(&user, &models.User{ID: uuid}).Error
}
