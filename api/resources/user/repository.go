package user

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db}
}

func (r *Repository) Create(user *User) error {
	return r.db.Create(&user).Error
}

func (r *Repository) FindOneByEmail(user *User, email string) error {
	return r.db.First(&user, &User{Email: email}).Error
}

func (r *Repository) FindOneById(user *User, id string) error {
	uuid, err := uuid.Parse(id)
	if err != nil {
		return err
	}

	return r.db.First(&user, &User{ID: uuid}).Error
}
