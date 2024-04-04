package database

import "gorm.io/gorm"

type Repository[T any] struct {
	db *gorm.DB
}

func NewRepository[T any](db *gorm.DB) *Repository[T] {
	return &Repository[T]{db}
}

func (r *Repository[T]) Create(obj *T) error {
	return r.db.Create(&obj).Error
}

func (r *Repository[T]) Update(find *T, update *T) error {
	return r.db.Model(&find).Updates(&update).Error
}

func (r *Repository[T]) FindOne(dest *T, find *T) error {
	return r.db.First(&dest, &find).Error
}

func (r *Repository[T]) FindOneById(dest *T, id interface{}) error {
	return r.db.First(&dest, "id = ?", id).Error
}

func (r *Repository[T]) Delete(model *T, find *T) error {
	return r.db.Delete(&model, &find).Error
}

func (r *Repository[T]) DeleteOneById(model *T, id interface{}) error {
	return r.db.Delete(&model, "id = ?", id).Error
}
