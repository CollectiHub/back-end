package database

import "gorm.io/gorm"

type Repository[T any] struct {
	DB *gorm.DB
}

func NewRepository[T any](db *gorm.DB) *Repository[T] {
	return &Repository[T]{db}
}

func (r *Repository[T]) Create(obj *T, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Create(&obj).Error; err != nil {
			tx.Rollback()
			return err
		}
		return nil
	}
	return r.DB.Create(&obj).Error
}

func (r *Repository[T]) Update(find *T, update *T, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Model(&find).Updates(&update).Error; err != nil {
			tx.Rollback()
			return err
		}
		return nil
	}
	return r.DB.Model(&find).Updates(&update).Error
}

func (r *Repository[T]) FindAll(dest *[]T, find *T) error {
	return r.DB.Find(&dest, &find).Error
}

func (r *Repository[T]) FindOne(dest *T, find *T) error {
	return r.DB.First(&dest, &find).Error
}

func (r *Repository[T]) FindOneById(dest *T, id interface{}) error {
	return r.DB.First(&dest, "id = ?", id).Error
}

func (r *Repository[T]) Delete(model *T, find *T, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Delete(&model, &find).Error; err != nil {
			tx.Rollback()
			return err
		}
		return nil
	}
	return r.DB.Delete(&model, &find).Error
}

func (r *Repository[T]) DeleteOneById(model *T, id interface{}, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Delete(&model, "id = ?", id).Error; err != nil {
			tx.Rollback()
			return err
		}
		return nil
	}
	return r.DB.Delete(&model, "id = ?", id).Error
}
