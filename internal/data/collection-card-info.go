package data

import (
	"kadocore/types"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type CollectionCardInfo struct {
	CardID uuid.UUID                  `gorm:"type:uuid;primaryKey"`
	UserID uuid.UUID                  `gorm:"type:uuid;primaryKey"`
	User   User                       `gorm:"constraint:OnDelete:CASCADE"`
	Card   Card                       `gorm:"constraint:OnDelete:CASCADE"`
	Status types.CollectionCardStatus `gorm:"type:collection_card_status;not null"`
}

type CollectionCardInfoModel struct {
	DB     *gorm.DB
	logger *zerolog.Logger
}

func (m CollectionCardInfoModel) Create(obj *CollectionCardInfo, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Create(&obj).Error; err != nil {
			tx.Rollback()
			return err
		}

		return nil
	}

	return m.DB.Create(&obj).Error
}

// Update all entities of collection card info with the given user id and cards ids with new status
func (m CollectionCardInfoModel) UpdateAllByUserIDAndCardIDs(userID string, cardIDs []string, status types.CollectionCardStatus, tx *gorm.DB) error {
	db := m.DB

	if tx != nil {
		db = tx
	}

	collectionCardInfos := make([]CollectionCardInfo, 0, len(cardIDs))
	for _, cardID := range cardIDs {
		collectionCardInfos = append(collectionCardInfos, CollectionCardInfo{
			CardID: uuid.MustParse(cardID),
			UserID: uuid.MustParse(userID),
			Status: status,
		})
	}

	err := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "card_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"status"}),
	}).Create(&collectionCardInfos).Error

	if err != nil && tx != nil {
		tx.Rollback()
	}

	return err
}

// Update one entity of collection card info with the given user id and card id with new status
func (m CollectionCardInfoModel) UpdateOneByUserIDAndCardID(userID string, cardID string, status types.CollectionCardStatus, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Model(&CollectionCardInfo{}).Where("user_id = ? AND card_id = ?", userID, cardID).Update("status", status).Error; err != nil {
			tx.Rollback()
			return err
		}

		return nil
	}

	return m.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "card_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"status"}),
	}).Create(&CollectionCardInfo{
		CardID: uuid.MustParse(cardID),
		UserID: uuid.MustParse(userID),
		Status: status,
	}).Error
}

func (m CollectionCardInfoModel) Update(find *CollectionCardInfo, update *Card, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Model(&find).Updates(&update).Error; err != nil {
			tx.Rollback()
			return err
		}

		return nil
	}

	return m.DB.Model(&find).Updates(&update).Error
}

type UpdateCollectionRequest struct {
	Ids    []string               `json:"ids"`
	Change UpdateCollectionChange `json:"change"`
}

type UpdateCollectionChange struct {
	Status types.CollectionCardStatus `json:"status"`
}

type UpdateCollectionResponse struct {
	CardsCollected int64 `json:"cards_collected"`
}
