package data

import (
	"collectihub/types"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

type Card struct {
	ID            uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primary_key"`
	Rarity        *string   `gorm:"type:varchar(12);not null"`
	CharacterName *string   `gorm:"type:varchar(64);default=''"`
	SerialNumber  *string   `gorm:"type:varchar(64);not null"`
	ImageUrl      *string   `gorm:"type:varchar(256);default:''"`
	CreatedAt     time.Time `gorm:"not null"`
	UpdatedAt     time.Time `gorm:"not null"`
}

type CardModel struct {
	DB     *gorm.DB
	logger *zerolog.Logger
}

func (m CardModel) Create(obj *Card, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Create(&obj).Error; err != nil {
			tx.Rollback()
			return err
		}

		return nil
	}

	return m.DB.Create(&obj).Error
}

func (m CardModel) Update(find *Card, update *Card, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Model(&find).Updates(&update).Error; err != nil {
			tx.Rollback()
			return err
		}

		return nil
	}

	return m.DB.Model(&find).Updates(&update).Error
}

func (m CardModel) FindOne(find *Card) (Card, error) {
	var dest Card
	err := m.DB.First(&dest, &find).Error

	return dest, err
}

func (m CardModel) GetAllRarities() ([]string, error) {
	var dest []struct{ Rarity *string }
	if err := m.DB.Model(&Card{}).Distinct("rarity").Find(&dest).Error; err != nil {
		m.logger.Err(err).Msg("failed to get all rarities")
		return nil, err
	}

	rarities := make([]string, 0)
	for _, r := range dest {
		rarities = append(rarities, *r.Rarity)
	}

	return rarities, nil
}

func (m CardModel) GetTotalCount() (int64, error) {
	var count int64
	if err := m.DB.Model(&Card{}).Count(&count).Error; err != nil {
		m.logger.Err(err).Msg("failed to get total count of cards")
		return 0, err
	}

	return count, nil
}

func (m CardModel) GetCollectedCount(userID string) (int64, error) {
	var count int64
	if err := m.DB.Model(&Card{}).Joins(
		"join collection_card_infos cci on cards.id = cci.card_id",
	).Where(
		"cci.user_id::text = ? and cci.status = ?",
		userID,
		types.CardCollected,
	).Count(&count).Error; err != nil {
		m.logger.Err(err).Msg("failed to get count of owned cards")
		return 0, err
	}

	return count, nil
}

// Get all cards by rarity
func (m CardModel) FindAllOwnedByRarity(userID string, rarity string) ([]GetOwnedCardResponse, error) {
	var dest []GetOwnedCardResponse
	if err := m.DB.Model(&Card{}).Select(
		"cards.id as id, cards.rarity as rarity, cards.character_name as character_name, cards.serial_number as serial_number, cards.image_url as image_url, COALESCE(cci.status, ?) as status",
		types.CardNotCollected,
	).Joins(
		"left join collection_card_infos cci on cards.id = cci.card_id and cci.user_id::text = ?",
		userID,
	).Where(
		"cards.rarity = ?",
		rarity,
	).Scan(&dest).Error; err != nil {
		m.logger.Err(err).Msg("failed to get all cards by rarity")
		return nil, err
	}
	// if err := m.DB.Find(&dest, "rarity = ?", rarity).Error; err != nil {
	// 	m.logger.Err(err).Msg("failed to get all cards by rarity")
	// 	return nil, err
	// }

	return dest, nil
}

func (m CardModel) FindAll(find *Card) ([]Card, error) {
	var dest []Card
	err := m.DB.Find(&dest, &find).Error

	return dest, err
}

func (m CardModel) DeleteOneById(id interface{}, tx *gorm.DB) error {
	if tx != nil {
		if err := tx.Delete(&Card{}, "id = ?", id).Error; err != nil {
			tx.Rollback()
			return err
		}

		return nil
	}

	return m.DB.Delete(&Card{}, "id = ?", id).Error
}

type CreateCardRequest struct {
	Rarity        *string `json:"rarity" example:"SSR" validate:"required,max=12"`
	CharacterName *string `json:"character_name" example:"Hatake Kakashi" validate:"omitempty,min=2,max=64"`
	SerialNumber  *string `json:"serial_number" example:"SE-014" validate:"len=0|min=1,max=64"`
	ImageUrl      *string `json:"image_url" example:"https://example.com/image.jpg" validate:"len=0|url"`
}

type UpdateCardRequest struct {
	Rarity        *string `json:"rarity" example:"SSR" validate:"omitempty,max=12"`
	CharacterName *string `json:"character_name" example:"Hatake Kakashi" validate:"omitempty,min=2,max=64"`
	SerialNumber  *string `json:"serial_number" example:"SE-014" validate:"omitempty|len=0|min=1,max=64"`
	ImageUrl      *string `json:"image_url" example:"https://example.com/image.jpg" validate:"len=0|url"`
}

type GetCardResponse struct {
	ID            uuid.UUID `json:"id" example:"550e8400-e29b-41d4-a716-446655440000"`
	Rarity        *string   `json:"rarity" example:"SSR"`
	CharacterName *string   `json:"character_name" example:"Hatake Kakashi"`
	SerialNumber  *string   `json:"serial_number" example:"SE-014"`
	ImageUrl      *string   `json:"image_url" example:"https://example.com/image.jpg"`
}

type GetOwnedCardResponse struct {
	ID            uuid.UUID `json:"id" example:"550e8400-e29b-41d4-a716-446655440000"`
	Rarity        *string   `json:"rarity" example:"SSR"`
	CharacterName *string   `json:"character_name" example:"Hatake Kakashi"`
	SerialNumber  *string   `json:"serial_number" example:"SE-014"`
	ImageUrl      *string   `json:"image_url" example:"https://example.com/image.jpg"`
	Status        *string   `json:"status" example:"collected"`
}

type GetCollectionInfoResponse struct {
	Rarities       []string `json:"rarities" example:"[\"SSR\",\"SR\",\"R\"]"`
	CardsTotal     int64    `json:"cards_total" example:"100"`
	CardsCollected int64    `json:"cards_collected" example:"100"`
}
