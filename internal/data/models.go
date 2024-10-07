package data

import (
	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

type Models struct {
	Users             UserModel
	VerificationCodes VerificationCodeModel
	RefreshTokens     RefreshTokenModel
	Manufacturers     ManufacturerModel
	Cards             CardModel
}

func NewModels(db *gorm.DB, logger *zerolog.Logger) Models {
	return Models{
		Users: UserModel{
			DB: db,
		},
		VerificationCodes: VerificationCodeModel{
			DB: db,
		},
		RefreshTokens: RefreshTokenModel{
			DB: db,
		},
		Manufacturers: ManufacturerModel{
			DB: db,
		},
		Cards: CardModel{
			DB:     db,
			logger: logger,
		},
	}
}
