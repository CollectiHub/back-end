package data

import "gorm.io/gorm"

type Models struct {
	Users             UserModel
	VerificationCodes VerificationCodeModel
	RefreshTokens     RefreshTokenModel
	Manufacturers     ManufacturerModel
}

func NewModels(db *gorm.DB) Models {
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
	}
}
