package database

import (
	"collectihub/internal/config"
	"collectihub/internal/data"
	"context"
	"log"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func New(cfg config.Config) *gorm.DB {
	db, err := gorm.Open(postgres.Open(cfg.DB_DSN), &gorm.Config{TranslateError: false})
	if err != nil {
		log.Fatalf("Failed to open database: %s", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = db.WithContext(ctx).Error
	if err != nil {
		log.Fatalf("Failed to connect context: %s", err)
	}

	if cfg.Env == config.EnvDev {
		db.Debug().Exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`)
		db.Debug().Exec(`
			DO $$ BEGIN
				CREATE TYPE user_role AS ENUM ('regular', 'admin');
			EXCEPTION
				WHEN duplicate_object THEN null;
			END $$;
		`)
		db.Debug().Exec(`
			DO $$ BEGIN
				CREATE TYPE verification_type AS ENUM ('email-verification', 'password-reset');
			EXCEPTION
				WHEN duplicate_object THEN null;
			END $$;
		`)

		migration_models := []interface{}{
			&data.User{},
			&data.RefreshToken{},
			&data.VerificationCode{},
			&data.Manufacturer{},
		}

		for i := 0; i < len(migration_models); i++ {
			if err = db.AutoMigrate(migration_models[i]); err != nil {
				log.Fatalf("Failed to auto migrate: %s", err)
			}
		}
	}

	return db
}
