package database

import (
	"aya/api/resources/user"
	"aya/internal/config"
	"context"
	"log"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func New(cfg config.Config) *gorm.DB {
	db, err := gorm.Open(postgres.Open(cfg.DB.DSN), &gorm.Config{})
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
		if err = db.AutoMigrate(&user.User{}); err != nil {
			log.Fatalf("Failed to auto migrate: %s", err)
		}
	}

	return db
}
