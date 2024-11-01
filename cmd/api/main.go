package main

import (
	"kadocore/internal/auth"
	"kadocore/internal/config"
	"kadocore/internal/data"
	"kadocore/internal/database"
	"kadocore/internal/mailer"
	"kadocore/internal/util/logger"
	"sync"

	"github.com/rs/zerolog"
)

const version = "1.0.0"

type application struct {
	config *config.Config
	logger *zerolog.Logger
	models data.Models
	mailer *mailer.Mailer
	oauth  auth.OAuthConfig
	wg     sync.WaitGroup
}

//	@title			KadoCore API
//	@version		1.0
//	@description	This API documentation describes endpoints and models you will face with during interaction with KadoCore APIs

//	@contact.name	Back-end engineer
//	@contact.email	ka1tzyu@gmail.com
//	@contant.url	https://t.me/@higharmored

//	@securityDefinitions.apiKey	BearerAuth
//	@in							header
//	@name						Authorization

// @host		localhost:4000
// @BasePath	/api/v1
func main() {
	cfg := config.New()
	logger := logger.New(cfg.Env == config.EnvDev)
	db := database.New(*cfg)
	mailer := mailer.New(*cfg, logger)
	oauth := auth.NewOAuth(*cfg)

	app := &application{
		config: cfg,
		logger: logger,
		models: data.NewModels(db, logger),
		mailer: mailer,
		oauth:  oauth,
	}

	// Call app.serve() to start the server.
	if err := app.serve(); err != nil {
		logger.Fatal().Err(err).Msg("Failed to start server")
	}
}
