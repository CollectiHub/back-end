package main

import (
	"collectihub/api/router"
	"collectihub/internal/config"
	"collectihub/internal/database"
	"collectihub/internal/util/logger"
	"fmt"
	"net/http"
	"time"
)

//	@title			CollectiHub API
//	@version		1.0
//	@description	This API documentation describes endpoints and models you will face with during interaction with CollectiHub APIs

//	@contact.name	Back-end engineer
//	@contact.email	ka1tzyu@gmail.com
//	@contant.url	https://t.me/@higharmored

//	@securityDefinitions.apiKey	BearerAuth
//	@in							header
//	@name						Authorization

//	@host		localhost:4000
//	@BasePath	/api/v1
func main() {
	cfg := config.New()
	logger := logger.New(cfg.Env == config.EnvDev)
	db := database.New(*cfg)

	srv := &http.Server{
		Addr:         fmt.Sprintf("localhost:%d", cfg.Port),
		Handler:      router.New(logger, db, *cfg),
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	logger.Info().Msgf("Starting server on port %d", cfg.Port)

	err := srv.ListenAndServe()
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to start server")
	}
}
