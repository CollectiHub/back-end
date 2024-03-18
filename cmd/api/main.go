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

func main() {
	cfg := config.New()
	logger := logger.New(cfg.Env == config.EnvDev)
	db := database.New(*cfg)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
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
