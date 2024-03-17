package main

import (
	"aya/api/router"
	"aya/internal/config"
	"aya/internal/database"
	"aya/internal/util/logger"
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
		Handler:      router.New(nil, db),
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
