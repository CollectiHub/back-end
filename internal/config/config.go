package config

import (
	"log"
	"os"
	"path"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	Port int
	Env  string
	DB   struct {
		DSN string
	}
}

const EnvDev = "development"
const EnvProd = "production"

func New() *Config {
	var cfg Config

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get cwd: %s", err)
	}

	envPath := path.Join(cwd, ".env")
	godotenv.Load(envPath)

	cfg.Port, err = strconv.Atoi(os.Getenv("PORT"))
	if err != nil {
		log.Fatalf("Failed to convert port: %s", err)
	}

	cfg.Env = os.Getenv("ENV")
	cfg.DB.DSN = os.Getenv("PG_CONNECTION_STRING")

	return &cfg
}
