package config

import (
	"log"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Port       int    `mapstructure:"PORT"`
	Env        string `mapstructure:"ENV"`
	HostDomain string `mapstructure:"HOST_DOMAIN"`

	DB_DSN string `mapstructure:"PG_CONNECTION_STRING"`

	AccessTokenPrivateKey string        `mapstructure:"ACCESS_TOKEN_PRIVATE_KEY"`
	AccessTokenPublicKey  string        `mapstructure:"ACCESS_TOKEN_PUBLIC_KEY"`
	AccessTokenExpiresIn  time.Duration `mapstructure:"ACCESS_TOKEN_EXPIRE"`

	RefreshTokenPrivateKey string        `mapstructure:"REFRESH_TOKEN_PRIVATE_KEY"`
	RefreshTokenPublicKey  string        `mapstructure:"REFRESH_TOKEN_PUBLIC_KEY"`
	RefreshTokenExpiresIn  time.Duration `mapstructure:"REFRESH_TOKEN_EXPIRE"`
}

const EnvDev = "development"
const EnvProd = "production"

func New() *Config {
	var cfg Config

	viper.AddConfigPath(".")
	viper.SetConfigType("env")
	viper.SetConfigFile(".env")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Failed to read in config: %s", err)
	}

	if err := viper.Unmarshal(&cfg); err != nil {
		log.Fatalf("Failed to unmarshal config: %s", err)
	}

	return &cfg
}
