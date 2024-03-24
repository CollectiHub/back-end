package auth

import (
	"collectihub/internal/config"
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type OAuthConfig struct {
	GoogleLoginConfig oauth2.Config
}

func NewOAuth(cfg config.Config) OAuthConfig {
	var oauthConfig OAuthConfig

	oauthConfig.GoogleLoginConfig = oauth2.Config{
		RedirectURL:  fmt.Sprintf("%s/api/v1/auth/google/callback", cfg.BaseUrl),
		ClientID:     cfg.GoogleClientId,
		ClientSecret: cfg.GoogleClientSecret,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	return oauthConfig
}
