package util

import (
	"collectihub/api/models"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

// CreateToken creates a JSON Web Token (JWT) with the specified time-to-live (TTL),
// user payload, and private key. It returns the generated token as a string.
// The TTL determines the expiration time of the token.
// The payload parameter contains the user information that will be included in the token.
// The privateKey parameter is the base64-encoded RSA private key used for signing the token.
// If the private key cannot be decoded or parsed, an error is returned.
// The function sets various claims in the token, including the subject (sub), expiration time (exp),
// issued at time (iat), not before time (nbf), username, email, verified status, OAuth provider,
// OAuth identity, and user role.
// Finally, the function signs the token using the RSA private key and returns the signed token.
// If signing the token fails, an error is returned.
func CreateToken(ttl time.Duration, payload models.User, privateKey string) (string, error) {
	decodedPrivateKey, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("could not decode key: %s", err)
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(decodedPrivateKey)
	if err != nil {
		return "", fmt.Errorf("could not parse key: %s", err)
	}

	now := time.Now().UTC()

	claims := make(jwt.MapClaims)

	// Settings claims
	claims["sub"] = payload.ID.String()
	claims["exp"] = now.Add(ttl).Unix()
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()

	claims["username"] = payload.Username
	claims["email"] = payload.Email
	claims["verified"] = payload.Verified
	claims["oauth_provider"] = payload.OAuthProvider
	claims["oauth_identity"] = payload.OAuthIndentity
	claims["role"] = payload.Role

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		return "", fmt.Errorf("could not sign key: %s", err)
	}

	return token, nil
}

// ValidateToken validates a JWT token using the provided public key.
// It decodes the base64 encoded public key, parses it as an RSA public key, and then uses it to verify the token's signature.
// If the token is valid, it returns the subject claim from the token.
// If the token is invalid or any error occurs during the validation process, it returns an error.
func ValidateToken(token string, publicKey string) (interface{}, error) {
	decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("could not decode key: %s", err)
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(decodedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("could not parse key: %s", err)
	}

	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %s", err)
		}

		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("not validated: %s", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return nil, fmt.Errorf("validate: invalid token")
	}

	return claims["sub"], nil
}
