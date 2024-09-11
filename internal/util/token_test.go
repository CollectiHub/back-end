package util

import (
	"collectihub/internal/data"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
	"time"
)

func TestCreateToken(t *testing.T) {
	t.Run("should return error on empty privateKey", func(t *testing.T) {
		gotValue, gotError := CreateToken(time.Minute, data.User{}, "")

		if gotError == nil {
			t.Errorf("expected error, got = %s", gotValue)
		}
	})

	t.Run("should return access token", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Errorf("error happended during test case preparation: %s", err)
			return
		}

		privBlock := pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}

		privatePEM := pem.EncodeToMemory(&privBlock)
		encodedPrivateKey := base64.StdEncoding.EncodeToString(privatePEM)

		_, gotError := CreateToken(time.Minute, data.User{}, encodedPrivateKey)

		if gotError != nil {
			t.Errorf("expected access token, got error = %s", gotError)
		}
	})
}

func TestValidateToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("error happended during test case preparation: %s", err)
		return
	}

	privBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	privatePEM := pem.EncodeToMemory(&privBlock)
	encodedPrivateKey := base64.StdEncoding.EncodeToString(privatePEM)

	validAccessToken, err := CreateToken(time.Minute*5, data.User{}, encodedPrivateKey)
	if err != nil {
		t.Errorf("error happended during test case preparation: %s", err)
		return
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Errorf("error happended during test case preparation: %s", err)
		return
	}

	pubBlock := pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubBytes,
	}

	publicPEM := pem.EncodeToMemory(&pubBlock)
	encodedPublicKey := base64.StdEncoding.EncodeToString(publicPEM)

	t.Run("should not validate token with invalid public key", func(t *testing.T) {
		gotValue, gotError := ValidateToken("", "")

		if gotError == nil {
			t.Errorf("expected error, got value = %s", gotValue)
		}
	})

	t.Run("should not validate token with invalid token", func(t *testing.T) {
		gotValue, gotError := ValidateToken("", encodedPublicKey)

		if gotError == nil {
			t.Errorf("expected error, got value = %s %s", gotValue, validAccessToken)
		}
	})

	t.Run("should validate token", func(t *testing.T) {
		gotValue, gotError := ValidateToken(validAccessToken, encodedPublicKey)

		if gotError != nil {
			t.Errorf("expected value, got error = %s", gotError)
		}

		if gotValue == nil {
			t.Errorf("expected value, got nil")
		}
	})
}
