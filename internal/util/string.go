package util

import (
	"math/rand"
	"time"
)

func GenerateRandomString(length int) string {
	return generateRandomStringWithCharset(length, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
}

func GenerateRandomNumberString(length int) string {
	return generateRandomStringWithCharset(length, "1234567890")
}

func generateRandomStringWithCharset(length int, charset string) string {
	seed := rand.NewSource(time.Now().UnixNano())
	random := rand.New(seed)

	result := make([]byte, length)
	for i := range result {
		result[i] = charset[random.Intn(len(charset))]
	}

	return string(result)
}
