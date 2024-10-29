package util

import (
	"math/rand"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
)

func Decapitalize(s string) string {
	if len(s) == 0 {
		return s
	}

	return string(s[0]+32) + s[1:]
}

func GetJsonFieldName(obj interface{}, field string) string {
	val := reflect.ValueOf(obj)
	for i := 0; i < reflect.Indirect(val).NumField(); i++ {
		t := reflect.Indirect(val).Type().Field(i)

		if t.Name == field {
			jsonTag := t.Tag.Get("json")

			if jsonTag == "" || jsonTag == "-" {
				return ""
			}

			var commaIdx int
			if commaIdx = strings.Index(jsonTag, ","); commaIdx < 0 {
				commaIdx = len(jsonTag)
			}

			return jsonTag[:commaIdx]
		}
	}

	return ""
}

func GenerateRandomString(length int) string {
	return generateRandomStringWithCharset(length, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
}

func GenerateRandomNumberString(length int) string {
	return generateRandomStringWithCharset(length, "1234567890")
}

func GenerateCleanUUID() string {
	id := uuid.New()
	return strings.ReplaceAll(id.String(), "-", "")
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
