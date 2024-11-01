package validation

import (
	"database/sql/driver"
	"kadocore/internal/constants"
	"kadocore/types"
	"reflect"

	"github.com/dlclark/regexp2"
	validator_pkg "github.com/go-playground/validator/v10"
)

func New() *validator_pkg.Validate {
	v := validator_pkg.New()

	v.RegisterValidation("upassword", func(fl validator_pkg.FieldLevel) bool {
		password := fl.Field().String()
		r := regexp2.MustCompile(constants.PasswordRegex, 0)
		match, _ := r.MatchString(password)
		return match
	})

	v.RegisterCustomTypeFunc(ValidateValuer, types.NullableString{})

	return v
}

func ValidateValuer(field reflect.Value) interface{} {
	if valuer, ok := field.Interface().(driver.Valuer); ok {
		val, err := valuer.Value()
		if err == nil {
			return val
		}
		// handle the error how you want
	}

	return nil
}
