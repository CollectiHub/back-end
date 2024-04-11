package validation

import (
	"collectihub/internal/constants"

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

	return v
}
