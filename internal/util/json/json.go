package json

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-playground/validator/v10"
)

func WriteJSON(w http.ResponseWriter, status int, data interface{}, wrap string) error {
	wrapper := make(map[string]interface{})

	wrapper[wrap] = data

	js, err := json.Marshal(wrapper)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(js)

	return nil
}

func ErrorJSON(w http.ResponseWriter, status int, err error) {
	type jsonError struct {
		Message string `json:"message"`
	}

	theError := jsonError{
		Message: err.Error(),
	}

	WriteJSON(w, status, theError, "error")
}

func DecodeJSON(r http.Request, data interface{}) error {
	if err := json.NewDecoder(r.Body).Decode(data); err != nil {
		return err
	}

	return nil
}

func ValidatorErrorJSON(w http.ResponseWriter, err error) {
	type jsonValidationErrors struct {
		Message []string `json:"message"`
	}

	if fieldErrors, ok := err.(validator.ValidationErrors); ok {
		resp := jsonValidationErrors{
			Message: make([]string, len(fieldErrors)),
		}

		for i, err := range fieldErrors {
			switch err.Tag() {
			case "required":
				resp.Message[i] = fmt.Sprintf("%s is a required field", err.Field())
			case "min":
				resp.Message[i] = fmt.Sprintf("%s must be a minimum of %s in length", err.Field(), err.Param())
			default:
				resp.Message[i] = fmt.Sprintf("something went wrong with %s: %s", err.Field(), err.Tag())
			}
		}

		WriteJSON(w, http.StatusBadRequest, resp, "error")
	}
}
