package json

import (
	"collectihub/internal/constants"
	"collectihub/internal/util"
	"collectihub/types"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5/pgconn"
)

func WriteJSON(w http.ResponseWriter, status int, message string, data interface{}) error {
	js, err := json.Marshal(&types.SuccessResponse{Message: message, Data: data})
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(js)

	return nil
}

func ErrorJSON(w http.ResponseWriter, status int, message string, err_data interface{}) error {
	// If error data is valid error instance, grab string representation and use it as error data
	if parsedError, isError := err_data.(error); isError {
		err_data = parsedError.Error()
	}

	js, err := json.Marshal(&types.ErrorResponse{Message: message, Error: err_data})
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(js)

	return nil
}

func DecodeJSON(r http.Request, data interface{}) error {
	if err := json.NewDecoder(r.Body).Decode(data); err != nil {
		return err
	}

	return nil
}

func DatabaseErrorJSON(w http.ResponseWriter, err error) {
	pqErr, ok := err.(*pgconn.PgError)
	if !ok {
		ErrorJSON(w, http.StatusBadRequest, constants.DatabaseErrorMessage, nil)
	}

	switch pqErr.Code {
	case "23505":
		ErrorJSON(w, http.StatusConflict, "Duplicate entry detected", &types.DetailedPqErrorResponse{
			Detail: pqErr.Detail,
			Field:  util.GetFieldNameFromPqErrorDetails(pqErr.Detail),
		})
	}
}

func ValidatorErrorJSON(w http.ResponseWriter, err error) {
	if fieldErrors, ok := err.(validator.ValidationErrors); ok {
		messages := make([]string, len(fieldErrors))

		for i, err := range fieldErrors {
			switch err.Tag() {
			case "required":
				messages[i] = fmt.Sprintf("%s is a required field", err.Field())
			case "min":
				messages[i] = fmt.Sprintf("%s must be a minimum of %s in length", err.Field(), err.Param())
			case "email":
				messages[i] = fmt.Sprintf("%s must be email", err.Field())
			default:
				messages[i] = fmt.Sprintf("something went wrong with %s: %s", err.Field(), err.Tag())
			}
		}

		ErrorJSON(w, http.StatusBadRequest, constants.JsonValidationErrorMessage, messages)
	}
}

func ValidateStruct(w http.ResponseWriter, payload interface{}) error {
	validate := validator.New()
	err := validate.Struct(payload)
	if err != nil {
		ValidatorErrorJSON(w, err)
		return err
	}

	return nil
}
