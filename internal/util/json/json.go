package json

import (
	"encoding/json"
	"kadocore/internal/validation"
	"kadocore/types"
	"net/http"
)

func WriteJSON(w http.ResponseWriter, status int, message string, data interface{}, header http.Header) error {
	if data == nil {
		data = struct{}{}
	}

	js, err := json.Marshal(&types.SuccessResponse{Message: message, Data: data})
	if err != nil {
		return err
	}

	for key, value := range header {
		w.Header()[key] = value
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(js)

	return nil
}

func ErrorJSON(w http.ResponseWriter, message string, httpError types.HttpError) error {
	var js []byte
	var err error

	// If error data is valid error instance, grab string representation and use it as error data
	if parsedError, ok := httpError.Err.(error); ok {
		js, err = json.Marshal(&types.ErrorResponse{Message: message, Error: parsedError.Error()})
	} else if parsedErrors, ok := httpError.Err.([]types.DetailedError); ok {
		js, err = json.Marshal(&types.ErrorResponse{Message: message, Errors: parsedErrors})
	} else {
		js, err = json.Marshal(&types.ErrorResponse{Message: message, Error: ""})
	}

	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpError.Status)
	w.Write(js)

	return nil
}

func DecodeJSON(r http.Request, data interface{}) error {
	if err := json.NewDecoder(r.Body).Decode(data); err != nil {
		return err
	}

	return nil
}

func ValidateStruct(w http.ResponseWriter, payload interface{}) error {
	validate := validation.New()
	err := validate.Struct(payload)
	if err != nil {
		return err
	}

	return nil
}
