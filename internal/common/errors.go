package common

import (
	"collectihub/internal/constants"
	"collectihub/internal/util"
	"collectihub/types"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5/pgconn"
)

func NewDatabaseError(err error) types.HttpError {
	var pqErr *pgconn.PgError
	if !errors.As(err, &pqErr) {
		return types.HttpError{
			Status: http.StatusInternalServerError,
			Err:    errors.New(constants.UnexpectedErrorMessage),
		}
	}

	switch pqErr.Code {
	case "23505":

		return types.HttpError{
			Status: http.StatusConflict,
			Err:    fmt.Errorf("duplicate entry detected: %s is already used", util.GetFieldNameFromPqErrorDetails(pqErr.Detail)),
		}
	default:
		return types.HttpError{
			Status: http.StatusInternalServerError,
			Err:    errors.New(constants.UnexpectedErrorMessage),
		}
	}
}

func NewValidationError(err error, model interface{}) types.HttpError {
	if fieldErrors, ok := err.(validator.ValidationErrors); ok {
		messages := make([]types.DetailedError, len(fieldErrors))

		for i, err := range fieldErrors {
			legitFieldName := util.GetJsonFieldName(model, err.Field())

			switch err.Tag() {
			case "required":
				messages[i] = types.DetailedError{Field: legitFieldName, Detail: fmt.Sprintf("%s is a required field", err.Field())}
			case "min":
				messages[i] = types.DetailedError{Field: legitFieldName, Detail: fmt.Sprintf("%s must be a minimum of %s in length", err.Field(), err.Param())}
			case "email":
				messages[i] = types.DetailedError{Field: legitFieldName, Detail: fmt.Sprintf("%s must be email", err.Field())}
			case "len":
				messages[i] = types.DetailedError{Field: legitFieldName, Detail: fmt.Sprintf("%s must have %s in length", err.Field(), err.Param())}
			default:
				messages[i] = types.DetailedError{Field: legitFieldName, Detail: fmt.Sprintf("something went wrong with %s: %s", err.Field(), err.Tag())}
			}
		}

		return types.HttpError{
			Status: http.StatusUnprocessableEntity,
			Err:    messages,
		}
	}

	return types.HttpError{
		Status: http.StatusUnprocessableEntity,
		Err:    errors.New("unknown validation error occurred"),
	}
}
