package types

type SuccessResponse struct {
	Message string      `json:"message" example:"Success!"`
	Data    interface{} `json:"data"`
}

type ErrorResponse struct {
	Message string          `json:"message"`         // messsage describing an error
	Error   string          `json:"error,omitempty"` // error type
	Errors  []DetailedError `json:"errors,omitempty"`
}

type DetailedError struct {
	Field  string `json:"field"`  // problematic field on which error occured, if error has no specific errored field (in case of general error) this field will be "" (empty string)
	Detail string `json:"detail"` // detail of field's error, if error is unknown, this field will be "" (empty string)
}

type HttpError struct {
	Status int
	Err    interface{}
}
