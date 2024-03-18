package types

type SuccessResponse struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

type ErrorResponse struct {
	Message string      `json:"message"`
	Error   interface{} `json:"error"`
}

type DetailedPqErrorResponse struct {
	Detail string `json:"detail"`
	Field  string `json:"field"`
}
