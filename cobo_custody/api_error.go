package cobo_custody

type ApiError struct {
	ErrorId          string `json:"error_id"`
	ErrorCode        int    `json:"error_code"`
	ErrorMessage     string `json:"error_message"`
	ErrorDescription string `json:"error_description"`
}
