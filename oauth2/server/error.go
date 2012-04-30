package server

type errorCode string

const (
	// Error codes returned by the server, following the OAuth specification.
	ErrorCodeAccessDenied            errorCode = "access_denied"
	ErrorCodeInvalidRequest          errorCode = "invalid_request"
	ErrorCodeInvalidScope            errorCode = "invalid_scope"
	ErrorCodeServerError             errorCode = "server_error"
	ErrorCodeTemporarilyUnavailable  errorCode = "temporarily_unavailable"
	ErrorCodeunauthorizedClient      errorCode = "unauthorized_client"
	ErrorCodeUnsupportedResponseType errorCode = "unsupported_response_type"
)
// Error [...]
type Error struct {
	Code        errorCode
	Description string
	URI         string
}

// Error [...]
func (e *Error) Error() string {
	return e.Code
}
