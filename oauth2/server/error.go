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

// NewServerError [...]
func NewServerError(code errorCode, description, uri string) ServerError {
	return ServerError{code, description, uri}
}

// ServerError [...]
type ServerError struct {
	code        errorCode
	description string
	uri         string
}

// Error [...]
func (e ServerError) Error() string {
	return string(e.code)
}

// Code [...]
func (e ServerError) Code() errorCode {
	return e.code
}

// Description [...]
func (e ServerError) Description() string {
	return e.description
}

// URI [...]
func (e ServerError) URI() string {
	return e.uri
}
