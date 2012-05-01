package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ----------------------------------------------------------------------------

// Store [...]
type Store interface {
	// A Client is always returned -- it is nil only if ClientID is invalid.
	// Use the error to indicate denied or unauthorized access.
	GetClient(clientID string) (Client, error)
	CreateAuthCode(r AuthCodeRequest) (string, error)
}

// ----------------------------------------------------------------------------

// Client is a client registered with the authorization server.
type Client interface {
	// Unique identifier for the client.
	ID() string
	// The registered client type ("confidential" or "public") as decribed in:
	// http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-2.1
	Type() string
	// The registered redirect_uri.
	RedirectURI() string
	// Validates that the provided redirect_uri is valid. It must return the
	// same provided URI or an empty string if it is not valid.
	// The specification is permissive and even allows multiple URIs, so the
	// validation rules are up to the server implementation.
	// Ref: http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-3.1.2.2
	ValidateRedirectURI(string) string
}

// ----------------------------------------------------------------------------

// AuthCodeRequest [...]
type AuthCodeRequest struct {
	ClientID     string
	ResponseType string
	RedirectURI  string
	Scope        string
	State        string
}

// AccessTokenRequest [...]
type AccessTokenRequest struct {
	GrantType   string
	Code        string
	RedirectURI string
}

// ----------------------------------------------------------------------------

// NewServer [...]
func NewServer() *Server {
	return &Server{
		errorURIs: make(map[errorCode]string),
	}
}

// Server [...]
type Server struct {
	Store     Store
	errorURIs map[errorCode]string
}

// RegisterErrorURI [...]
func (s *Server) RegisterErrorURI(code errorCode, uri string) {
	s.errorURIs[code] = uri
}

// NewError [...]
func (s *Server) NewError(code errorCode, description string) ServerError {
	return NewServerError(code, description, s.errorURIs[code])
}

// NewAuthCodeRequest [...]
func (s *Server) NewAuthCodeRequest(r *http.Request) AuthCodeRequest {
	v := r.URL.Query()
	return AuthCodeRequest{
		ClientID:     v.Get("client_id"),
		ResponseType: v.Get("response_type"),
		RedirectURI:  v.Get("redirect_uri"),
		Scope:        v.Get("scope"),
		State:        v.Get("state"),
	}
}

// HandleAuthCodeRequest [...]
func (s *Server) HandleAuthCodeRequest(w http.ResponseWriter, r *http.Request) error {
	// 1. Get all request values.
	req := s.NewAuthCodeRequest(r)

	// 2. Validate required parameters.
	var err error
	if req.ClientID == "" {
		// Missing ClientID: no redirect.
		err = s.NewError(ErrorCodeInvalidRequest,
			"The \"client_id\" parameter is missing.")
	} else if req.ResponseType == "" {
		err = s.NewError(ErrorCodeInvalidRequest,
			"The \"response_type\" parameter is missing.")
	} else if req.ResponseType != "code" {
		err = s.NewError(ErrorCodeUnsupportedResponseType,
			fmt.Sprintf("The response type %q is not supported.",
			req.ResponseType))
	}

	// 3. Load client and validate the redirection URI.
	var redirectURI *url.URL
	if req.ClientID != "" {
		client, clientErr := s.Store.GetClient(req.ClientID)
		if client == nil {
			// Invalid ClientID: no redirect.
			if err == nil {
				err = s.NewError(ErrorCodeInvalidRequest,
					"The \"client_id\" parameter is invalid.")
			}
		} else {
			if u, uErr := validateRedirectURI(
				client.ValidateRedirectURI(req.RedirectURI)); uErr == nil {
				redirectURI = u
			} else {
				// Missing, mismatching or invalid URI: no redirect.
				if err == nil {
					if req.RedirectURI == "" {
						err = s.NewError(ErrorCodeInvalidRequest,
							"Missing redirection URI.")
					} else {
						err = s.NewError(ErrorCodeInvalidRequest, uErr.Error())
					}
				}
			}
			if clientErr != nil && err == nil {
				// Client was not authorized.
				err = clientErr
			}
		}
	}

	// 4. If no valid redirection URI was set, abort.
	if redirectURI == nil {
		// An error occurred because client_id or redirect_uri are invalid:
		// the caller must display an error page and don't redirect.
		return err
	}

	// 5. Add the response data to the URL and redirect.
	query := redirectURI.Query()
	setQueryPairs(query, "state", req.State)
	var code string
	if err == nil {
		code, err = s.Store.CreateAuthCode(req)
	}
	if err == nil {
		// Success.
		query.Set("code", code)
	} else {
		e, ok := err.(ServerError)
		if !ok {
			e = s.NewError(ErrorCodeServerError, e.Error())
		}
		setQueryPairs(query,
			"error", string(e.Code()),
			"error_description", e.Description(),
			"error_uri", e.URI(),
		)
	}
	redirectURI.RawQuery = query.Encode()
	http.Redirect(w, r, redirectURI.String(), 302)
	return nil
}

// ----------------------------------------------------------------------------

// setQueryPairs sets non-empty values in a url.Values.
//
// This is just a convenience to avoid checking for emptiness for each value.
func setQueryPairs(v url.Values, pairs ...string) {
	for i := 0; i < len(pairs); i += 2 {
		if pairs[i+1] != "" {
			v.Set(pairs[i], pairs[i+1])
		}
	}
}

// validateRedirectURI checks if a redirection URL is valid.
func validateRedirectURI(uri string) (u *url.URL, err error) {
	u, err = url.Parse(uri)
	if err != nil {
		err = fmt.Errorf("The redirection URI is malformed: %q.", uri)
	} else if !u.IsAbs() {
		err = fmt.Errorf("The redirection URI must be absolute: %q.", uri)
	} else if u.Fragment != "" {
		err = fmt.Errorf(
			"The redirection URI must not contain a fragment: %q.", uri)
	}
	return
}

// randomString generates authorization codes or tokens with a given strength.
func randomString(strength int) string {
	s := make([]byte, strength)
	if _, err := rand.Read(s); err != nil {
		return ""
	}
	return strings.TrimRight(base64.URLEncoding.EncodeToString(s), "=")
}
