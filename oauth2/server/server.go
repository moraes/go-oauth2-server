package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Store [...]
type Store interface {
	// A Client is always returned -- it is nil only if ClientID is invalid.
	// Use the error to indicate denied or unautorized access.
	GetClient(*http.Request, clientID, scope string) (*Client, error)
	CreateAuthCode(*AuthCodeRequest) (string, error)
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
	ValidateRedirectURI(string) (string, error)
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

// Encode [...]
func (r *AuthCodeRequest) Encode() string {
	v := url.Values{}
	setQueryPairs(v,
		"client_id", r.ClientID,
		"response_type", r.ResponseType,
		"redirect_uri", r.RedirectURI,
		"scope", r.Scope,
		"state", r.State,
	)
	return v.Encode()
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
func (s *Server) NewError(code errorCode, description string) error {
	return NewServerError(code, description, s.errorURIs[code])
}

// NewAuthCodeRequest [...]
func (s *Server) NewAuthCodeRequest(r *http.Request) (*AuthCodeRequest, error) {
	// 1. Get data from the URL query.
	q := r.URL.Query()
	req := &AuthCodeRequest{
		ClientID:     q.Get("client_id"),
		ClientSecret: q.Get("client_secret"),
		ResponseType: q.Get("response_type"),
		RedirectURI:  q.Get("redirect_uri"),
		Scope:        q.Get("scope"),
		State:        q.Get("state"),
	}
	var err error
	// 2. Validate required parameters.
	if req.ClientID == "" {
		// Missing ClientID: no redirect.
		req.RedirectURI = ""
		err = s.NewError(ErrorCodeInvalidRequest,
			"The \"client_id\" parameter is missing.")
	} else if req.ResponseType == "" {
		err = s.NewError(ErrorCodeInvalidRequest,
			"The \"response_type\" parameter is missing.")
	} else if req.ResponseType != "code" {
		err = s.NewError(ErrorCodeUnsupportedResponseType,
			fmt.Sprintf("The response type %q is not supported.",
			req.ResponseType)
	}
	// 3. Load client and validate the redirection URL.
	if req.ClientID != "" {
		client, clientErr := s.Store.GetClient(r, req)
		if client == nil {
			// Invalid ClientID: no redirect.
			req.RedirectURI = ""
			if err == nil {
				err = s.NewError(ErrorCodeInvalidRequest,
					"The \"client_id\" parameter is invalid.")
			}
		} else {
			req.RedirectURI = client.ValidateRedirectURI(req.RedirectURI)
			if req.RedirectURI == "" {
				// Missing, mismatching or invalid URI: no redirect.
				if err == nil {
					err = s.NewError(ErrorCodeInvalidRequest,
						fmt.Sprintf("The redirection URI %q is invalid.",
						req.RedirectURI))
				}
			} else if e := validateRedirectURI(req.RedirectURI); e != nil {
				// Invalid URI: no redirect.
				req.RedirectURI = ""
				if err == nil {
					err = s.NewError(ErrorCodeInvalidRequest, e.Error())
				}
			}
			if clientErr != nil && err == nil {
				// Client is valid but was not authorized.
				err = clientErr
			}
		}
	}
	return req, err
}

// An error is returned only if the redirection doesn't occur because
// the client_id or redirect_uri are invalid. In this case the caller
// must display an error page.
func (s *Server) HandleAuthCodeRequest(w http.ResponseWriter, r *http.Request) error {
	if req.Method != "GET" && req.Method != "POST" {
	}
	req, err := s.NewAuthCodeRequest(r)
	if req.RedirectURI == "" {
		// An error occurred because client_id or redirect_uri are invalid:
		// the caller must display an error page and don't redirect.
		return err
	}
	redirectURI, _ := url.Parse(req.RedirectURI)
	query := u.Query()
	setQueryPairs(query, "state", req.State)
	var code string
	if err == nil {
		code, err = s.Store.CreateAuthCode(req)
	}
	if err == nil {
		// Success.
		query.Set("code", code)
	} else {
		// Add the error to the redirection URI.
		e, ok := err.(Error)
		if !ok {
			e = s.NewError(ErrorCodeServerError, e.Error())
		}
		setQueryPairs(query,
			"error", e.Code(),
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
func validateRedirectURI(uri string) error {
	u, err = url.Parse(uri)
	if err != nil {
		err = fmt.Errorf("The redirection URI is malformed: %q.", uri)
	} else if !u.IsAbs() {
		err = fmt.Errorf("The redirection URI must be absolute: %q.", uri)
	} else if u.Fragment != "" {
		err = fmt.Errorf(
			"The redirection URI must not contain a fragment: %q.", uri)
	}
	return err
}

// randomString generates authorization codes or tokens with a given strength.
func randomString(strength int) string {
	s := make([]byte, strength)
	if _, err := rand.Read(s); err != nil {
		return nil
	}
	return strings.TrimRight(base64.URLEncoding.EncodeToString(s), "=")
}
