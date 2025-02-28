// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Token represents the credentials used to authorize
// the requests to access protected resources on the OAuth 2.0
// provider's backend.
//
// This type is a mirror of oauth2.Token and exists to break
// an otherwise-circular dependency. Other internal packages
// should convert this Token into an oauth2.Token before use.
type Token struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer", the default.
	TokenType string

	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken string

	// Expiry is the optional expiration time of the access token.
	//
	// If zero, TokenSource implementations will reuse the same
	// token forever and RefreshToken or equivalent
	// mechanisms for that TokenSource will not be used.
	Expiry time.Time

	// Raw optionally contains extra metadata from the server
	// when updating a token.
	Raw interface{}
}

// tokenJSON is the struct representing the HTTP response from OAuth2
// providers returning a token or error in JSON form.
// https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
type tokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int32  `json:"expires_in"`
	// error fields
	// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

func (e *tokenJSON) expiry() (t time.Time) {
	if v := e.ExpiresIn; v != 0 {
		return time.Now().Add(time.Duration(v) * time.Second)
	}
	return
}

func RetrieveToken(ctx context.Context, clientID, clientSecret, tokenURL string, d map[string]string) (*Token, error) {
	req, err := newTokenRequest(tokenURL, clientID, clientSecret, d)
	if err != nil {
		return nil, err
	}
	token, err := doTokenRoundTrip(ctx, req)

	// Don't overwrite `RefreshToken` with an empty value
	// if this was a token refreshing request.
	r, ok := d["refresh_token"]
	if token != nil && token.RefreshToken == "" && ok {
		token.RefreshToken = r
	}
	return token, err
}

// newTokenRequest returns a new *http.Request to retrieve a new token
// from tokenURL using the provided clientID, clientSecret, and POST
// body parameters.
//
// inParams is whether the clientID & clientSecret should be encoded
// as the POST body. An 'inParams' value of true means to send it in
// the POST body (along with any values in v); false means to send it
// in the Authorization header.
func newTokenRequest(tokenURL, clientID, clientSecret string, d map[string]string) (*http.Request, error) {
	jsonData, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", tokenURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	return req, nil
}

func doTokenRoundTrip(ctx context.Context, req *http.Request) (*Token, error) {
	r, err := ContextClient(ctx).Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}

	failureStatus := r.StatusCode < 200 || r.StatusCode > 299
	retrieveError := &RetrieveError{
		Response: r,
		Body:     body,
		// attempt to populate error detail below
	}

	var token *Token
	content, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch content {
	case "application/x-www-form-urlencoded", "text/plain":
		// some endpoints return a query string
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			if failureStatus {
				return nil, retrieveError
			}
			return nil, fmt.Errorf("oauth2: cannot parse response: %v", err)
		}
		retrieveError.ErrorCode = vals.Get("error")
		retrieveError.ErrorDescription = vals.Get("error_description")
		retrieveError.ErrorURI = vals.Get("error_uri")
		token = &Token{
			AccessToken:  vals.Get("access_token"),
			TokenType:    vals.Get("token_type"),
			RefreshToken: vals.Get("refresh_token"),
			Raw:          vals,
		}
		e := vals.Get("expires_in")
		expires, _ := strconv.Atoi(e)
		if expires != 0 {
			token.Expiry = time.Now().Add(time.Duration(expires) * time.Second)
		}
	default:
		var tj tokenJSON
		if err = json.Unmarshal(body, &tj); err != nil {
			if failureStatus {
				return nil, retrieveError
			}
			return nil, fmt.Errorf("oauth2: cannot parse json: %v", err)
		}
		retrieveError.ErrorCode = tj.ErrorCode
		retrieveError.ErrorDescription = tj.ErrorDescription
		retrieveError.ErrorURI = tj.ErrorURI
		token = &Token{
			AccessToken:  tj.AccessToken,
			TokenType:    tj.TokenType,
			RefreshToken: tj.RefreshToken,
			Expiry:       tj.expiry(),
			Raw:          make(map[string]interface{}),
		}
		json.Unmarshal(body, &token.Raw) // no error checks for optional fields
	}
	// according to spec, servers should respond status 400 in error case
	// https://www.rfc-editor.org/rfc/rfc6749#section-5.2
	// but some unorthodox servers respond 200 in error case
	if failureStatus || retrieveError.ErrorCode != "" {
		return nil, retrieveError
	}
	if token.AccessToken == "" {
		return nil, errors.New("oauth2: server response missing access_token")
	}
	return token, nil
}

// mirrors oauth2.RetrieveError
type RetrieveError struct {
	Response         *http.Response
	Body             []byte
	ErrorCode        string
	ErrorDescription string
	ErrorURI         string
}

func (r *RetrieveError) Error() string {
	if r.ErrorCode != "" {
		s := fmt.Sprintf("oauth2: %q", r.ErrorCode)
		if r.ErrorDescription != "" {
			s += fmt.Sprintf(" %q", r.ErrorDescription)
		}
		if r.ErrorURI != "" {
			s += fmt.Sprintf(" %q", r.ErrorURI)
		}
		return s
	}
	return fmt.Sprintf("oauth2: cannot fetch token: %v\nResponse: %s", r.Response.Status, r.Body)
}
