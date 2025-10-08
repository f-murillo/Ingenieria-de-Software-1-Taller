package main

import (
	"errors"
	"net/http"
)

/*
AuthError is returned by Authorize for any authorization failure.
Using a single sentinel error simplifies comparisons.
*/
var AuthError = errors.New("Unauthorized")

/*
Authorize derives the username from the session_token cookie by:
1) reading the session_token cookie (must exist)
2) finding the user in the DB who owns that session token
3) comparing the token from cookie and DB (defense in depth)
4) verifying the X-CSRF-Token header matches the stored csrf_token
On success returns the username; on failure returns AuthError.
This avoids trusting a client-provided username and mitigates session
fixation and CSRF attacks.
*/
func Authorize(r *http.Request) (string, error) {
	// Read session cookie.
	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" {
		return "", AuthError
	}

	// Lookup the user that holds this session token.
	user, err := getUserBySessionToken(st.Value)
	if err != nil {
		return "", AuthError
	}

	// Ensure DB actually contains a non-null session token and it matches.
	if !user.SessionToken.Valid || st.Value != user.SessionToken.String {
		return "", AuthError
	}

	// Validate CSRF token: client must send the CSRF token in a header.
	csrf := r.Header.Get("X-CSRF-Token")
	if csrf == "" {
		return "", AuthError
	}
	if !user.CSRFToken.Valid || csrf != user.CSRFToken.String {
		return "", AuthError
	}

	// All checks passed; return the canonical username from the DB.
	return user.Username, nil
}
