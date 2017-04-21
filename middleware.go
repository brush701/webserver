package main

import (
  "net/http"
  "os"
  jwt "github.com/dgrijalva/jwt-go"
  "errors"
  "fmt"
)

func attemtAccess(r *http.Request, role string) error {
  t, err := retrieveTokenFromHeader(r)

  // If the token is empty...
  if t == "" {
    errors.New("No token provided")
  }
  if err != nil {
      return err
  }

  token, err := parseToken(t, os.Getenv("SECRET_KEY"))
  if err != nil {
    return err
  }

  claims := token.Claims.(jwt.MapClaims)

  if claims["role"] != role {
    return fmt.Errorf("User role %s does not match required role %s", claims["role"], role)
  }

  return nil
}

//VerifyAdmin is a middleware layer that permits only admin users to proceed.
//Users are authenticated via jwt. These tokens are produced by the LoginHandler
func VerifyAdmin(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
    err := attemtAccess(r, "admin")

    if err != nil {
      http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
      return
    }
		next.ServeHTTP(w,r)

	})
}

//VerifyUser is a middleware layer that permits any logged in user to proceed.
//Users are authenticated via jwt. These tokens are produced by the LoginHandler
func VerifyUser(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
    err := attemtAccess(r, "user")

    if err != nil {
      http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
      return
    }
		next.ServeHTTP(w,r)

	})
}
