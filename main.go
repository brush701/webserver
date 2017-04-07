package main

import (
	//"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"
	"fmt"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	r := mux.NewRouter()

	r.Handle("/", http.FileServer(http.Dir("./views/")))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	// Manual Token
	r.Handle("/login", LoginHandler).Methods("GET")

	http.ListenAndServe(":80", handlers.LoggingHandler(os.Stdout, r))
}

// Handlers
var LoginHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	user := "ben"
	w.Write(GetToken(user))
})

func GetToken(user string) []byte{
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["UID"] = 1 //This is where we look up user in db
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET_KEY")))
	if err != nil {
		log.Fatal(err)
	}
	return []byte(tokenString)
}

func ParseToken(myToken string, myKey string) (*jwt.Token, error) {
    token, err := jwt.Parse(myToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			         return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			     }
				return []byte(myKey), nil
    })

    if err == nil && token.Valid {
			claims := token.Claims.(jwt.MapClaims)
			expiration, err := time.Parse(time.RFC822, claims["exp"].(string))
			if err !=  nil {
				return nil, errors.New("Invalid Token Expiration")
			}
			if expiration.After(time.Now()) {
				return nil, errors.New("Exipred Token")
			}
        return token, nil
    } else {
        return nil, errors.New("Invalid Token")
    }
}

func ValidateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
		// Get token from the Authorization header
    // format: Authorization: Bearer
		var token string
    tokens, ok := r.Header["Authorization"]
    if ok && len(tokens) >= 1 {
        token = tokens[0]
        token = strings.TrimPrefix(token, "Bearer ")
    }

    // If the token is empty...
    if token == "" {
        // If we get here, the required token is missing
        http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
        return
    }

		_, err := ParseToken(token, os.Getenv("SECRET_KEY"))
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		}

		//should do some permissions validation here...

		next.ServeHTTP(w,r)
	})
}

var NotImplemented = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Not Implemented"))
})

var StatusHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("API is up and running"))
})
