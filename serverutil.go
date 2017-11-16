package main

import (
  jwt "github.com/dgrijalva/jwt-go"
	"net/http"
	"time"
	"fmt"
	"strings"
  "errors"
	"log"
  "os"
)

//Create a new token for a user
//args:
//User user - User object to be authenticated
//returns:
//[]byte tokenString - string representation of JWT
func getToken(user *User) []byte{
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["UID"] = user.ID //This is where we look up user in db
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	claims["role"] = user.Role
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET_KEY")))
	if err != nil {
		log.Fatal(err)
	}
	return []byte(tokenString)
}

// Get token from the Authorization header
// Used to authenticate logged in users
// format: Authorization: Bearer
func retrieveTokenFromHeader(req *http.Request) (string, error) {
	var token string
	tokens, ok := req.Header["Authorization"]
	if ok && len(tokens) >= 1 {
			token = tokens[0]
			token = strings.TrimPrefix(token, "Bearer ")
			return token,nil
	}
	return "", errors.New("No Authorization Header Found")
}


//Converts a candidate string representation of a JWT into a JWT object
//performs basic checks for syntactic validity and expiration
func parseToken(myToken string, myKey string) (*jwt.Token, error) {
    token, err := jwt.Parse(myToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			         return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			     }
				return []byte(myKey), nil
    })

    if err == nil && token.Valid {
			claims := token.Claims.(jwt.MapClaims)

			expiration, ok := claims["exp"].(float64)
			if !ok {
				return nil, errors.New("Invalid Token Expiration")
			}
			if int64(expiration) <= time.Now().Unix() {
				return nil, errors.New("Expired Token")
			}
        return token, nil
    }
    return nil, errors.New("Invalid Token")
}

func userEmailExists(newUser User) (bool) {
  tmp := new(User)
  err :=  DB.Where(User{Email: newUser.Email}).Find(&tmp).Error
  return err == nil
}

func subscriberEmailExists(newSub Subscriber) (bool) {
  tmp := new(Subscriber)
  err :=  DB.Where(Subscriber{Email: newSub.Email}).Find(&tmp).Error
  return err == nil
}
