package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"
	"fmt"
	"strings"
	"io/ioutil"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	//"github.com/gorilla/csrf"
	"github.com/joho/godotenv"
	"github.com/jinzhu/gorm"
	 _ "github.com/jinzhu/gorm/dialects/sqlite"
 "golang.org/x/crypto/bcrypt"
)

const Bcrypt_cost = 15
var DB *gorm.DB


func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}


	DB, err = gorm.Open(os.Getenv("DB_DIALECT"), os.Getenv("DB_URL"))
	if err != nil {
		panic("failed to connect database")
	}
	defer DB.Close()

	DB.AutoMigrate(&User{})
	DB.AutoMigrate(&Subscriber{})

	adminUser := User{
		UserName: os.Getenv("ADMIN_USER"),
		Role: "admin",
		Email: "user@test.com",
		PasswordHash: []byte(os.Getenv("ADMIN_PWD_HASH")),
	}

	DB.Create(&adminUser)

	r := mux.NewRouter()
	adminRouter := mux.NewRouter()
	userRouter := mux.NewRouter()


	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	r.PathPrefix("/admin/").Handler(http.StripPrefix("/admin",
    ValidateToken(adminRouter)))

	r.PathPrefix("/user/").Handler(http.StripPrefix("/user",
    ValidateToken(userRouter)))

	adminRouter.Handle("/", StatusHandler)
	userRouter.Handle("/", StatusHandler)

	// Manual Token
	r.Handle("/login", LoginHandler).Methods("GET")
	r.Handle("/register", RegisterHandler).Methods("POST")
	r.Handle("/subscribe", SubscribeHandler).Methods("POST")
	r.PathPrefix("/").Handler(http.StripPrefix("/", http.FileServer(http.Dir("./views/"))))
	http.ListenAndServe(":8000", handlers.LoggingHandler(os.Stdout, r))
}

// Handlers
var LoginHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	user, password, ok := r.BasicAuth()
	userRecord := new(User)

	if (ok) {
	  err := DB.Where(&User{UserName: user}).Find(&userRecord).Error


		if err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

		err = bcrypt.CompareHashAndPassword(userRecord.PasswordHash, []byte(password))
		if (err != nil) {
			//incorrect password
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		w.Write(getToken(userRecord))
	}	else {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	}//w.Header().Set("X-CSRF-Token", csrf.Token(r))

})

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

func retrieveTokenFromHeader(req *http.Request) (string, error) {
	// Get token from the Authorization header
	// format: Authorization: Bearer
	var token string
	tokens, ok := req.Header["Authorization"]
	if ok && len(tokens) >= 1 {
			token = tokens[0]
			token = strings.TrimPrefix(token, "Bearer ")
			return token,nil
	} else { return "", errors.New("No Authorization Header Found")}
}

func parseToken(myToken string, myKey string) (*jwt.Token, error) {
    token, err := jwt.Parse(myToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			         return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			     }
				return []byte(myKey), nil
    })

    if err == nil && token.Valid {
			claims := token.Claims.(jwt.MapClaims)

			expiration := int64(claims["exp"].(float64))
			if err !=  nil {
				return nil, errors.New("Invalid Token Expiration")
			}
			if expiration <= time.Now().Unix() {
				return nil, errors.New("Exipred Token")
			}
        return token, nil
    } else {
        return nil, errors.New("Invalid Token")
    }
}

func VerifyAdmin(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
		tokenString, err := retrieveTokenFromHeader(r)

    // If the token is empty...
    if tokenString == "" || err != nil {
        http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
        return
    }

		token, err := parseToken(tokenString, os.Getenv("SECRET_KEY"))
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		claims := token.Claims.(jwt.MapClaims)

		if claims["role"] != "admin" {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w,r)
	})
}

func ValidateToken(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {

		token, err := retrieveTokenFromHeader(r)

    // If the token is empty...
    if token == "" || err != nil {
        // If we get here, the required token is missing
        http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
        return
    }

		_, err = parseToken(token, os.Getenv("SECRET_KEY"))
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w,r)
	})
}

var RegisterHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	err := r.ParseForm()
	if err != nil {
		log.Fatal(err)
	}

	passwordHash, _ := bcrypt.GenerateFromPassword([]byte(password),Bcrypt_cost)
	email := r.PostFormValue("email")

	newUser := User{
		UserName: username,
		Email: email,
		PasswordHash: passwordHash,
		Role: "user",
	}

	DB.Create(&newUser)

	w.Write(getToken(&newUser))
})

var SubscribeHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	var newSubscriber = Subscriber{}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}

	err = json.Unmarshal(body, &newSubscriber)

	DB.Create(&newSubscriber)

	w.Write([]byte(http.StatusText(http.StatusOK)))
})

var NotImplemented = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Not Implemented"))
})

var StatusHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("API is up and running"))
})
