package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"io/ioutil"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/jinzhu/gorm"
	 _ "github.com/jinzhu/gorm/dialects/sqlite"
 "golang.org/x/crypto/bcrypt"
)
//BcryptCost is the cost perameter supplied to the bcrypt hashing function
const BcryptCost = 15

//DB is the handle for the application database. It is exported for testing
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
    VerifyAdmin(adminRouter)))

	r.PathPrefix("/user/").Handler(http.StripPrefix("/user",
    VerifyUser(userRouter)))

	adminRouter.Handle("/", StatusHandler)
	adminRouter.Handle("/list_subs", SubListHandler)
	userRouter.Handle("/", StatusHandler)

	// Manual Token
	r.Handle("/login", LoginHandler).Methods("GET")
	r.Handle("/register", RegisterHandler).Methods("POST")
	r.Handle("/subscribe", SubscribeHandler).Methods("POST")
	r.PathPrefix("/").Handler(http.StripPrefix("/", http.FileServer(http.Dir("./views/"))))
	http.ListenAndServe(":8000", handlers.LoggingHandler(os.Stdout, r))
}

//LoginHandler accepts login requests via http basic auth and
//authenticates against the users table. Successful login results in the creation
//of a Json Web Token for successive authentication
var LoginHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	//Fetch the credentials from http auth header
	user, password, ok := r.BasicAuth()
	userRecord := new(User)

	if (ok) {
		//find the matching username in the users table
	  err := DB.Where(&User{UserName: user}).Find(&userRecord).Error

		if err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

		//check the provided password against the stored hash
		err = bcrypt.CompareHashAndPassword(userRecord.PasswordHash, []byte(password))
		if (err != nil) {
			//incorrect password
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		//provide a valid JWT for the user
		w.Write(getToken(userRecord))
	}	else {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	}
})

//RegisterHandler accepts form POSTs and creates a new user.
var RegisterHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Fatal(err)
	}

	email := r.PostFormValue("email")
	username := r.PostFormValue("user")
	password := r.PostFormValue("password")
	passwordHash, _ := bcrypt.GenerateFromPassword([]byte(password),BcryptCost)

	newUser := User{
		UserName: username,
		Email: email,
		PasswordHash: passwordHash,
		Role: "user",
	}

	DB.Create(&newUser)

	w.Write(getToken(&newUser))
})

//SubscribeHandler accepts POSTs in Json format and adds the information to the
//subscribers table.
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

//SubListHandler replies to GET requests with a Json representatio of the
//subscribers table.
var SubListHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	subs := []Subscriber{}
	err := DB.Find(&subs).Error
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
	msg, err := json.Marshal(subs)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
	w.Write(msg)
})

//NotImplemented is a generic placeholder for future functionality
var NotImplemented = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Not Implemented"))
})

//StatusHandler replies to GET requests with a string message indicating
//the current API status
var StatusHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("API is up and running"))
})
