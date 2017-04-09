package main_test

import (
    "os"
    "net/http"
    "net/url"
    "net/http/httptest"
    "testing"
    "io/ioutil"
    "fmt"
    "strings"
    main "git.richardbenjaminrush.com/webserver"
    "github.com/jinzhu/gorm"
  _ "github.com/jinzhu/gorm/dialects/sqlite"
    "golang.org/x/crypto/bcrypt"
)

const testUser = "ben"
const testPassword = "test"

func TestMain(m *testing.M) {
  os.Setenv("DB_DIALECT","sqlite3")
  os.Setenv("DB_URL", "test.db")
  fmt.Println("Environment variables set")

  hash, _ := bcrypt.GenerateFromPassword([]byte(testPassword),main.Bcrypt_cost)

  user := main.User{
    UserName: testUser ,
    Role:"user",
    Email: "user@test.com",
    PasswordHash: hash,
  }

  adminUser := main.User{
		UserName: os.Getenv("ADMIN_USER"),
		Role: "admin",
		Email: "user@test.com",
		PasswordHash: []byte(os.Getenv("ADMIN_PWD_HASH")),
	}

  if _, err := os.Stat("/path/to/whatever"); os.IsExist(err) {
    // path/to/whatever does not exist
    os.Remove("test.db")
  }
  db, err := gorm.Open(os.Getenv("DB_DIALECT"), os.Getenv("DB_URL"))
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

  db.AutoMigrate(&main.User{})
  db.Create(&user)
  db.Create(&adminUser)
  main.DB = db

  retCode := m.Run()
  //myTeardownFunction()
  os.Exit(retCode)
}

func doLogin(user, password string) (*httptest.ResponseRecorder, error) {
  req, err := http.NewRequest("GET", "/login", nil)
  if err != nil {
      return nil, err
  }
  // We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
  rr := httptest.NewRecorder()
  handler := http.HandlerFunc(main.LoginHandler)

  req.SetBasicAuth(user,password)

  // Add our context to the request: note that WithContext returns a copy of
  // the request, which we must assign.
  //req = req.WithContext(ctx)
  handler.ServeHTTP(rr, req)
  return rr, nil
}

func getUserPage(path, token string) (*httptest.ResponseRecorder, error) {
  req, err := http.NewRequest("GET", path, nil)
  if err != nil {
      return nil, err
  }

  req.Header["Authorization"] = []string{"Bearer " + token}
  rr := httptest.NewRecorder()
  handler := http.HandlerFunc(main.ValidateToken(main.StatusHandler))

  handler.ServeHTTP(rr, req)
  return rr, nil
}

func TestLoginHandler_ValidCredentialsSucceed(t *testing.T) {

  rr, err := doLogin(testUser, testPassword)

  if err != nil {
    t.Fatal(err)
  }

  // Check the status code is what we expect.
  if status := rr.Code; status != http.StatusOK {
      t.Errorf("handler returned wrong status code: got %v want %v",
          status, http.StatusOK)
  }


  body, _ := ioutil.ReadAll(rr.Result().Body)
  token := string(body)
  // If the token is empty...
  if (token == "Unauthorized\n") {
      // If we get here, the required token is missing
      t.Errorf("no token received")
      return
  }
}

func TestLoginHandler_InvalidCredentialsFail(t *testing.T) {
  rr, err := doLogin(testUser, "wrong")

  if err != nil {
    t.Fatal(err)
  }

  // Check the status code is what we expect.
  if status := rr.Code; status != http.StatusUnauthorized {
      t.Errorf("handler returned wrong status code: got %v want %v",
          status, http.StatusUnauthorized)
  }


  body, _ := ioutil.ReadAll(rr.Result().Body)

  expected := "Unauthorized\n"
  // If the token is empty...
  if (string(body) != expected) {
      // If we get here, the required token is present (and should not be)
      t.Errorf("bad response for invalid user: Expected |%s|, got |%s|", expected, string(body))
      return
  }
}

func TestValidateToken_ValidTokenSucceed(t *testing.T) {
  rr, err := doLogin(testUser, testPassword)

  if err != nil {
    t.Fatal(err)
  }

  if status := rr.Code; status != http.StatusOK {
      t.Errorf("login handler returned wrong status code: got %v want %v",
          status, http.StatusOK)
  }


  body, _ := ioutil.ReadAll(rr.Result().Body)
  token := string(body)
  rr, err = getUserPage("/user/"+testUser, token)

  if status := rr.Code; status != http.StatusOK {
      t.Errorf("token handler returned wrong status code: got %v want %v",
          status, http.StatusOK)
  }

}

func TestValidateToken_InvalidTokenFail(t *testing.T) {
  rr, _ := getUserPage("/user/"+testUser, "badtoken")

  if status := rr.Code; status != http.StatusUnauthorized {
      t.Errorf("token handler returned wrong status code: got %v want %v",
          status, http.StatusUnauthorized)
  }

}

func TestRegisterUser_Succeed(t *testing.T) {
  form := url.Values{}
  form.Add("email", "newuser@test.com")  

  req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
  req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
  req.SetBasicAuth("newuser","newpassword")

  rr := httptest.NewRecorder()
  handler := http.HandlerFunc(main.RegisterHandler)
  handler.ServeHTTP(rr, req)

  if status := rr.Code; status != http.StatusOK {
      t.Errorf("register handler returned wrong status code: got %v want %v",
          status, http.StatusOK)
  }

}
