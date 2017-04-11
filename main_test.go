package main_test

import (
    "os"
  	"encoding/json"
    "net/http"
    "net/url"
    "net/http/httptest"
    "testing"
    "io/ioutil"
    "fmt"
    "strings"
    "bytes"
    main "git.richardbenjaminrush.com/webserver"
    "github.com/jinzhu/gorm"
  _ "github.com/jinzhu/gorm/dialects/sqlite"
    "golang.org/x/crypto/bcrypt"
)

const testUser = "ben"
const testPassword = "password"

const testAdmin = "admin"
const testAdminPwd = "welcome"

func TestMain(m *testing.M) {
  os.Setenv("DB_DIALECT","sqlite3")
  os.Setenv("DB_URL", "test.db")
  fmt.Println("Environment variables set")

  hash, _ := bcrypt.GenerateFromPassword([]byte(testPassword),main.Bcrypt_cost)
  adminhash, _ := bcrypt.GenerateFromPassword([]byte(testAdminPwd),main.Bcrypt_cost)

  user := main.User{
    UserName: testUser ,
    Role:"user",
    Email: "user@test.com",
    PasswordHash: hash,
  }

  adminUser := main.User{
		UserName: testAdmin,
		Role: "admin",
		Email: "user@test.com",
		PasswordHash: adminhash,
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
  db.AutoMigrate(&main.Subscriber{})
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

func getAdminPage(path, token string) (*httptest.ResponseRecorder, error) {
  return getPage(path, main.VerifyAdmin(main.StatusHandler), token)
}

func getUserPage(path, token string) (*httptest.ResponseRecorder, error) {
  return getPage(path, main.ValidateToken(main.StatusHandler), token)
}

func getPage(path string, h http.HandlerFunc, token string) (*httptest.ResponseRecorder, error) {
  req, err := http.NewRequest("GET", path, nil)
  if err != nil {
      return nil, err
  }

  req.Header["Authorization"] = []string{"Bearer " + token}
  rr := httptest.NewRecorder()
  handler := http.HandlerFunc(h)

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
  rr, err = getUserPage("/user/", token)

  if status := rr.Code; status != http.StatusOK {
      t.Errorf("token handler returned wrong status code: got %v want %v",
          status, http.StatusOK)
  }

}

func TestValidateToken_InvalidTokenFail(t *testing.T) {
  rr, _ := getUserPage("/user/", "badtoken")

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

func TestSubscribe_Succeed(t *testing.T) {
  sub := main.Subscriber{
    Name: "John Doe",
    Email: "newuser@test.com",
  }

  js, _ := json.Marshal(&sub)

  req, _ := http.NewRequest("POST", "/subscribe", bytes.NewBuffer(js))
  req.Header.Add("Content-Type", "application/json")

  rr := httptest.NewRecorder()
  handler := http.HandlerFunc(main.SubscribeHandler)
  handler.ServeHTTP(rr, req)

  if status := rr.Code; status != http.StatusOK {
      t.Errorf("subscribe handler returned wrong status code: got %v want %v",
          status, http.StatusOK)
  }

}

func TestVerifyAdmin_ValidTokenSucceed(t *testing.T) {
  rr, err := doLogin(testAdmin, testAdminPwd)

  if err != nil {
    t.Fatal(err)
  }

  if status := rr.Code; status != http.StatusOK {
      t.Errorf("login handler returned wrong status code: got %v want %v",
          status, http.StatusOK)
  }


  body, _ := ioutil.ReadAll(rr.Result().Body)
  token := string(body)
  rr, err = getAdminPage("/admin/", token)

  if status := rr.Code; status != http.StatusOK {
      t.Errorf("token handler returned wrong status code: got %v want %v",
          status, http.StatusOK)
  }
}

func TestVerifyAdmin_RegularUserFail(t *testing.T) {
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
  rr, err = getAdminPage("/admin/", token)

  if status := rr.Code; status != http.StatusUnauthorized {
      t.Errorf("token handler returned wrong status code: got %v want %v",
          status, http.StatusUnauthorized)
  }
}
